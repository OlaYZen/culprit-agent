"""systemd units -- a straight upgrade over the Windows service collector.

Three things the Windows build could not have:

1. **`Result` names why a unit failed** (`oom-kill`, `timeout`, `watchdog`,
   `exit-code`, `signal`) and `NRestarts` exposes restart loops, so the
   problems list carries causes, not just states.
2. **The `_BENIGN_STOPPED` allowlist is gone.** Windows needed a hand-curated
   set of services that legitimately self-stop; here `Type=oneshot` /
   `RemainAfterExit` say so per unit, so "enabled but not running" is derived
   from properties, never from a name list.
3. **Per-unit resource attribution.** Every unit is a cgroup, so
   /sys/fs/cgroup/<unit>/ gives exact CPU, memory, IO *and per-unit PSI*. This
   is the actual answer to "which service is making this machine slow" -- the
   Windows best-effort was labelling which svchost hosted what.

Transport is `systemctl -o json` subprocesses (3 spawns per 20s tick, ~10ms
each, measured) -- see the note in linux.py for why not D-Bus bindings. The
`--user` bus is queried too; much desktop functionality lives there.
"""

from __future__ import annotations

import logging
import os
import pwd
import re
import time

from .. import linux
from . import cron as cron_mod

log = logging.getLogger("culprit.services")

# Unit properties fetched in one batched `systemctl show` call.
_PROPS = ("Id,Description,LoadState,ActiveState,SubState,UnitFileState,"
          "MainPID,ExecMainStatus,NRestarts,Result,Type,RemainAfterExit,"
          "ActiveEnterTimestamp,InactiveEnterTimestamp,ExecMainStartTimestamp,"
          "ExecMainExitTimestamp,ConditionResult,ControlGroup,User,WantedBy")

# A unit that ran at boot and exited cleanly within this many seconds of it
# did its job (dmesg.service saving the boot log, a one-off setup script
# declared Type=simple): not a daemon that is missing.
_BOOT_JOB_WINDOW_S = 900.0
# A main process that exits 0 within this long of starting is a job that
# ran to completion, whenever it was started -- by boot or by hand. A
# daemon stopped by hand had run for hours; a daemon that dies seconds
# after every start trips the restart-loop rule instead.
_JOB_MAX_RUN_S = 120.0
# Targets that only the boot sequence reaches: a unit pulled in by nothing
# but these has no reason to be running later.
_BOOT_TARGETS = frozenset({"sysinit.target", "basic.target", "local-fs.target",
                           "local-fs-pre.target", "remote-fs.target", "rescue.target",
                           "emergency.target", "initrd.target", "shutdown.target"})
_FINISHED_LINE = r"Finished |Deactivated successfully|Succeeded\."

# Per-unit journal rate: a trailing window read on the slow tick, overlapping
# on purpose -- a rate over 20 s of a unit that logs once a minute is noise,
# and the Pulse compares this with the same window from other days. Measured
# on the dev box (1.3 GB journal, a hammered sshd): ~10 ms warm.
_JOURNAL_WINDOW_S = 120
# Above this many lines in the window the counts stop being per-unit truth
# (journalctl returns the newest N, so a chatty unit hides a quiet one), and
# the whole source reports unavailable rather than inventing a silence.
_JOURNAL_MAX_LINES = 8000
_CRON_REFRESH_S = 300.0


class ServiceCollector:
    def __init__(self) -> None:
        # unit -> (monotonic, cpu_usec) for cgroup CPU% deltas across ticks.
        self._prev_cpu: dict[str, tuple[float, int]] = {}
        self._prev_io: dict[str, tuple[float, int, int]] = {}
        # unit -> when its last run ended, from the journal: systemd unloads
        # an inactive unit and `systemctl show` then reports no timestamps,
        # so a boot job that finished needs its journal line to prove it.
        self._exit_cache: dict[str, tuple[float | None, float | None]] = {}
        # Cron is read on its own cadence: the schedules come from files, but
        # "when did it last run" is a journal read (~0.8 s here), and a job's
        # last run does not change between slow ticks.
        self._cron: list[dict[str, object]] = []
        self._cron_reason: str | None = None
        self._cron_at = 0.0

    def sample(self) -> dict[str, object]:
        system = self._scope("system")
        user = self._scope("user")
        if not system["available"] and not user["available"]:
            # The systemd bus is unreachable (typically an agent in a container).
            # Fall back to enumerating the RUNNING units from process cgroups --
            # no systemctl needed -- so the view shows the active services
            # instead of nothing.
            fallback = self._cgroup_fallback(system["reason"])
            if fallback is not None:
                return fallback
            return {"available": False,
                    "reason": system["reason"] or "systemctl produced no output",
                    "services": [], "summary": {}, "problems": [], "by_pid": {},
                    "timers": []}

        services = system["services"] + user["services"]
        boot_time = _boot_time()
        # Listed before the journal fallback runs: a timer's activated unit is
        # usually a oneshot that systemd has unloaded between runs, which is
        # exactly the case the fallback exists for.
        listed_timers = self._list_timers()
        activated = {str(t.get("activates")) for t in listed_timers if t.get("activates")}
        for service in services:
            if (_boot_job_candidate(service) or str(service["name"]) in activated) \
                    and service.get("exited_at") is None:
                name = str(service["name"])
                if name not in self._exit_cache:
                    self._exit_cache[name] = _journal_run(name, str(service.get("scope")))
                service["started_at"], service["exited_at"] = self._exit_cache[name]
            elif service.get("active_state") != "inactive":
                self._exit_cache.pop(str(service["name"]), None)
        rates, rates_reason = _journal_rates()
        for service in services:
            if rates is None:
                service["lines_sec"] = None
                continue
            key = (f"user:{service['name']}" if service.get("scope") == "user"
                   else str(service["name"]))
            # A unit with no lines in the window logged nothing: that is a
            # zero, not a gap. `None` is reserved for "not readable".
            service["lines_sec"] = rates.get(key, 0.0)
        problems = _find_problems(services, boot_time=boot_time)
        problems.sort(key=lambda p: (0 if p["severity"] == "critical" else 1,
                                     str(p["display_name"] or p["name"])))

        summary: dict[str, object] = {
            "total": len(services),
            "denied": 0,  # systemctl lists everything; nothing is per-unit gated
            "user_units": len(user["services"]),
        }
        for service in services:
            key = f"status_{service['status']}"
            summary[key] = int(summary.get(key, 0)) + 1
            key = f"start_{service['start_type']}"
            summary[key] = int(summary.get(key, 0)) + 1

        services.sort(key=lambda s: (
            0 if s["status"] == "running" else 1,
            -(s.get("cpu_percent") or 0.0),
            str(s["display_name"] or s["name"]).lower(),
        ))

        by_pid: dict[str, list[str]] = {}
        for service in services:
            if service["pid"]:
                by_pid.setdefault(str(service["pid"]), []).append(
                    str(service["display_name"] or service["name"]))

        return {
            "available": True,
            "reason": None,
            "services": services,
            "summary": summary,
            "problems": problems,
            "by_pid": by_pid,
            "timers": _timer_rows(listed_timers, services) + self._cron_jobs(),
            "cgroup_attribution": linux.cgroup_version() == 2,
            # Whether services[].lines_sec means anything, and why not.
            "journal_rate": rates is not None,
            "journal_rate_reason": rates_reason,
            "journal_rate_window_s": _JOURNAL_WINDOW_S,
            # What cron could not be read, if anything (per-user crontabs are
            # root:crontab 1730 and invisible to an unprivileged agent).
            "cron_reason": self._cron_reason,
            "user_bus": user["available"],
            "user_bus_reason": user["reason"],
        }

    # -------------------------------------------------------------- cgroup fallback
    def _cgroup_fallback(self, bus_reason: str | None) -> dict[str, object] | None:
        """Running units from process cgroups, for when the systemd bus is
        unreachable (an agent in a container without /run/systemd + /run/dbus).

        No per-unit CPU/memory (those need the host cgroupfs, hidden by the
        cgroup namespace) and no inactive/failed units or descriptions (those
        need systemctl) -- but the active services and their main process show,
        which beats an empty view. Needs to see host processes (--pid host);
        returns None when nothing is visible so the caller reports unavailable.
        """
        groups: dict[str, list[int]] = {}
        try:
            entries = os.scandir("/proc")
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdigit():
                continue
            unit = linux.unit_from_cgroup(int(entry.name))
            if unit and unit.endswith((".service", ".socket", ".scope")):
                groups.setdefault(unit, []).append(int(entry.name))
        if not groups:
            return None

        services: list[dict[str, object]] = []
        by_pid: dict[str, list[str]] = {}
        for name in sorted(groups):
            leader = min(groups[name])
            services.append({
                "name": name, "scope": "system", "display_name": None,
                "status": "running", "active_state": "active",
                "sub_state": "running", "load_state": "loaded",
                "start_type": "transient", "pid": leader,
                "username": _username_of(leader), "description": None,
                "result": None, "restarts": None, "exit_status": None,
                "type": None, "remain_after_exit": False,
                "condition_result": None, "since": None,
            })
            by_pid.setdefault(str(leader), []).append(name)
        return {
            "available": True,
            "reason": None,
            "degraded": True,
            "degraded_reason": (
                f"systemd bus unreachable ({bus_reason or 'no bus'}); showing "
                "the active units found in process cgroups. No per-unit CPU/"
                "memory, and no inactive or failed units. Mount /run/systemd + "
                "/run/dbus (or run the agent natively) for the full view."),
            "services": services,
            "summary": {"total": len(services), "denied": 0, "user_units": 0,
                        "status_running": len(services)},
            "problems": [],
            "by_pid": by_pid,
            "timers": [],
            "cgroup_attribution": False,
            "user_bus": False,
            "user_bus_reason": None,
        }

    # ------------------------------------------------------------------ scopes
    def _scope(self, scope: str) -> dict[str, object]:
        flag = ["--user"] if scope == "user" else []
        listed = linux.run_json(
            ["systemctl", *flag, "list-units", "--type=service", "--all",
             "-o", "json", "--no-pager"], timeout=15)
        if not isinstance(listed, list):
            return {"available": False, "services": [],
                    "reason": (f"systemctl {' '.join(flag) or '--system'} "
                               "list-units failed (no bus for this scope?)")}

        names = [u.get("unit") for u in listed if u.get("unit")]
        props = self._show_batch(names, flag)
        now = time.monotonic()
        services = []
        for unit in listed:
            name = str(unit.get("unit") or "")
            detail = props.get(name, {})
            active = str(unit.get("active") or "unknown")
            sub = str(unit.get("sub") or "unknown")
            pid = _to_int(detail.get("MainPID"))
            entry: dict[str, object] = {
                "name": name,
                "scope": scope,
                "display_name": unit.get("description"),
                "status": _status_of(active, sub),
                "active_state": active,
                "sub_state": sub,
                "load_state": unit.get("load"),
                "start_type": detail.get("UnitFileState") or "transient",
                "pid": pid or None,
                "username": detail.get("User") or ("root" if scope == "system"
                                                   else None),
                "description": unit.get("description"),
                "result": detail.get("Result"),
                "restarts": _to_int(detail.get("NRestarts")),
                "exit_status": _to_int(detail.get("ExecMainStatus")),
                "type": detail.get("Type"),
                "remain_after_exit": detail.get("RemainAfterExit") == "yes",
                "condition_result": detail.get("ConditionResult"),
                "since": _parse_stamp(detail.get("ActiveEnterTimestamp")),
                "inactive_since": _parse_stamp(detail.get("InactiveEnterTimestamp")),
                # When the main process ended on its own; empty while it runs,
                # for a unit that never ran, and for one systemd has unloaded.
                "started_at": _parse_stamp(detail.get("ExecMainStartTimestamp")),
                "exited_at": _parse_stamp(detail.get("ExecMainExitTimestamp")),
                "wanted_by": (detail.get("WantedBy") or "").split(),
            }
            entry.update(self._cgroup_usage(name, detail.get("ControlGroup"), now))
            services.append(entry)
        return {"available": True, "reason": None, "services": services}

    def _show_batch(self, names: list[str], flag: list[str]) -> dict[str, dict]:
        """One `systemctl show` for every unit -- blocks separated by blank
        lines, in argument order. One spawn instead of N."""
        out: dict[str, dict] = {}
        if not names:
            return out
        text = linux.run(["systemctl", *flag, "show", "-p", _PROPS, "--", *names],
                         timeout=20)
        if text is None:
            return out
        for block in text.split("\n\n"):
            fields: dict[str, str] = {}
            for line in block.splitlines():
                key, found, value = line.partition("=")
                if found:
                    fields[key] = value
            unit_id = fields.get("Id")
            if unit_id:
                out[unit_id] = fields
        return out

    def _cgroup_usage(self, name: str, control_group: str | None,
                      now: float) -> dict[str, object]:
        path = linux.unit_cgroup_dir(control_group)
        if path is None:
            return {}
        stats = linux.cgroup_stats(path)
        out: dict[str, object] = {
            "memory_bytes": stats.get("memory_bytes"),
            "psi_cpu_some": stats.get("psi_cpu_some"),
            "psi_memory_some": stats.get("psi_memory_some"),
            "psi_io_some": stats.get("psi_io_some"),
        }
        if stats.get("oom_kills"):
            out["oom_kills"] = stats["oom_kills"]
        cpu_usec = stats.get("cpu_usec")
        if isinstance(cpu_usec, int):
            prev = self._prev_cpu.get(name)
            self._prev_cpu[name] = (now, cpu_usec)
            if prev and now > prev[0]:
                out["cpu_percent"] = round(
                    max(0.0, (cpu_usec - prev[1]) / ((now - prev[0]) * 1e4)), 2)
        read_b = stats.get("io_read_bytes")
        write_b = stats.get("io_write_bytes")
        if isinstance(read_b, int) and isinstance(write_b, int):
            prev_io = self._prev_io.get(name)
            self._prev_io[name] = (now, read_b, write_b)
            if prev_io and now > prev_io[0]:
                dt = now - prev_io[0]
                out["io_bytes_sec"] = round(
                    max(0.0, (read_b - prev_io[1] + write_b - prev_io[2]) / dt))
        return out

    def _cron_jobs(self) -> list[dict[str, object]]:
        """Cron's schedules in the timer shape, refreshed every five minutes."""
        now = time.monotonic()
        if now - self._cron_at > _CRON_REFRESH_S or not self._cron:
            try:
                self._cron, self._cron_reason = cron_mod.jobs()
            except Exception as exc:  # noqa: BLE001 -- one optional source
                log.debug("cron read failed: %s", exc)
                self._cron, self._cron_reason = [], f"cron could not be read ({exc})"
            self._cron_at = now
        return list(self._cron)

    def _list_timers(self) -> list[dict[str, object]]:
        """`systemctl list-timers` as it comes: unit, what it activates, and
        the two stamps systemd keeps (microsecond epochs)."""
        listed = linux.run_json(
            ["systemctl", "list-timers", "--all", "-o", "json", "--no-pager"],
            timeout=10)
        return [t for t in (listed if isinstance(listed, list) else [])
                if isinstance(t, dict)]


def _journal_rates() -> tuple[dict[str, float] | None, str | None]:
    """Journal lines per second per unit over the trailing window.

    The one signal that says an application *stopped working* while its unit
    stays perfectly active: a daemon that deadlocks keeps its PID, its port
    and its cgroup, and goes quiet in the log. Only the unit field is
    requested, so the messages themselves are never read here -- nothing is
    parsed, only counted.
    """
    entries = linux.journalctl_json(
        ["--since", f"-{_JOURNAL_WINDOW_S}s",
         "--output-fields=_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT"],
        timeout=15, max_entries=_JOURNAL_MAX_LINES)
    if not entries:
        # An empty window is not proof of a readable journal: a gated one
        # returns nothing too. `journal` in sysinfo's access map is the place
        # that says which, so this only reports the honest ambiguity.
        access = linux.journal_access()
        if access.get("readable"):
            return {}, None          # a genuinely silent two minutes
        return None, str(access.get("reason")
                         or "the system journal is not readable by this agent")
    if len(entries) >= _JOURNAL_MAX_LINES:
        return None, (f"more than {_JOURNAL_MAX_LINES} lines in {_JOURNAL_WINDOW_S}s: "
                      "the newest are all journalctl returns, so a quiet unit "
                      "cannot be told from one crowded out")
    # A user unit and a system unit can share a name (dbus.service is both),
    # so user lines are counted under their own key -- one unit must never be
    # credited with another's log.
    counts: dict[str, int] = {}
    for entry in entries:
        user_unit = entry.get("_SYSTEMD_USER_UNIT")
        unit = entry.get("_SYSTEMD_UNIT")
        key = (f"user:{user_unit}" if isinstance(user_unit, str) and user_unit
               else unit if isinstance(unit, str) and unit else None)
        if key:
            counts[key] = counts.get(key, 0) + 1
    return {unit: round(n / _JOURNAL_WINDOW_S, 4) for unit, n in counts.items()}, None


# --------------------------------------------------------------------- timers
def _timer_rows(listed: list[dict[str, object]],
                services: list[dict]) -> list[dict[str, object]]:
    """Scheduled jobs, each with **its last run**.

    A timer whose service failed on its last run is a real signal that Windows
    Task Scheduler made very hard to see -- and *how long the run took* is a
    second one that nothing else reports: a backup that normally runs twenty
    minutes and "succeeded" in four seconds did not back anything up. The run
    is joined from the activated unit's own properties, which the batched
    `systemctl show` already read, so this costs no extra call.
    """
    by_name = {str(s["name"]): s for s in services}
    out = []
    for timer in listed:
        activates = timer.get("activates")
        service = by_name.get(str(activates or ""))
        run, reason = _run_of(service) if service is not None else (
            None, "the unit this activates is not loaded, so systemd keeps no "
                  "record of its last run")
        out.append({
            "unit": timer.get("unit"),
            "activates": activates,
            # systemd reports microsecond epoch stamps.
            "next": _usec(timer.get("next")),
            "last": _usec(timer.get("last")),
            "run": run,
            "run_reason": reason,
        })
    return out


def _run_of(service: dict) -> tuple[dict[str, object] | None, str | None]:
    """The activated unit's last (or current) run, or why there is none.

    `ExecMainExitTimestamp` is empty while the main process lives, which is
    what separates a run still going from one that finished: a duration is
    only ever reported for a run that ended, and the one in flight reports
    how long it has been going instead. Nothing is inferred from a missing
    stamp -- a unit that has never run says so.
    """
    started = service.get("started_at")
    ended = service.get("exited_at")
    if not isinstance(started, (int, float)):
        return None, "this unit has not run since the last boot"
    running = ended is None and str(service.get("active_state")) in (
        "active", "activating", "reloading", "deactivating")
    duration = None
    if isinstance(ended, (int, float)) and ended >= started:
        duration = round(float(ended) - float(started), 3)
    return {
        "started": float(started),
        "ended": float(ended) if isinstance(ended, (int, float)) else None,
        # Set only for a run that ended; a run in flight carries elapsed.
        "duration_s": duration,
        "elapsed_s": round(time.time() - float(started), 1) if running else None,
        "status": service.get("exit_status"),
        "result": service.get("result"),
        "running": running,
    }, None


# --------------------------------------------------------------------- mapping
def _status_of(active: str, sub: str) -> str:
    if active == "active":
        return "running" if sub == "running" else sub  # exited, waiting, ...
    if active == "failed":
        return "failed"
    if active in ("activating", "deactivating", "reloading"):
        return active
    return "stopped"


def _find_problems(services: list[dict],
                   boot_time: float | None = None) -> list[dict[str, object]]:
    """Derived from unit properties, not from a curated name list.

    A oneshot with RemainAfterExit=no is *supposed* to be inactive after its
    work; a unit whose start condition was false never intended to run; and a
    unit that started at boot and exited 0 on its own within the boot window
    (dmesg.service saving the boot log, a setup script someone declared
    Type=simple) did its job -- the exit status and the exit time are
    systemd's own record of that. What is left -- failures, restart loops,
    enabled long-running services that are not running -- is worth looking at.
    """
    problems = []
    for service in services:
        result = service.get("result")
        restarts = service.get("restarts") or 0

        if service["status"] == "failed":
            detail = f"Unit failed: {result or 'unknown reason'}."
            if result == "oom-kill":
                detail = ("Killed by the OOM killer -- this unit ran the "
                          "machine out of memory (or was the chosen victim).")
            elif result == "exit-code":
                code = service.get("exit_status")
                detail = f"Main process exited with status {code}."
            elif result in ("timeout", "watchdog"):
                detail = f"Unit failed by {result} -- it stopped responding to systemd."
            problems.append(_problem(service, "critical", detail))
            continue

        if restarts >= 3:
            problems.append(_problem(
                service, "warn",
                f"Restarted {restarts} times since it was started -- a "
                "restart loop. The unit's journal has the crash output."))
            continue

        if (service["start_type"] == "enabled"
                and service["active_state"] == "inactive"
                and not (service.get("type") == "oneshot"
                         and not service.get("remain_after_exit"))
                and service.get("condition_result") != "no"
                and not _finished_boot_job(service, boot_time)):
            problems.append(_problem(
                service, "warn",
                "Enabled to start at boot but is not running, and it is not a "
                "oneshot that legitimately exits."))
    return problems


def _boot_job_candidate(service: dict) -> bool:
    """Enabled, inactive, ended cleanly, and not already excused as a
    oneshot or by a false condition: the units the boot-job test applies to."""
    return (service.get("start_type") == "enabled"
            and service.get("active_state") == "inactive"
            and service.get("result") == "success"
            and service.get("exit_status") == 0
            and not (service.get("type") == "oneshot" and not service.get("remain_after_exit"))
            and service.get("condition_result") != "no")


def _finished_boot_job(service: dict, boot_time: float | None) -> bool:
    """A job that ran to completion, not a daemon that died or was stopped.

    The evidence, in order: a main process that exited 0 within two minutes
    of starting is a job whenever it was started (dmesg.service saving the
    boot log takes a second, and someone re-running it by hand does not make
    it a daemon); Type=idle is the boot-time convenience type and never a
    daemon; an exit within the boot window is a boot job; and with no times
    at all, a unit that only the boot targets pull in is a boot job by its
    wiring. A daemon stopped by hand ran for hours before its clean exit and
    is wanted by multi-user.target, so it fails every test and stays a
    problem. Times come from systemd's properties while the unit is loaded,
    else from the unit's own journal lines.
    """
    if service.get("result") != "success" or service.get("exit_status") != 0:
        return False
    if service.get("type") == "idle":
        return True
    started = service.get("started_at")
    exited = service.get("exited_at")
    if isinstance(exited, (int, float)):
        if isinstance(started, (int, float)) and 0 <= exited - started <= _JOB_MAX_RUN_S:
            return True
        if boot_time and 0 <= exited - boot_time <= _BOOT_JOB_WINDOW_S:
            return True
        return False
    wanted = service.get("wanted_by") or []
    return bool(wanted) and all(target in _BOOT_TARGETS for target in wanted)


_STARTED_LINE = re.compile(r"^(Started |Starting )")
_ENDED_LINE = re.compile(r"Finished |Deactivated successfully|Succeeded\.")


def _journal_run(name: str, scope: str) -> tuple[float | None, float | None]:
    """(started, ended) of the unit's last run in this boot, from systemd's
    own lines in the unit's journal (~20 ms, once per unit while it stays
    inactive): the way to time a run systemd has already unloaded."""
    match = ["--user-unit", name] if scope == "user" else ["-u", name]
    entries = linux.journalctl_json(["-b", *match, "_COMM=systemd"], timeout=10,
                                    max_entries=12)
    ended: float | None = None
    started: float | None = None
    for entry in entries:            # newest first
        message = entry.get("MESSAGE")
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", "replace")
            except (TypeError, ValueError):
                message = ""
        message = str(message or "")
        raw = entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry.get("__REALTIME_TIMESTAMP")
        try:
            ts = int(raw) / 1e6
        except (TypeError, ValueError):
            continue
        if ended is None:
            if _ENDED_LINE.search(message):
                ended = ts
            continue
        if _STARTED_LINE.search(message):
            started = ts
            break
    return started, ended


def _boot_time() -> float | None:
    try:
        import psutil
        return float(psutil.boot_time())
    except Exception:  # noqa: BLE001 -- no boot time, no boot window
        return None


def _problem(service: dict, severity: str, detail: str) -> dict[str, object]:
    return {
        "name": service["name"],
        "display_name": service["display_name"],
        "status": service["status"],
        "start_type": service["start_type"],
        "scope": service["scope"],
        "severity": severity,
        "result": service.get("result"),
        "restarts": service.get("restarts"),
        "detail": detail,
    }


_user_cache: dict[int, str] = {}


def _username_of(pid: int) -> str | None:
    """Owner of a PID, from /proc/<pid>/status (cached per uid)."""
    uid_row = linux.parse_kv_file(f"/proc/{pid}/status").get("Uid", "").split()
    if not uid_row:
        return None
    try:
        uid = int(uid_row[0])
    except ValueError:
        return None
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


def _to_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _usec(value: object) -> float | None:
    number = _to_int(value)
    if not number:
        return None
    return number / 1e6


def _parse_stamp(value: str | None) -> float | None:
    """'Tue 2026-09-01 07:01:19 CEST' -> epoch seconds (local time)."""
    if not value:
        return None
    parts = value.split()
    if len(parts) < 3:
        return None
    try:
        struct = time.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
        return time.mktime(struct)
    except ValueError:
        return None
