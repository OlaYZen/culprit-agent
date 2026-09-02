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
import time

from .. import linux

log = logging.getLogger("culprit.services")

# Unit properties fetched in one batched `systemctl show` call.
_PROPS = ("Id,Description,LoadState,ActiveState,SubState,UnitFileState,"
          "MainPID,ExecMainStatus,NRestarts,Result,Type,RemainAfterExit,"
          "ActiveEnterTimestamp,ConditionResult,ControlGroup,User")


class ServiceCollector:
    def __init__(self) -> None:
        # unit -> (monotonic, cpu_usec) for cgroup CPU% deltas across ticks.
        self._prev_cpu: dict[str, tuple[float, int]] = {}
        self._prev_io: dict[str, tuple[float, int, int]] = {}

    def sample(self) -> dict[str, object]:
        system = self._scope("system")
        user = self._scope("user")
        if not system["available"] and not user["available"]:
            return {"available": False,
                    "reason": system["reason"] or "systemctl produced no output",
                    "services": [], "summary": {}, "problems": [], "by_pid": {},
                    "timers": []}

        services = system["services"] + user["services"]
        problems = _find_problems(services)
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
            "timers": self._timers(),
            "cgroup_attribution": linux.cgroup_version() == 2,
            "user_bus": user["available"],
            "user_bus_reason": user["reason"],
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

    def _timers(self) -> list[dict[str, object]]:
        """Scheduled jobs. A timer whose service failed on its last run is a
        real signal that Windows Task Scheduler made very hard to see."""
        listed = linux.run_json(
            ["systemctl", "list-timers", "--all", "-o", "json", "--no-pager"],
            timeout=10)
        out = []
        for timer in listed if isinstance(listed, list) else []:
            out.append({
                "unit": timer.get("unit"),
                "activates": timer.get("activates"),
                # systemd reports microsecond epoch stamps.
                "next": _usec(timer.get("next")),
                "last": _usec(timer.get("last")),
            })
        return out


# --------------------------------------------------------------------- mapping
def _status_of(active: str, sub: str) -> str:
    if active == "active":
        return "running" if sub == "running" else sub  # exited, waiting, ...
    if active == "failed":
        return "failed"
    if active in ("activating", "deactivating", "reloading"):
        return active
    return "stopped"


def _find_problems(services: list[dict]) -> list[dict[str, object]]:
    """Derived from unit properties, not from a curated name list.

    A oneshot with RemainAfterExit=no is *supposed* to be inactive after its
    work; a unit whose start condition was false never intended to run. What
    is left -- failures, restart loops, enabled long-running services that are
    not running -- is worth looking at.
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
                and service.get("condition_result") != "no"):
            problems.append(_problem(
                service, "warn",
                "Enabled to start at boot but is not running, and it is not a "
                "oneshot that legitimately exits."))
    return problems


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
