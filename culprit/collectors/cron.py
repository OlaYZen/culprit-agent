"""Cron jobs in the same shape as systemd timers, so the Pulse can judge them.

Plenty of real work is still scheduled by cron, and cron is worse than systemd
in exactly the way that matters here: it keeps no state. There is no `last`,
no `next`, no result and no duration -- a job that stopped running leaves no
trace anywhere except the absence of a line in the journal, which is precisely
the kind of silence the Pulse exists to notice.

So this collector reconstructs the two facts a schedule needs:

* **when it should have run**, by parsing the schedule expression (a five-field
  parser, no dependency: `*`, lists, ranges, steps, and the `@daily` family)
  and walking day -> hour -> minute rather than minute by minute;
* **when it did**, from cron's own journal lines (`(root) CMD (...)`), read
  newest-first with a cap so the cost does not follow the journal's size.

Nothing is inferred beyond that. A job whose period is longer than the journal
window covers is reported as unjudgeable with that as the reason, `@reboot`
jobs say they have no schedule to be late against, and per-user crontabs --
which are `1730 root:crontab` and unreadable to an unprivileged agent -- are
named as a gap rather than silently skipped.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

from .. import linux

log = logging.getLogger("culprit.cron")

SYSTEM_CRONTAB = Path("/etc/crontab")
CRON_D = Path("/etc/cron.d")
USER_CRONTABS = Path("/var/spool/cron/crontabs")

# Newest-first with a cap: `-r -n` lets journalctl stop early instead of
# walking the whole window (see linux.journalctl_json). Measured on the dev
# box: 0.73 s for 2000 entries covering ~3.5 days.
_JOURNAL_ENTRIES = 2000
_MAX_JOBS = 200
_MAX_COMMAND = 160

_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_CMD_LINE = re.compile(r"^\((?P<user>[^)]+)\)\s+CMD\s+\((?P<command>.*)\)\s*$")

_SHORTHAND = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}
_MONTHS = {name: index for index, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_DAYS = {name: index for index, name in enumerate(
    ("sun", "mon", "tue", "wed", "thu", "fri", "sat"), 0)}


def _field(text: str, low: int, high: int,
           names: dict[str, int] | None = None) -> set[int] | None:
    """One cron field as the set of values it matches, or None if malformed."""
    out: set[int] = set()
    for part in text.split(","):
        part = part.strip().lower()
        if not part:
            return None
        step = 1
        if "/" in part:
            part, _, raw_step = part.partition("/")
            if not raw_step.isdigit() or int(raw_step) < 1:
                return None
            step = int(raw_step)
        if part in ("*", ""):
            start, end = low, high
        else:
            bounds = part.split("-", 1)
            values = []
            for bound in bounds:
                bound = bound.strip()
                if names and bound in names:
                    values.append(names[bound])
                elif bound.isdigit():
                    values.append(int(bound))
                else:
                    return None
            start = values[0]
            end = values[1] if len(values) > 1 else (high if step > 1 else values[0])
        if start > end or start < low or end > high:
            return None
        out.update(range(start, end + 1, step))
    return out or None


def parse_schedule(expression: str) -> dict[str, object] | None:
    """A cron expression as five value sets, or None when it is not one.

    `dom` and `dow` are kept apart because cron's rule for them is a union,
    not an intersection: with both restricted, a job runs when *either*
    matches. Getting that backwards would silently move half the schedules on
    a machine.
    """
    expression = expression.strip()
    if expression.startswith("@"):
        if expression.lower() in ("@reboot",):
            return {"reboot": True}
        expression = _SHORTHAND.get(expression.lower(), "")
        if not expression:
            return None
    fields = expression.split()
    if len(fields) != 5:
        return None
    minute = _field(fields[0], 0, 59)
    hour = _field(fields[1], 0, 23)
    dom = _field(fields[2], 1, 31)
    month = _field(fields[3], 1, 12, _MONTHS)
    dow = _field(fields[4], 0, 7, _DAYS)
    if None in (minute, hour, dom, month, dow):
        return None
    dow = {0 if value == 7 else value for value in dow}     # cron accepts both
    return {"minute": minute, "hour": hour, "dom": dom, "month": month, "dow": dow,
            "dom_any": fields[2].strip() == "*", "dow_any": fields[4].strip() == "*",
            "reboot": False}


def _day_matches(spec: dict[str, object], when: time.struct_time) -> bool:
    if when.tm_mon not in spec["month"]:            # type: ignore[operator]
        return False
    dom_ok = when.tm_mday in spec["dom"]            # type: ignore[operator]
    dow_ok = ((when.tm_wday + 1) % 7) in spec["dow"]  # type: ignore[operator]
    if spec["dom_any"] and spec["dow_any"]:
        return True
    if spec["dom_any"]:
        return dow_ok
    if spec["dow_any"]:
        return dom_ok
    return dom_ok or dow_ok                          # cron's union, not an AND


def occurrence(spec: dict[str, object], now: float,
               forward: bool, horizon_days: int = 400) -> float | None:
    """The next (or previous) time this schedule fires, walking whole days
    first so a yearly job costs the same as a minutely one."""
    if spec.get("reboot"):
        return None
    step = 1 if forward else -1
    day = time.localtime(now)
    for offset in range(0, horizon_days + 1):
        stamp = now + step * offset * 86400
        day = time.localtime(stamp)
        if not _day_matches(spec, day):
            continue
        hours = sorted(spec["hour"], reverse=not forward)    # type: ignore[arg-type]
        minutes = sorted(spec["minute"], reverse=not forward)  # type: ignore[arg-type]
        for hour in hours:
            for minute in minutes:
                candidate = time.mktime((day.tm_year, day.tm_mon, day.tm_mday,
                                         hour, minute, 0, 0, 0, -1))
                if forward and candidate > now:
                    return candidate
                if not forward and candidate < now:
                    return candidate
    return None


def _read(path: Path, with_user: bool) -> list[dict[str, object]]:
    """One crontab file's jobs. System files carry a user column; a user's own
    crontab does not."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or _ENV_LINE.match(line):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if with_user else 1)
            expression, rest = parts[0], parts[1:]
        else:
            parts = line.split(None, 6 if with_user else 5)
            if len(parts) < (7 if with_user else 6):
                continue
            expression, rest = " ".join(parts[:5]), parts[5:]
        user = rest[0] if with_user and rest else None
        command = (rest[1] if with_user and len(rest) > 1 else
                   rest[0] if not with_user and rest else "")
        spec = parse_schedule(expression)
        if spec is None or not command:
            continue
        out.append({"source": str(path), "line": number, "schedule": expression,
                    "user": user or "root", "command": command[:_MAX_COMMAND],
                    "spec": spec})
    return out


def _last_runs() -> tuple[dict[str, float] | None, float | None, str | None]:
    """(command -> when it last ran, how far back the read reached, reason).

    cron's own lines are the only record that a job ran at all.
    """
    entries = linux.journalctl_json(["-t", "CRON", "--output-fields=MESSAGE"],
                                    timeout=25, max_entries=_JOURNAL_ENTRIES)
    if not entries:
        access = linux.journal_access()
        if not access.get("readable"):
            return None, None, str(access.get("reason") or "the journal is not readable")
        return {}, None, ("cron has logged nothing this journal holds -- with "
                          "`-L 0` in /etc/default/cron it logs no job lines at all")
    out: dict[str, float] = {}
    oldest = None
    for entry in entries:
        raw = entry.get("__REALTIME_TIMESTAMP")
        try:
            stamp = int(raw) / 1e6
        except (TypeError, ValueError):
            continue
        oldest = stamp if oldest is None else min(oldest, stamp)
        message = entry.get("MESSAGE")
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", "replace")
            except (TypeError, ValueError):
                continue
        match = _CMD_LINE.match(str(message or "").strip())
        if not match:
            continue                       # a pam session line, not a job
        key = _normalise(match.group("command"))
        if key not in out:                 # newest first: the first is the last run
            out[key] = stamp
    return out, oldest, None


def _normalise(command: str) -> str:
    """Cron logs the command as written but stops at an unescaped `%`, and
    whitespace varies; both sides are compared through this."""
    text = re.split(r"(?<!\\)%", command, maxsplit=1)[0]
    return " ".join(text.split())[:_MAX_COMMAND]


def jobs(now: float | None = None) -> tuple[list[dict[str, object]], str | None]:
    """Every readable cron job as a timer row, or (rows, reason) when the
    sources themselves are the problem."""
    now = now or time.time()
    found: list[dict[str, object]] = []
    if SYSTEM_CRONTAB.exists():
        found += _read(SYSTEM_CRONTAB, with_user=True)
    if CRON_D.is_dir():
        try:
            for entry in sorted(CRON_D.iterdir()):
                # run-parts ignores anything with a dot or a tilde, and so
                # does cron: a file named `foo.dpkg-dist` is not a schedule.
                if entry.is_file() and re.fullmatch(r"[A-Za-z0-9_-]+", entry.name):
                    found += _read(entry, with_user=True)
        except OSError as exc:
            log.debug("cron.d unreadable: %s", exc)
    gaps = []
    if not os.access(USER_CRONTABS, os.R_OK):
        gaps.append(f"per-user crontabs ({USER_CRONTABS}) are group `crontab`, "
                    "mode 1730: they are invisible to this agent")
    else:
        try:
            for entry in sorted(USER_CRONTABS.iterdir()):
                if entry.is_file():
                    for job in _read(entry, with_user=False):
                        job["user"] = entry.name
                        found.append(job)
        except OSError:
            gaps.append(f"{USER_CRONTABS} could not be listed")

    runs, oldest, run_reason = _last_runs()
    out: list[dict[str, object]] = []
    for index, job in enumerate(found[:_MAX_JOBS]):
        spec = job.pop("spec")
        key = _normalise(str(job["command"]))
        last = (runs or {}).get(key)
        previous = occurrence(spec, now, forward=False)
        nxt = occurrence(spec, now, forward=True)
        period = (nxt - previous) if (nxt and previous) else None
        reason = run_reason
        if reason is None and period and oldest is not None and now - oldest < period * 1.5:
            # The journal does not reach back far enough to have seen this
            # job's last run, so its absence proves nothing.
            reason = (f"cron's journal here reaches back {(now - oldest) / 3600:.0f} h, "
                      f"less than this job's own interval")
        out.append({
            "unit": f"cron:{Path(str(job['source'])).name}:{job['line']}",
            "activates": None,
            "manager": "cron",
            "command": job["command"],
            "user": job["user"],
            "schedule": job["schedule"],
            "source": job["source"],
            "next": nxt,
            "last": last,
            # What cron *should* have done last, which is the only thing an
            # absence can be measured against.
            "expected_last": previous,
            "last_reason": reason if last is None else None,
            "reboot": bool(spec.get("reboot")),
            # cron records no duration and no result, and never has.
            "run": None,
            "run_reason": "cron keeps no record of how long a job ran or how it ended",
        })
        index += 0
    return out, ("; ".join(gaps) if gaps else None)
