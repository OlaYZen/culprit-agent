"""The agent: a report-only culprit node.

Runs the exact same collectors and sampler as the host -- same tiers, same
payload shapes, same honesty rules -- but instead of serving a dashboard it
pushes its snapshot to the host node over HTTPS/HTTP with a bearer token.
No FastAPI, no uvicorn, no SQLite: the runtime dependency is psutil plus the
standard library, which is what makes an agent cheap to drop on many servers.

    python -m culprit.agent --host https://hub:8787 --token <name>.<secret>

The first run writes agent.json next to the code (chmod 600 -- it holds the
token); after that a bare `python -m culprit.agent` is enough, which is what
the systemd unit runs.

Push, not pull, on purpose: an agent only needs *outbound* reachability to the
host, so nothing new listens on the monitored servers and NAT/firewalls in the
wrong direction cost nothing. Reports are gzipped (a full snapshot compresses
roughly 10x) and failures are retried with backoff -- the agent never dies
because the host is temporarily away; it keeps sampling and reports again.
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import logging
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from . import config as config_module
from .db import History
from .sampler import Sampler
from .state import Broker, Store

log = logging.getLogger("culprit.agent")

CONFIG_PATH = config_module.ROOT / "agent.json"

_DEFAULTS = {
    "host_url": "",            # e.g. https://hub.example:8787
    "token": "",               # <name>.<secret>, from the host's Nodes view
    "report_interval": 1.0,    # seconds between pushes
    "verify_tls": True,        # False only for self-signed certs you accept
}

# Big sections that change on their own slower cadence. Each is resent only
# when its content object actually changed (the sampler replaces the object
# per tick, so identity is the cheap and exact change test) -- a 1s report
# cadence therefore costs a few KB per second, not the whole snapshot.
_DELTA_SECTIONS = ("process_table", "diagnosis", "services", "volumes",
                   "network_detail", "ports", "sync", "events", "system",
                   "cgroups", "kernel", "changes", "ceilings")
# A full snapshot goes out anyway on this period, so drift (like the mutated
# uptime inside the cached `system` section) never outlives a minute.
_FULL_SYNC_S = 60.0


def load_agent_config(path: Path = CONFIG_PATH) -> dict:
    cfg = dict(_DEFAULTS)
    if path.exists():
        try:
            cfg.update({k: v for k, v in json.loads(path.read_text()).items()
                        if k in _DEFAULTS})
        except (OSError, ValueError) as exc:
            log.error("could not read %s: %s", path, exc)
    return cfg


def save_agent_config(cfg: dict, path: Path = CONFIG_PATH) -> None:
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    os.chmod(path, 0o600)  # the token lives in here


class Reporter:
    def __init__(self, store: Store, cfg: dict) -> None:
        self.store = store
        self.url = cfg["host_url"].rstrip("/") + "/api/agents/report"
        self.token = cfg["token"]
        self.interval = max(0.5, float(cfg["report_interval"]))
        self.node_name = self.token.partition(".")[0]
        self._context: ssl.SSLContext | None = None
        if self.url.startswith("https") and not cfg.get("verify_tls", True):
            self._context = ssl.create_default_context()
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE
            log.warning("TLS verification disabled -- the host's identity is "
                        "not being checked")
        self.consecutive_failures = 0
        self._sent_ids: dict[str, int] = {}   # section -> id() last delivered
        self._full_next = True
        self._last_full = 0.0
        # Set after the sampler starts; the process collector the host's
        # relayed commands run against.
        self.proc = None

    def _build_snapshot(self) -> dict:
        """Full snapshot, or just the sections that changed since the last
        report the host acknowledged."""
        snapshot = self.store.snapshot()
        now = time.monotonic()
        if self._full_next or now - self._last_full >= _FULL_SYNC_S:
            self._last_full = now
            self._pending_ids = {key: id(snapshot.get(key))
                                 for key in _DELTA_SECTIONS}
            return snapshot
        for key in _DELTA_SECTIONS:
            section = snapshot.get(key)
            if id(section) == self._sent_ids.get(key):
                snapshot.pop(key, None)
        self._pending_ids = {key: id(self.store.get(key))
                             for key in _DELTA_SECTIONS}
        return snapshot

    def _post(self, payload: dict) -> dict | None:
        """Gzip-POST one payload to the host, returning the parsed reply or
        None on failure. Never raises."""
        body = gzip.compress(
            json.dumps(payload, default=_json_fallback,
                       separators=(",", ":")).encode())
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            })
        with urllib.request.urlopen(request, timeout=15,
                                    context=self._context) as response:
            return json.loads(response.read() or b"{}")

    def push(self) -> bool:
        """One report. Runs in a thread (urllib blocks)."""
        payload = {
            "agent": {
                "name": self.node_name,
                "version": __version__,
                "report_interval": self.interval,
                "interval_fast": config_module.get().interval_fast,
            },
            "snapshot": self._build_snapshot(),
        }
        try:
            reply = self._post(payload) or {}
            if self.consecutive_failures:
                log.info("host reachable again after %d failed report(s)",
                         self.consecutive_failures)
            self.consecutive_failures = 0
            # Delivered: what we just sent is what the host now has.
            self._sent_ids.update(self._pending_ids)
            # A host that does not know this node (fresh start, restarted)
            # holds a partial merge at best -- resend everything next time.
            self._full_next = not reply.get("known", True)
            self._apply_settings(reply.get("settings") or {})
            self._run_commands(reply.get("commands") or [])
            return True
        except urllib.error.HTTPError as exc:
            self.consecutive_failures += 1
            if exc.code in (401, 403):
                # An invalid token will not fix itself; still keep trying at a
                # slow crawl in case the token gets (re-)enrolled host-side.
                log.error("host rejected the token (%s) -- re-enroll this "
                          "agent on the host: culprit agents add %s",
                          exc.code, self.node_name)
            else:
                log.warning("report failed: HTTP %s", exc.code)
            return False
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self.consecutive_failures += 1
            if self.consecutive_failures in (1, 5) or \
                    self.consecutive_failures % 60 == 0:
                log.warning("host unreachable (%s attempt(s)): %s",
                            self.consecutive_failures, exc)
            return False

    def _run_commands(self, commands: list) -> None:
        """Execute commands the host relayed and post the results back at once.

        Same collector code the host runs on itself -- process detail via the
        live ProcessCollector, End task / renice via the module functions,
        which enforce the critical-process guards and honour this agent's own
        allow_process_actions config. Results go back immediately in a
        results-only report, so a command round-trips in about one report
        interval rather than waiting for the next scheduled push.
        """
        if not commands:
            return
        results = [self._execute(command) for command in commands]
        try:
            self._post({
                "agent": {"name": self.node_name, "version": __version__,
                          "report_interval": self.interval},
                "command_results": results,
            })
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.warning("could not return %d command result(s): %s",
                        len(results), exc)

    def _execute(self, command: dict) -> dict:
        from .collectors import processes as proc_mod

        cmd_id = command.get("id")
        action = command.get("action")
        try:
            if action == "process_detail":
                if self.proc is None:
                    return _cmd_err(cmd_id, 503, "process collector not ready")
                extras = frozenset(
                    part.strip() for part in (command.get("extras") or "").split(",")
                    if part.strip()) & {"files", "threads"}
                detail = self.proc.detail(int(command["pid"]), extras)
                if detail is None:
                    return _cmd_err(cmd_id, 404, "no such process (it may have exited)")
                return {"id": cmd_id, "ok": True, "result": detail}

            if action in ("terminate", "priority", "throttle"):
                if not config_module.get().allow_process_actions:
                    return _cmd_err(cmd_id, 403,
                                    "process actions are disabled on this agent "
                                    "(allow_process_actions is false)")
                if action == "terminate":
                    outcome = proc_mod.terminate(int(command["pid"]),
                                                 bool(command.get("force")))
                elif action == "throttle":
                    # Caps the process's whole systemd unit / container scope
                    # (CPUQuota + IOWeight, --runtime) -- the reversible
                    # verb between renice and End task.
                    outcome = proc_mod.throttle(int(command["pid"]),
                                                str(command.get("level")))
                else:
                    outcome = proc_mod.set_priority(int(command["pid"]),
                                                    str(command.get("level")))
                if outcome.get("ok"):
                    return {"id": cmd_id, "ok": True, "result": outcome}
                return _cmd_err(cmd_id, 409, str(outcome.get("reason")))

            return _cmd_err(cmd_id, 400, f"unknown action {action!r}")
        except Exception as exc:  # noqa: BLE001 -- a bad command must not kill the agent
            log.warning("command %s (%s) failed: %s", cmd_id, action, exc)
            return _cmd_err(cmd_id, 500, str(exc))

    def _apply_settings(self, settings: dict) -> None:
        """Overrides the host handed back with its response -- the Refresh
        control on the dashboard lands here. Applied like the host applies its
        own titlebar control: to the running sampler only, never persisted."""
        fast = settings.get("interval_fast")
        if fast is None:
            return
        try:
            fast = float(fast)
        except (TypeError, ValueError):
            return
        changed = False
        if abs(config_module.get().interval_fast - fast) > 1e-9:
            _, errors = config_module.update({"interval_fast": fast},
                                             persist=False)
            if errors:
                log.warning("host asked for interval_fast=%r: %s", fast, errors)
                return
            changed = True
        # Reporting keeps pace with sampling; below 1s the report floor is
        # 0.5s so a 0.5s refresh on the dashboard still means 2 reports/s max.
        desired_report = max(0.5, fast)
        if abs(self.interval - desired_report) > 1e-9:
            self.interval = desired_report
            changed = True
        if changed:
            log.info("host set sampling to %.2gs (reporting every %.2gs)",
                     fast, self.interval)

    @property
    def delay(self) -> float:
        """Backoff: normal cadence while healthy, up to 60s while the host is
        away. Sampling continues regardless -- only the pushing slows down."""
        if self.consecutive_failures == 0:
            return self.interval
        return min(60.0, self.interval * (2 ** min(self.consecutive_failures, 5)))


async def run_agent(cfg: dict) -> int:
    config_module.load()  # collector thresholds; agent has no config.json UI
    store = Store()
    broker = Broker()  # zero subscribers: publish() is a no-op
    history = History(config_module.DEFAULT_DB_PATH, enabled=False)
    sampler = Sampler(store, broker, history)
    await sampler.start()

    reporter = Reporter(store, cfg)
    reporter.proc = sampler.proc  # the collector relayed commands run against
    log.info("agent '%s' reporting to %s every %.0fs",
             reporter.node_name, reporter.url, reporter.interval)

    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopping.set)
        except NotImplementedError:
            pass

    try:
        while not stopping.is_set():
            await loop.run_in_executor(None, reporter.push)
            try:
                await asyncio.wait_for(stopping.wait(), timeout=reporter.delay)
            except asyncio.TimeoutError:
                pass
    finally:
        await sampler.stop()
    log.info("agent stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="culprit-agent",
        description="Report-only culprit node: samples this machine and "
                    "pushes to a culprit host. No dashboard, no open ports.",
    )
    parser.add_argument("--host", help="host node URL, e.g. https://hub:8787")
    parser.add_argument("--token", help="agent token from `culprit agents add`")
    parser.add_argument("--interval", type=float,
                        help="seconds between reports (default 1)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify the host's TLS certificate")
    parser.add_argument("--log-level", default="info",
                        choices=("debug", "info", "warning", "error"))
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = load_agent_config()
    changed = False
    if args.host:
        cfg["host_url"] = args.host
        changed = True
    if args.token:
        cfg["token"] = args.token
        changed = True
    if args.interval:
        cfg["report_interval"] = args.interval
        changed = True
    if args.insecure:
        cfg["verify_tls"] = False
        changed = True
    if not cfg["host_url"] or not cfg["token"]:
        parser.error("no host/token configured. First run:\n"
                     "  python -m culprit.agent --host <url> --token <token>\n"
                     "(get a token on the host with: "
                     "python -m culprit agents add <name>)")
    if changed:
        save_agent_config(cfg)
        log.info("saved %s", CONFIG_PATH)

    return asyncio.run(run_agent(cfg))


def _cmd_err(cmd_id, status, message):  # type: ignore[no-untyped-def]
    return {"id": cmd_id, "ok": False, "status": status, "error": message}


def _json_fallback(value):  # type: ignore[no-untyped-def]
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


if __name__ == "__main__":
    sys.exit(main())
