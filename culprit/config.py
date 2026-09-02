"""Runtime configuration.

Defaults live here; `config.json` in the project root overrides them and is
written back by the Settings panel. The file is created on first save rather
than on first run, so a fresh clone has nothing to clean up.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("culprit.config")

CONFIG_PATH = ROOT / "config.json"
WEB_DIR = ROOT / "web"
DEFAULT_DB_PATH = ROOT / "data" / "culprit.db"


@dataclass
class Config:
    # --- server ---
    host: str = "127.0.0.1"
    port: int = 8787
    open_browser: bool = True

    # --- sampling cadences, in seconds ---
    # Four tiers rather than one loop: polling services or the event log at 1Hz
    # would burn CPU for data that changes on a scale of minutes.
    interval_fast: float = 1.0      # cpu / memory / gpu / disk+net throughput
    interval_proc: float = 2.0      # process table (the expensive one)
    interval_slow: float = 20.0     # services, volumes, adapters, sync
    interval_events: float = 120.0  # journal, crash files, pending reboot

    # --- history ---
    persist_history: bool = True
    retention_days: int = 7
    # One row per rollup_seconds, aggregated from the fast ring buffer.
    rollup_seconds: int = 60
    # Per-rollup, only the N heaviest processes are stored. Keeps the DB small
    # while still answering "what was pinning the CPU at 14:20?".
    history_top_processes: int = 8
    db_path: str = ""  # "" -> DEFAULT_DB_PATH

    # --- in-memory ring buffer (drives the live sparklines) ---
    live_window_seconds: int = 900

    # --- process table ---
    process_count: int = 250
    # Roll child processes up under their parent by image name in the tree view.
    tree_grouping: bool = True

    # --- pressure thresholds -----------------------------------------------
    # These drive the Lag Doctor verdicts. Tuned for a general-purpose laptop;
    # a build server would want cpu_high much closer to 100.
    cpu_high: float = 85.0            # % busy, sustained
    cpu_queue_per_core: float = 1.0   # runnable threads per core before it hurts
    mem_available_low_mb: float = 1024.0
    mem_commit_high: float = 90.0     # % of CommitLimit
    hard_faults_high: float = 500.0   # major faults/sec -- actual disk paging
    disk_queue_high: float = 2.0
    disk_latency_high_ms: float = 25.0
    disk_busy_high: float = 85.0      # % of time the device had IO in flight
    disk_space_low_pct: float = 10.0
    gpu_high: float = 85.0
    # PSI avg10 (% of wall time stalled) that counts as full pressure. These
    # only apply when /proc/pressure exists; otherwise the derived signals
    # above carry the model. 'full' stalls are gated at half these values.
    psi_cpu_high: float = 50.0        # % of time some task waited for a CPU
    psi_memory_high: float = 10.0     # memory stalls hurt much earlier
    psi_io_high: float = 40.0
    # A pressure state must hold for this many consecutive fast ticks before it
    # is reported, so a single 100% spike from opening a menu is not an alert.
    sustain_ticks: int = 5

    # --- lag score weights -------------------------------------------------
    # Relative contribution of each resource to a process's lag score. Values
    # are normalised, so only the ratios matter.
    weight_cpu: float = 1.0
    weight_memory: float = 0.55
    weight_disk: float = 0.85
    weight_gpu: float = 0.6
    weight_faults: float = 0.5
    # Sustained D-state (uninterruptible sleep): the process is being made to
    # wait inside the kernel regardless of what any usage counter says.
    weight_stuck: float = 2.0

    # --- events ---
    event_lookback_days: int = 30
    event_max_per_source: int = 200

    # --- actions ---
    # End-task / priority changes from the UI. On by default because "find what
    # is lagging the system" is only half a job if you cannot then stop it, but
    # every call goes through a confirmation modal and is refused for PID 0/4
    # and the critical-service allowlist. Set false for a read-only install.
    allow_process_actions: bool = True

    # --- agent deployment -------------------------------------------------
    # Shape the deploy command the Nodes view shows for a freshly enrolled or
    # rotated agent. `deploy_host` overrides the address the command tells the
    # agent to report to (blank = the address the dashboard was reached on);
    # `agent_command` is what runs the bundle -- set it to "sudo ./agent.sh" to
    # run the agent as root, which unlocks full port/process attribution.
    deploy_host: str = ""            # e.g. "192.168.1.5:8787" or "https://hub:8787"
    agent_command: str = "./agent.sh"

    # --- ui ---
    ui: dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    @property
    def resolved_db_path(self) -> Path:
        return Path(self.db_path) if self.db_path else DEFAULT_DB_PATH

    @property
    def effective_port(self) -> int:
        """The port actually bound, which may be a one-off command-line override.

        Kept separate from `self.port` on purpose. An earlier version wrote the
        environment override straight into the dataclass, and since `update()`
        persists the whole object, running `run.ps1 -Port 9000` once and then
        changing any unrelated setting pinned 9000 into config.json for good.
        The file keeps what the user chose; this reports what is in use.
        """
        raw = os.environ.get("CULPRIT_PORT")
        if raw:
            try:
                return int(raw)
            except ValueError:
                pass
        return self.port

    @property
    def effective_host(self) -> str:
        return os.environ.get("CULPRIT_HOST") or self.host

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_lock = threading.Lock()
_current = Config()

# Fields the Settings panel may write. Deliberately excludes host/port/db_path:
# changing those needs a restart, and letting a browser rewrite a filesystem
# path on a monitoring daemon is not a trade worth making.
EDITABLE = {
    "interval_fast", "interval_proc", "interval_slow", "interval_events",
    "persist_history", "retention_days", "history_top_processes",
    "live_window_seconds", "process_count", "tree_grouping",
    "cpu_high", "cpu_queue_per_core", "mem_available_low_mb", "mem_commit_high",
    "hard_faults_high", "disk_queue_high", "disk_latency_high_ms",
    "disk_busy_high", "disk_space_low_pct", "gpu_high", "sustain_ticks",
    "psi_cpu_high", "psi_memory_high", "psi_io_high",
    "weight_cpu", "weight_memory", "weight_disk", "weight_gpu",
    "weight_faults", "weight_stuck",
    "event_lookback_days", "event_max_per_source",
    "allow_process_actions", "open_browser", "ui",
    "deploy_host", "agent_command",
}

# Accepted ranges for editable numeric fields, used by the API to reject
# nonsense before it reaches the sampler. Inclusive on both ends.
LIMITS: dict[str, tuple[float, float]] = {
    "interval_fast": (0.25, 60.0),
    "interval_proc": (0.5, 120.0),
    "interval_slow": (2.0, 600.0),
    "interval_events": (10.0, 3600.0),
    "retention_days": (1, 365),
    "history_top_processes": (1, 50),
    "live_window_seconds": (60, 86400),
    "process_count": (10, 2000),
    "cpu_high": (10, 100),
    "cpu_queue_per_core": (0.1, 100),
    "mem_available_low_mb": (64, 1_048_576),
    "mem_commit_high": (10, 100),
    "hard_faults_high": (1, 1_000_000),
    "disk_queue_high": (0.1, 1000),
    "disk_latency_high_ms": (1, 10_000),
    "disk_busy_high": (10, 100),
    "disk_space_low_pct": (1, 90),
    "gpu_high": (10, 100),
    "sustain_ticks": (1, 120),
    "psi_cpu_high": (1, 100), "psi_memory_high": (0.5, 100),
    "psi_io_high": (1, 100),
    "weight_cpu": (0, 10), "weight_memory": (0, 10), "weight_disk": (0, 10),
    "weight_gpu": (0, 10), "weight_faults": (0, 10), "weight_stuck": (0, 10),
    "event_lookback_days": (1, 3650),
    "event_max_per_source": (10, 5000),
}


def get() -> Config:
    return _current


def load() -> Config:
    """Read config.json over the defaults. Unknown/invalid keys are ignored."""
    global _current
    cfg = Config()
    if CONFIG_PATH.exists():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        known = {f.name: f for f in fields(Config)}
        for key, value in (raw or {}).items():
            spec = known.get(key)
            if spec is None:
                continue
            try:
                if spec.type in ("float", float):
                    value = float(value)
                elif spec.type in ("int", int):
                    value = int(value)
                elif spec.type in ("bool", bool):
                    value = bool(value)
                elif spec.type in ("str", str):
                    value = str(value)
            except (TypeError, ValueError):
                continue
            setattr(cfg, key, value)
    # Command-line / environment overrides are deliberately *not* written into
    # the dataclass -- see `effective_port`. Read them via `effective_host` /
    # `effective_port` so a one-off flag never becomes a saved preference.
    with _lock:
        _current = cfg
    return cfg


def update(patch: dict[str, Any], persist: bool = True) -> tuple[Config, list[str]]:
    """Apply a patch to the live config, optionally writing it to disk.

    Returns the new config plus a list of human-readable rejections. Invalid
    values are reported rather than silently clamped -- the Settings panel shows
    them inline next to the offending field.

    `persist=False` applies the change to the running sampler and nothing more.
    That is what the title-bar Refresh control uses: it means "show me faster
    right now", not "this is my saved preference". Persisting it there meant one
    mis-click permanently slowed sampling for every future run, with nothing in
    the UI explaining why -- so durable changes belong to the Settings page,
    which is explicit about saving.
    """
    global _current
    errors: list[str] = []
    known = {f.name: f for f in fields(Config)}
    with _lock:
        previous = _current
        cfg = Config(**_current.to_dict())
        for key, value in patch.items():
            if key not in EDITABLE:
                errors.append(f"{key}: not editable at runtime")
                continue
            spec = known[key]
            try:
                if spec.type in ("bool", bool):
                    value = bool(value)
                elif spec.type in ("int", int):
                    value = int(value)
                elif spec.type in ("float", float):
                    value = float(value)
                elif spec.type in ("str", str):
                    value = str(value).strip()
            except (TypeError, ValueError):
                errors.append(f"{key}: expected a number")
                continue
            if key in LIMITS:
                low, high = LIMITS[key]
                if not (low <= float(value) <= high):
                    errors.append(f"{key}: must be between {low:g} and {high:g}")
                    continue
            setattr(cfg, key, value)
        if not errors:
            changed = {
                key: value for key, value in patch.items()
                if getattr(previous, key, None) != getattr(cfg, key, None)
            }
            _current = cfg
            if not changed:
                return _current, errors
            # Logged either way: both kinds change how the sampler behaves, and
            # without a record a setting that moved by accident is invisible and
            # very confusing later.
            log.info(
                "config %s: %s",
                "updated" if persist else "changed for this session only",
                ", ".join(
                    f"{key}={getattr(previous, key, None)!r}->{value!r}"
                    for key, value in changed.items()
                ),
            )
            if not persist:
                return _current, errors
            try:
                CONFIG_PATH.write_text(
                    json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8"
                )
            except OSError as exc:
                errors.append(f"could not write config.json: {exc}")
    return _current, errors
