"""Lag Doctor: turn raw counters into "here is what is making this machine slow".

The design principle is that **resource usage is not the same as a problem**. A
process holding 6 GB on a machine with 40 GB free is not hurting anyone, and
ranking processes by raw memory would put it at the top every time. What matters
is a process's contribution to a resource that is *currently under pressure*.

On Windows, pressure had to be approximated from utilisation, queue depth,
fault rates and latency. On Linux the kernel computes the real thing:
**PSI** (/proc/pressure/*) is the measured fraction of wall time tasks spent
stalled on CPU, memory or IO. Where PSI exists it drives the pressure values;
the derived model stays as the labelled fallback (and as sub-signals, because
they explain *which* underlying number is moving). One deliberate exception:
memory pressure also honours the low-available-RAM watermark even when PSI is
quiet, because MemAvailable exhaustion is the leading indicator -- PSI only
fires once reclaim has already started hurting.

Scoring stays two-stage:

1. A 0..1 pressure per resource (CPU, memory, disk, GPU).
2. Each process scored by its share of each resource, gated by that resource's
   pressure, with a 0.3 floor so the ranking stays meaningful on an idle box.

The Windows "hung window" term is replaced by two kernel-level signals that are
more direct evidence of a process being made to wait: sustained D-state
(uninterruptible sleep -- `stuck`) and scheduler run delay from schedstat.
Window responsiveness itself does not exist on a headless/Wayland Linux box
and the UI says so instead of quietly omitting it.
"""

from __future__ import annotations

from ..config import Config
from ..util import Sustain, clamp, safe_div

# Severity ladder, worst last. Used for ordering and for the overall verdict.
SEVERITY_ORDER = ("ok", "info", "warn", "critical")

# Below this, a resource's pressure gate stops shrinking. Keeps the "top
# consumers" ranking sane when the machine is idle.
_PRESSURE_FLOOR = 0.30

# Reference points for normalising process-level rates into a 0..1 share.
_DISK_REFERENCE_FLOOR = 20 * 1024 * 1024   # 20 MB/s -- a busy-ish disk
_FAULT_REFERENCE_FLOOR = 5_000.0           # page faults/sec
# run_delay is ms-waiting-per-second-of-wall-time; 250ms/s means the process
# spends a quarter of its life runnable but starved of a CPU.
_RUN_DELAY_REFERENCE = 250.0


class LagAnalyzer:
    def __init__(self) -> None:
        self._sustain = Sustain()
        self._prev_oom: int | None = None

    # ------------------------------------------------------------- pressure
    def pressures(self, snapshot: dict, cfg: Config) -> dict[str, float]:
        """Per-resource pressure in 0..1. 1.0 means "this is the bottleneck"."""
        cpu = snapshot.get("cpu") or {}
        memory = snapshot.get("memory") or {}
        disk = (snapshot.get("disk") or {}).get("total") or {}
        gpu = snapshot.get("gpu") or {}
        psi = snapshot.get("psi") or {}

        # --- derived sub-signals (always computed: they explain the number,
        # and they are the whole model when PSI is absent) ------------------
        cpu_util = _ratio(cpu.get("total"), cfg.cpu_high)
        cpu_queue = _ratio(cpu.get("queue_per_core"), cfg.cpu_queue_per_core)

        available = memory.get("available_mb")
        mem_low = (
            0.0 if available is None or cfg.mem_available_low_mb <= 0
            else clamp(1.0 - safe_div(float(available), cfg.mem_available_low_mb),
                       0.0, 1.0)
        )
        # Only meaningful under strict overcommit; the heuristic default lets
        # Committed_AS blow past CommitLimit on perfectly healthy machines.
        commit = (_ratio(memory.get("commit_percent"), cfg.mem_commit_high)
                  if memory.get("commit_enforced") else 0.0)
        thrash = _ratio(memory.get("hard_faults_sec"), cfg.hard_faults_high)

        disk_latency = _ratio(disk.get("latency_ms"), cfg.disk_latency_high_ms)
        disk_queue = _ratio(disk.get("queue_length"), cfg.disk_queue_high)
        disk_busy = _ratio(disk.get("busy_percent"), cfg.disk_busy_high)

        # --- PSI, scaled against configurable "this much stall is a real
        # problem" thresholds ----------------------------------------------
        psi_cpu = _psi_avg10(psi, "cpu", "some")
        psi_mem_some = _psi_avg10(psi, "memory", "some")
        psi_mem_full = _psi_avg10(psi, "memory", "full")
        psi_io_some = _psi_avg10(psi, "io", "some")
        psi_io_full = _psi_avg10(psi, "io", "full")
        psi_mode = psi_cpu is not None

        if psi_mode:
            cpu_pressure = _ratio(psi_cpu, cfg.psi_cpu_high)
            # `full` stalls (everyone blocked) are weighted double: they are
            # the whole-machine freeze people actually report.
            mem_pressure = max(
                _ratio(psi_mem_some, cfg.psi_memory_high),
                _ratio(psi_mem_full, cfg.psi_memory_high / 2),
                mem_low,  # leading indicator; see module docstring
            )
            disk_pressure = max(
                _ratio(psi_io_some, cfg.psi_io_high),
                _ratio(psi_io_full, cfg.psi_io_high / 2),
            )
        else:
            cpu_pressure = max(cpu_util, cpu_queue)
            mem_pressure = max(mem_low, commit, thrash)
            # Latency is the honest disk signal; busy% is the weakest and is
            # discounted (worse still on multi-queue NVMe).
            disk_pressure = max(disk_latency, disk_queue, disk_busy * 0.7)

        gpu_pressure = _ratio(gpu.get("total"), cfg.gpu_high)

        return {
            "cpu": round(cpu_pressure, 3),
            "memory": round(mem_pressure, 3),
            "disk": round(disk_pressure, 3),
            "gpu": round(gpu_pressure, 3),
            "mode": "psi" if psi_mode else "derived",
            # Components, so the UI can explain which sub-signal fired.
            "detail": {
                "psi_cpu": _round3(_ratio(psi_cpu, cfg.psi_cpu_high)),
                "psi_memory": _round3(max(
                    _ratio(psi_mem_some, cfg.psi_memory_high),
                    _ratio(psi_mem_full, cfg.psi_memory_high / 2))),
                "psi_io": _round3(max(
                    _ratio(psi_io_some, cfg.psi_io_high),
                    _ratio(psi_io_full, cfg.psi_io_high / 2))),
                "cpu_utilisation": round(cpu_util, 3),
                "cpu_queue": round(cpu_queue, 3),
                "memory_available": round(mem_low, 3),
                "memory_commit": round(commit, 3),
                "memory_thrash": round(thrash, 3),
                "disk_latency": round(disk_latency, 3),
                "disk_queue": round(disk_queue, 3),
                "disk_busy": round(disk_busy, 3),
            },
        }

    # -------------------------------------------------------------- scoring
    def score_processes(self, processes: list[dict], snapshot: dict,
                        pressures: dict[str, float], cfg: Config) -> None:
        """Attach `lag_score`, `lag_breakdown` and `lag_reasons` in place."""
        memory = snapshot.get("memory") or {}
        disk_total = (snapshot.get("disk") or {}).get("total") or {}
        system_faults = (memory.get("page_faults_sec") or 0.0)

        total_ram = float(memory.get("total") or 0) or 1.0
        disk_reference = max(
            float((disk_total.get("read_bytes_sec") or 0)
                  + (disk_total.get("write_bytes_sec") or 0)),
            _DISK_REFERENCE_FLOOR,
        )
        fault_reference = max(float(system_faults), _FAULT_REFERENCE_FLOOR)

        gate = {
            key: max(_PRESSURE_FLOOR, float(pressures.get(key, 0.0)))
            for key in ("cpu", "memory", "disk", "gpu")
        }
        # Anchor: a process consuming 100% of the CPU while the CPU is the
        # bottleneck scores 100. Anything piling more on top clamps there.
        anchor = cfg.weight_cpu or 1.0

        for proc in processes:
            if proc.get("is_kthread"):
                # Kernel threads do real work but attributing "lag" to e.g.
                # kswapd inverts cause and effect -- kswapd being busy is a
                # *symptom* of memory pressure caused by someone else.
                proc["lag_score"] = 0.0
                proc["lag_breakdown"] = {}
                proc["lag_reasons"] = (["kernel thread"]
                                       if float(proc.get("cpu") or 0) > 0.5 else [])
                continue

            # Blend instantaneous with the rolling mean: sustained load should
            # outrank a one-tick spike, but a real spike should still surface.
            cpu_now = float(proc.get("cpu") or 0.0)
            cpu_avg = float(proc.get("cpu_avg") or 0.0)
            cpu_share = clamp((0.6 * cpu_now + 0.4 * cpu_avg) / 100.0, 0.0, 1.0)
            # Scheduler run delay: direct evidence this process wants CPU it
            # is not getting. Folded into the CPU term because it is the same
            # resource seen from the victim's side.
            delay_share = clamp(float(proc.get("run_delay_ms") or 0.0)
                                / _RUN_DELAY_REFERENCE, 0.0, 1.0)
            cpu_term_share = max(cpu_share, delay_share * 0.8)

            mem_share = clamp(float(proc.get("working_set") or 0) / total_ram, 0.0, 1.0)
            io_share = clamp(float(proc.get("io_bytes_sec") or 0) / disk_reference,
                             0.0, 1.0)
            gpu_share = clamp(float(proc.get("gpu") or 0.0) / 100.0, 0.0, 1.0)
            fault_share = clamp(float(proc.get("page_faults_sec") or 0.0)
                                / fault_reference, 0.0, 1.0)

            terms = {
                "cpu": cfg.weight_cpu * cpu_term_share * gate["cpu"],
                "memory": cfg.weight_memory * mem_share * gate["memory"],
                "disk": cfg.weight_disk * io_share * gate["disk"],
                "gpu": cfg.weight_gpu * gpu_share * gate["gpu"],
                # Faults ride on memory pressure -- soft faults alone are normal.
                "faults": cfg.weight_faults * fault_share * gate["memory"],
                # Ungated: a process stuck in uninterruptible sleep is being
                # made to wait no matter what the aggregate counters say.
                "stuck": cfg.weight_stuck if proc.get("stuck") else 0.0,
            }

            raw = sum(terms.values())
            proc["lag_score"] = round(clamp(100.0 * raw / anchor, 0.0, 100.0), 1)
            proc["lag_breakdown"] = {
                key: round(clamp(100.0 * value / anchor, 0.0, 100.0), 1)
                for key, value in terms.items() if value > 0.0005
            }
            proc["lag_reasons"] = _reasons(proc, mem_share)

    # ------------------------------------------------------------- verdicts
    def diagnose(self, snapshot: dict, processes: list[dict],
                 pressures: dict[str, float], cfg: Config,
                 volumes: list[dict] | None = None) -> dict[str, object]:
        """Build the sustained-pressure findings and attribute them to processes."""
        cpu = snapshot.get("cpu") or {}
        memory = snapshot.get("memory") or {}
        disk_total = (snapshot.get("disk") or {}).get("total") or {}
        gpu = snapshot.get("gpu") or {}
        psi = snapshot.get("psi") or {}

        candidates: list[dict[str, object]] = []

        def consider(key: str, active: bool, severity: str, title: str,
                     detail: str, resource: str, evidence: dict[str, object],
                     blame: str | None = None) -> None:
            streak = self._sustain.feed(key, active)
            if active and streak >= cfg.sustain_ticks:
                finding: dict[str, object] = {
                    "key": key, "severity": severity, "title": title,
                    "detail": detail, "resource": resource,
                    "evidence": evidence, "sustained_ticks": streak,
                }
                if blame:
                    # "Nobody on this machine is at fault": the cause is
                    # outside the process table (hypervisor, cooling, the
                    # swap device, a file server). No culprits are listed,
                    # because ranking processes under it would invent blame.
                    finding["external"] = True
                    finding["blame"] = blame
                candidates.append(finding)

        # --- PSI: the kernel's own stall measurements ----------------------
        psi_cpu = _psi_avg10(psi, "cpu", "some")
        if psi_cpu is not None:
            consider(
                "psi_cpu", psi_cpu >= cfg.psi_cpu_high,
                "critical" if psi_cpu >= cfg.psi_cpu_high * 1.8 else "warn",
                "Tasks stalled waiting for CPU",
                f"The kernel measured runnable tasks waiting for a CPU "
                f"{psi_cpu:.0f}% of the time (10s average). This is stall "
                "time, not utilisation -- it is the delay people feel.",
                "cpu", {"psi_some_avg10": round(psi_cpu, 1)},
            )
        psi_mem_full = _psi_avg10(psi, "memory", "full")
        if psi_mem_full is not None:
            active = psi_mem_full >= cfg.psi_memory_high / 2
            consider(
                "psi_memory", active,
                "critical" if psi_mem_full >= cfg.psi_memory_high else "warn",
                "Whole system stalled on memory",
                f"Every non-idle task was blocked on memory reclaim "
                f"{psi_mem_full:.1f}% of the time. This is the freeze that "
                "precedes OOM kills.",
                "memory", {"psi_full_avg10": round(psi_mem_full, 2)},
            )
        psi_io_full = _psi_avg10(psi, "io", "full")
        if psi_io_full is not None:
            consider(
                "psi_io", psi_io_full >= cfg.psi_io_high / 2,
                "critical" if psi_io_full >= cfg.psi_io_high else "warn",
                "System stalled on storage",
                f"All non-idle tasks were blocked on IO {psi_io_full:.1f}% of "
                "the time (10s average). Storage is holding everything up.",
                "disk", {"psi_full_avg10": round(psi_io_full, 2)},
            )

        # --- CPU -----------------------------------------------------------
        cpu_total = float(cpu.get("total") or 0.0)
        consider(
            "cpu_saturated", cpu_total >= cfg.cpu_high,
            "critical" if cpu_total >= 95 else "warn",
            "CPU saturated",
            f"CPU has held {cpu_total:.0f}% (threshold {cfg.cpu_high:.0f}%). "
            "Everything runnable is competing for cores.",
            "cpu", {"cpu_percent": round(cpu_total, 1)},
        )
        queue_per_core = float(cpu.get("queue_per_core") or 0.0)
        consider(
            "cpu_queue", queue_per_core >= cfg.cpu_queue_per_core,
            "critical" if queue_per_core >= cfg.cpu_queue_per_core * 3 else "warn",
            "Threads waiting for CPU",
            f"{queue_per_core:.1f} runnable threads per core are queued. This is "
            "what makes a machine feel unresponsive even below 100% CPU.",
            "cpu", {"queue_per_core": round(queue_per_core, 2),
                    "queue_length": cpu.get("queue_length")},
        )
        steal = float(cpu.get("steal") or 0.0)
        consider(
            "cpu_steal", steal >= 10.0,
            "critical" if steal >= 30.0 else "warn",
            "Hypervisor stealing CPU time",
            f"{steal:.0f}% of CPU time was taken by the hypervisor for other "
            "guests. This VM is slow because of its neighbours, not its own "
            "workload -- nothing inside the guest can fix it. Ask the "
            "platform for a less contended host, or reserve CPU for this VM.",
            "cpu", {"steal_percent": round(steal, 1)},
            blame="the hypervisor (noisy neighbours), not a process here",
        )
        thermal = cpu.get("thermal") or {}
        if thermal.get("available"):
            events = float(thermal.get("throttle_events_sec") or 0.0)
            ratio = thermal.get("clock_ratio")
            consider(
                "thermal_throttle", events >= 1.0,
                "critical" if events >= 20.0 else "warn",
                "CPU throttled by its thermal or power limit",
                f"The CPU logged {events:.0f} throttle events/s: it is cutting "
                "its own clock to stay within a temperature or power limit"
                + (f" (running at {float(ratio) * 100:.0f}% of its maximum "
                   "frequency)" if isinstance(ratio, (int, float)) else "")
                + ". Everything runs slower and no process caused it -- look "
                "at cooling, dust, airflow, or the power profile.",
                "cpu", {"throttle_events_sec": round(events, 1),
                        "clock_ratio": ratio,
                        "frequency_mhz": cpu.get("frequency_mhz")},
                blame="the CPU's cooling or power limit, not a process",
            )

        # --- Memory --------------------------------------------------------
        available_mb = memory.get("available_mb")
        if available_mb is not None:
            low = float(available_mb) <= cfg.mem_available_low_mb
            consider(
                "memory_low", low,
                "critical" if float(available_mb) <= cfg.mem_available_low_mb / 2
                else "warn",
                "Low available memory",
                f"Only {float(available_mb):,.0f} MB available (MemAvailable). "
                "The kernel is reclaiming caches and will start swapping or "
                "OOM-killing next.",
                "memory", {"available_mb": round(float(available_mb))},
            )
        commit_percent = float(memory.get("commit_percent") or 0.0)
        consider(
            "commit_high",
            bool(memory.get("commit_enforced"))
            and commit_percent >= cfg.mem_commit_high,
            "critical" if commit_percent >= 97 else "warn",
            "Commit charge near limit",
            f"Committed_AS is at {commit_percent:.0f}% of CommitLimit under "
            "strict overcommit (vm.overcommit_memory=2) -- allocations start "
            "failing here.",
            "memory", {"commit_percent": round(commit_percent, 1)},
        )
        hard_faults = float(memory.get("hard_faults_sec") or 0.0)
        consider(
            "thrashing", hard_faults >= cfg.hard_faults_high,
            "critical" if hard_faults >= cfg.hard_faults_high * 4 else "warn",
            "Paging from disk",
            f"{hard_faults:,.0f} major faults/sec. Memory is being served from "
            "disk instead of RAM -- the classic cause of whole-system stutter.",
            "memory", {"hard_faults_sec": round(hard_faults)},
        )
        swap_pages = (float(memory.get("swap_in_sec") or 0.0)
                      + float(memory.get("swap_out_sec") or 0.0))
        if memory.get("swap_rotational") is True:
            slow_devices = ", ".join(
                str(d.get("path")) for d in (memory.get("swap_devices") or [])
                if isinstance(d, dict) and d.get("rotational"))
            consider(
                "swap_slow", swap_pages >= 100.0,
                "critical" if swap_pages >= 2000.0 else "warn",
                "Swapping to a spinning disk",
                f"{swap_pages:,.0f} pages/s are moving to or from swap on a "
                f"rotational disk ({slow_devices}). Every page brought back "
                "costs a seek, so this stalls the whole machine far harder "
                "than the same paging on an SSD would. The fix is hardware: "
                "move swap to solid-state storage, or add RAM.",
                "memory", {"swap_in_sec": memory.get("swap_in_sec"),
                           "swap_out_sec": memory.get("swap_out_sec"),
                           "swap_device": slow_devices},
                blame="the swap device (a rotational disk), not a process",
            )

        # OOM kills: an event, not a level, so it bypasses the sustain window.
        oom_total = memory.get("oom_kills_total")
        if isinstance(oom_total, int):
            if self._prev_oom is not None and oom_total > self._prev_oom:
                candidates.append({
                    "key": "oom_kill", "severity": "critical",
                    "title": "The kernel killed a process (OOM)",
                    "detail": f"{oom_total - self._prev_oom} process(es) were "
                              "killed by the out-of-memory killer since the "
                              "last sample. See the Events view for which.",
                    "resource": "memory",
                    "evidence": {"oom_kills_total": oom_total},
                    "sustained_ticks": cfg.sustain_ticks,
                })
            self._prev_oom = oom_total

        # --- Disk ----------------------------------------------------------
        latency_ms = disk_total.get("latency_ms")
        if latency_ms is not None:
            value = float(latency_ms)
            consider(
                "disk_latency", value >= cfg.disk_latency_high_ms,
                "critical" if value >= cfg.disk_latency_high_ms * 3 else "warn",
                "Disk latency high",
                f"{value:.0f} ms average per request. Anything above "
                f"{cfg.disk_latency_high_ms:.0f} ms is felt directly as file "
                "operations and app launches hanging.",
                "disk", {"latency_ms": round(value, 1)},
            )
        queue_length = disk_total.get("queue_length")
        if queue_length is not None:
            value = float(queue_length)
            consider(
                "disk_queue", value >= cfg.disk_queue_high,
                "critical" if value >= cfg.disk_queue_high * 4 else "warn",
                "Disk queue backing up",
                f"{value:.1f} requests in flight. The storage stack cannot keep "
                "up with what is being asked of it. (On multi-queue NVMe this "
                "number is less meaningful -- trust latency first.)",
                "disk", {"queue_length": round(value, 2)},
            )
        busy = disk_total.get("busy_percent")
        if busy is not None:
            value = float(busy)
            # Busy alone is only informational -- an SSD can sit at 100% busy
            # with 0.3ms latency and nobody notices.
            consider(
                "disk_busy", value >= cfg.disk_busy_high, "info",
                "Disk busy",
                f"Disk active {value:.0f}% of the time. Not a problem on its own "
                "unless latency or PSI is also elevated -- and on multi-queue "
                "NVMe, active-time is close to meaningless.",
                "disk", {"busy_percent": round(value, 1)},
            )

        # --- GPU -----------------------------------------------------------
        if gpu.get("available"):
            gpu_total = float(gpu.get("total") or 0.0)
            consider(
                "gpu_saturated", gpu_total >= cfg.gpu_high, "warn",
                "GPU saturated",
                f"GPU at {gpu_total:.0f}%. On integrated graphics this also "
                "steals memory bandwidth from the CPU.",
                "gpu", {"gpu_percent": round(gpu_total, 1)},
            )

        # --- Volumes (checked on the slow tick, no sustain needed) ---------
        for volume in volumes or []:
            free_pct = 100.0 - float(volume.get("percent") or 0.0)
            if free_pct <= cfg.disk_space_low_pct:
                candidates.append({
                    "key": f"space_{volume.get('mountpoint')}",
                    "severity": "critical" if free_pct <= 3 else "warn",
                    "title": f"{volume.get('mountpoint')} nearly full",
                    "detail": f"{free_pct:.1f}% free for users (ext4 reserves "
                              "~5% for root on top of this). Full filesystems "
                              "fail writes, break package upgrades, and "
                              "journald starts dropping history.",
                    "resource": "storage",
                    "evidence": {"mountpoint": volume.get("mountpoint"),
                                 "free": volume.get("free"),
                                 "percent_used": volume.get("percent")},
                    "sustained_ticks": cfg.sustain_ticks,
                })

        # --- Stuck processes (uninterruptible sleep) -----------------------
        stuck = [p for p in processes if p.get("stuck")]
        if stuck:
            names = ", ".join(sorted({str(p["name"]) for p in stuck})[:4])
            wchans = sorted({str(p.get("wchan")) for p in stuck if p.get("wchan")})
            plural = "es" if len(stuck) != 1 else ""
            # The kernel function they are blocked in says *what* they wait
            # on. A cluster of NFS/SMB/FUSE waits is a file server (or the
            # network to it) stalling, not anything on this machine.
            remote = _remote_storage_cluster(wchans)
            finding = {
                "key": "stuck_procs", "severity": "critical",
                "title": f"{len(stuck)} process{plural} stuck in "
                         "uninterruptible sleep",
                "detail": f"{names} have sat in D-state for several consecutive "
                          "samples -- blocked inside the kernel, almost always "
                          "on dead storage or an unreachable network mount. "
                          "They cannot be killed until the IO completes."
                          + (f" Blocked in: {', '.join(wchans[:3])}." if wchans
                             else ""),
                "resource": "responsiveness",
                "evidence": {"pids": [p["pid"] for p in stuck],
                             "wchan": ", ".join(wchans[:3]) or None},
                "sustained_ticks": cfg.sustain_ticks,
            }
            if remote:
                finding["title"] = (f"{len(stuck)} process{plural} stuck waiting "
                                    f"on {remote}")
                finding["detail"] = (
                    f"{names} are blocked inside the kernel's {remote} client "
                    f"({', '.join(wchans[:3])}). The processes listed are the "
                    "victims, not the cause: the server on the other end (or "
                    "the network path to it) is not answering. Killing them "
                    "does nothing until the mount responds -- check the "
                    "server, then the mount options (soft/hard, timeo).")
                finding["external"] = True
                finding["blame"] = f"the {remote} server or the network to it"
                finding["victims"] = True
            candidates.append(finding)

        # Attribute each finding to the processes actually driving that resource.
        # An external finding lists no culprits -- unless the listed processes
        # are its *victims* (D-state), which the finding then says outright.
        for finding in candidates:
            if finding.get("external") and not finding.get("victims"):
                finding["culprits"] = []
            else:
                finding["culprits"] = _culprits(processes, str(finding["resource"]))

        candidates.sort(key=lambda f: (
            -SEVERITY_ORDER.index(str(f["severity"])),
            -float(f.get("sustained_ticks") or 0),
        ))

        worst = candidates[0]["severity"] if candidates else "ok"
        ranked = sorted(processes, key=lambda p: -float(p.get("lag_score") or 0))

        return {
            "status": _overall(worst),
            "severity": worst,
            "headline": _headline(worst, candidates),
            "findings": candidates,
            "pressures": pressures,
            "pressure_mode": pressures.get("mode", "derived"),
            "offenders": [_slim(p) for p in ranked[:12] if float(p.get("lag_score") or 0) > 1],
        }


# --------------------------------------------------------------------- helpers
def _ratio(value: object, threshold: float) -> float:
    """How far `value` has gone toward `threshold`, capped at 1.0."""
    if value is None or threshold <= 0:
        return 0.0
    try:
        return clamp(float(value) / threshold, 0.0, 1.0)
    except (TypeError, ValueError):
        return 0.0


def _psi_avg10(psi: dict, resource: str, kind: str) -> float | None:
    block = (psi or {}).get(resource) or {}
    values = block.get(kind) or {}
    value = values.get("avg10")
    return float(value) if isinstance(value, (int, float)) else None


def _round3(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


_RESOURCE_SORT = {
    "cpu": lambda p: -float(p.get("cpu") or 0),
    "memory": lambda p: -float(p.get("working_set") or 0),
    "disk": lambda p: -float(p.get("io_bytes_sec") or 0),
    "gpu": lambda p: -float(p.get("gpu") or 0),
    "storage": lambda p: -float(p.get("write_bytes_sec") or 0),
    "responsiveness": lambda p: (0 if p.get("stuck") else 1,
                                 -float(p.get("lag_score") or 0)),
}


def _culprits(processes: list[dict], resource: str) -> list[dict[str, object]]:
    """The processes most responsible for one resource being under pressure."""
    key = _RESOURCE_SORT.get(resource, _RESOURCE_SORT["cpu"])
    candidates = [p for p in processes if not p.get("is_kthread")]
    if resource == "responsiveness":
        candidates = [p for p in candidates if p.get("stuck")] or candidates
    if resource in ("disk", "storage"):
        # Per-process IO is permission-gated; blaming a process whose IO we
        # cannot read would be invention. Only measured, non-zero IO counts --
        # and when nothing qualifies, the finding shows no culprits rather
        # than a made-up ranking.
        candidates = [p for p in candidates
                      if (p.get("io_bytes_sec") or 0) > 0]
    if resource == "cpu":
        # For CPU, a starved victim is not the culprit; sort out the ones
        # merely suffering (high run delay, low usage).
        candidates = [p for p in candidates if float(p.get("cpu") or 0) > 0.1] \
            or candidates
    ranked = sorted(candidates, key=key)[:5]
    return [
        {
            "pid": p["pid"], "name": p["name"], "username": p.get("username"),
            "cpu": p.get("cpu"), "working_set": p.get("working_set"),
            "io_bytes_sec": p.get("io_bytes_sec"), "gpu": p.get("gpu"),
            "stuck": p.get("stuck"), "lag_score": p.get("lag_score"),
            "share": _share_text(p, resource),
            "container": p.get("container"),
        }
        for p in ranked
    ]


# wchan prefixes that mean "waiting on a remote filesystem". The kernel
# function name is the only evidence there is, and it is specific enough.
_REMOTE_WCHAN = (
    (("nfs", "rpc_", "__nfs", "xprt_"), "NFS"),
    (("cifs", "smb", "SMB"), "SMB/CIFS"),
    (("fuse_", "request_wait_answer"), "FUSE"),
    (("ceph_", "rbd_"), "Ceph"),
    (("glusterfs", "gf_"), "GlusterFS"),
)


def _remote_storage_cluster(wchans: list[str]) -> str | None:
    """The remote filesystem the stuck processes are waiting on, when every
    known wait function points at the same one (a mixed bag is not a verdict)."""
    if not wchans:
        return None
    labels: set[str] = set()
    for wchan in wchans:
        for prefixes, label in _REMOTE_WCHAN:
            if wchan.startswith(prefixes):
                labels.add(label)
                break
        else:
            return None   # a local wait in the mix: not a remote-storage verdict
    return labels.pop() if len(labels) == 1 else None


def _share_text(proc: dict, resource: str) -> str:
    if resource == "cpu":
        return f"{float(proc.get('cpu') or 0):.1f}% CPU"
    if resource == "memory":
        return f"{_mb(proc.get('working_set'))} resident"
    if resource in ("disk", "storage"):
        io = proc.get("io_bytes_sec")
        return "I/O not readable" if io is None else f"{_mb(io)}/s I/O"
    if resource == "gpu":
        return f"{float(proc.get('gpu') or 0):.0f}% GPU"
    if resource == "responsiveness":
        return "D-state" if proc.get("stuck") else ""
    return ""


def _reasons(proc: dict, mem_share: float) -> list[str]:
    """Short, specific phrases the UI shows under a process's score.

    Thresholds are low on purpose. An earlier version only spoke up at 15% CPU
    or 5% of RAM, which left processes scoring 6 or 7 with an empty explanation
    -- a number with no reason next to it is exactly the kind of thing that
    makes a dashboard untrustworthy. If nothing clears a threshold, the dominant
    term from the score breakdown is described instead, so every scored process
    can always say why.
    """
    out: list[str] = []
    if proc.get("stuck"):
        wchan = proc.get("wchan")
        out.append("Stuck in uninterruptible sleep"
                   + (f" ({wchan})" if wchan else ""))

    cpu_avg = float(proc.get("cpu_avg") or 0)
    cpu_now = float(proc.get("cpu") or 0)
    if cpu_avg >= 4:
        out.append(f"{cpu_avg:.1f}% CPU sustained")
    elif cpu_now >= 12:
        out.append(f"{cpu_now:.0f}% CPU spike")

    delay = float(proc.get("run_delay_ms") or 0)
    if delay >= 50:
        out.append(f"waiting {delay:.0f} ms/s for a CPU")

    if mem_share >= 0.02:
        out.append(f"{_mb(proc.get('working_set'))} RAM ({mem_share * 100:.0f}% of total)")

    io = float(proc.get("io_bytes_sec") or 0)
    if io >= 512 * 1024:
        out.append(f"{_mb(io)}/s disk I/O")

    gpu = float(proc.get("gpu") or 0)
    if gpu >= 3:
        out.append(f"{gpu:.0f}% GPU")

    majflt = float(proc.get("major_faults_sec") or 0)
    if majflt >= 20:
        out.append(f"{majflt:,.0f} major faults/s (paging)")

    threads = int(proc.get("threads") or 0)
    if threads >= 150:
        out.append(f"{threads} threads")

    if out:
        return out

    # Nothing crossed a threshold, but the process still scored. Explain the
    # largest contributing term rather than showing a bare number.
    breakdown = proc.get("lag_breakdown") or {}
    if breakdown:
        top = max(breakdown.items(), key=lambda item: item[1])[0]
        faults = float(proc.get("page_faults_sec") or 0)
        described = {
            "cpu": f"{cpu_now:.1f}% CPU",
            "memory": f"{_mb(proc.get('working_set'))} resident",
            "disk": f"{_mb(io)}/s disk I/O",
            "gpu": f"{gpu:.1f}% GPU",
            "faults": f"{faults:,.0f} page faults/s",
            "stuck": "uninterruptible sleep",
        }.get(top)
        if described:
            out.append(f"mostly {described}")
    return out


def _slim(proc: dict) -> dict[str, object]:
    return {
        key: proc.get(key) for key in (
            "pid", "ppid", "name", "username", "cpu", "cpu_avg", "cpu_raw",
            "working_set", "private", "io_bytes_sec", "read_bytes_sec",
            "write_bytes_sec", "gpu", "vram", "threads", "page_faults_sec",
            "major_faults_sec", "run_delay_ms", "state", "stuck", "wchan",
            "lag_score", "lag_breakdown", "lag_reasons", "exe", "container",
        )
    }


def _overall(severity: str) -> str:
    if severity == "ok":
        return "healthy"
    if severity == "info":
        return "nominal"
    if severity == "warn":
        return "strained"
    return "struggling"


def _headline(severity: str, findings: list[dict]) -> str:
    if not findings:
        return "No sustained resource pressure detected."
    top = findings[0]
    culprits = top.get("culprits") or []
    if top.get("external"):
        return f"{top['title']} - outside this machine: {top.get('blame')}."
    if culprits:
        lead = culprits[0]
        where = lead.get("container") or {}
        inside = f" in {where['name']}" if where.get("name") else ""
        return f"{top['title']} - {lead['name']}{inside} ({lead['share']}) leads."
    return str(top["title"])


def _mb(value: object) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "0 MB"
    if number >= 1024 ** 3:
        return f"{number / 1024 ** 3:.1f} GB"
    if number < 1024 ** 2:
        # "0 MB/s" next to a ranked culprit reads as a lie; say what it is.
        return f"{number / 1024:.0f} KB"
    return f"{number / 1024 ** 2:.0f} MB"
