"""Disk throughput, queue depth, latency and volume capacity.

Split across two cadences because the two questions are different:

* fast tick -- *is the disk the bottleneck right now?* Answered from
  /proc/diskstats deltas: await-style latency and queue depth, not throughput.
  A disk saturated at 100% busy with 2ms latency is fine; one at 40% busy with
  80ms latency is why the UI is frozen.
* slow tick -- *am I running out of space?* Mount enumeration touches the
  filesystem, and network/auto mounts can block for seconds (the same failure
  as Windows' disconnected network drives), so they are filtered before any
  statvfs call.

The %util caveat, carried over and sharpened: on multi-queue NVMe both
`ms_doing_io` (busy%) and `ios_in_progress` (queue) are much weaker signals
than on single-queue devices, because independent hardware queues overlap.
Latency is the number to lead with; the UI says so.
"""

from __future__ import annotations

import logging
import os
import time

from .. import linux
from ..util import clamp

log = logging.getLogger("culprit.disks")

_SECTOR = 512  # /proc/diskstats sector counts are always 512-byte units

# Filesystems that are memory, packaging or plumbing rather than storage.
_SKIP_FSTYPES = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "ramfs", "proc", "sysfs",
    "cgroup", "cgroup2", "devpts", "securityfs", "debugfs", "tracefs",
    "pstore", "bpf", "autofs", "mqueue", "hugetlbfs", "configfs", "fusectl",
    "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "fuse.snapfuse",
    "fuse.portal", "fuse.gvfsd-fuse",
}
# These can block for seconds when the far end is gone; statvfs on them is how
# a monitoring tool hangs its own sampler.
_NETWORK_FSTYPES = {"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs",
                    "9p", "ceph", "glusterfs", "afs"}


class DiskCollector:
    """Fast-tick physical disk activity from /proc/diskstats."""

    def __init__(self) -> None:
        self._devices = _whole_devices()
        self._prev: dict[str, tuple[float, dict[str, int]]] = {}
        self._prev_at = 0.0
        self.sample()  # prime the deltas

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        stats = _read_diskstats(self._devices)
        disks = []
        total = {"read_bytes_sec": 0.0, "write_bytes_sec": 0.0,
                 "reads_sec": 0.0, "writes_sec": 0.0, "queue_length": 0.0,
                 "busy_ms": 0.0, "io_ms": 0.0, "ios": 0.0,
                 "read_total": 0, "write_total": 0}

        physical_count = 0
        for name, row in stats.items():
            layered = bool(self._devices.get(name, {}).get("layered"))
            prev = self._prev.get(name)
            self._prev[name] = (now, row)
            if not layered:
                total["read_total"] += row["sectors_read"] * _SECTOR
                total["write_total"] += row["sectors_written"] * _SECTOR
            if not prev or now <= prev[0]:
                continue
            dt = now - prev[0]
            d = {key: max(0, row[key] - prev[1].get(key, 0)) for key in row}

            reads = d["reads"] / dt
            writes = d["writes"] / dt
            read_bytes = d["sectors_read"] * _SECTOR / dt
            write_bytes = d["sectors_written"] * _SECTOR / dt
            ios = d["reads"] + d["writes"]
            # await, exactly as iostat computes it: total time waited divided
            # by IOs completed. The most honest "how slow is storage" number.
            latency = ((d["ms_reading"] + d["ms_writing"]) / ios) if ios else 0.0
            read_latency = (d["ms_reading"] / d["reads"]) if d["reads"] else 0.0
            write_latency = (d["ms_writing"] / d["writes"]) if d["writes"] else 0.0
            busy = clamp(100.0 * d["ms_doing_io"] / (dt * 1000.0))
            merged = (d["reads_merged"] + d["writes_merged"]) / dt

            rotational = self._devices.get(name, {}).get("rotational")
            disks.append({
                "instance": name,
                "layered": layered,
                "index": None,          # Linux disks have names, not indexes
                "letters": name,        # what the per-disk rows display
                "rotational": rotational,
                "read_bytes_sec": round(read_bytes),
                "write_bytes_sec": round(write_bytes),
                "reads_sec": round(reads, 1),
                "writes_sec": round(writes, 1),
                "queue_length": row["ios_in_progress"],
                "busy_percent": round(busy, 1),
                "latency_ms": round(latency, 2),
                "read_latency_ms": round(read_latency, 2),
                "write_latency_ms": round(write_latency, 2),
                "merged_io_sec": round(merged, 1),
            })

            if layered:
                continue  # already counted through the underlying disk
            physical_count += 1
            total["read_bytes_sec"] += read_bytes
            total["write_bytes_sec"] += write_bytes
            total["reads_sec"] += reads
            total["writes_sec"] += writes
            total["queue_length"] += row["ios_in_progress"]
            total["busy_ms"] += d["ms_doing_io"]
            total["io_ms"] += d["ms_reading"] + d["ms_writing"]
            total["ios"] += ios

        elapsed = (now - self._prev_at) if self._prev_at else 0.0
        self._prev_at = now
        device_count = max(1, physical_count)

        return {
            "available": bool(stats),
            "reason": None if stats else "/proc/diskstats listed no whole block devices",
            "disks": sorted(disks, key=lambda d: d["instance"]),
            "total": {
                "read_bytes_sec": round(total["read_bytes_sec"]),
                "write_bytes_sec": round(total["write_bytes_sec"]),
                "reads_sec": round(total["reads_sec"], 1),
                "writes_sec": round(total["writes_sec"], 1),
                "queue_length": round(total["queue_length"], 2),
                # Busy% averaged across devices so one idle disk of two reads
                # as 50%, matching what the per-disk rows show.
                "busy_percent": (
                    round(clamp(100.0 * total["busy_ms"]
                                / (elapsed * 1000.0 * device_count)), 1)
                    if elapsed and disks else None
                ),
                "latency_ms": (round(total["io_ms"] / total["ios"], 2)
                               if total["ios"] else 0.0),
                "read_total": total["read_total"],
                "write_total": total["write_total"],
            },
        }

    def close(self) -> None:
        pass


class VolumeCollector:
    """Slow-tick mount capacity + block-device identity."""

    def __init__(self) -> None:
        self._media: list[dict[str, object]] | None = None

    def sample(self) -> dict[str, object]:
        volumes = []
        skipped = []
        seen_devices: set[str] = set()
        for mount in _mounts():
            fstype, mountpoint, source, options = (
                mount["fstype"], mount["mountpoint"], mount["source"],
                mount["options"])
            base_type = fstype.split(".")[0]
            if fstype in _SKIP_FSTYPES or base_type in _SKIP_FSTYPES:
                continue
            if fstype in _NETWORK_FSTYPES or base_type in _NETWORK_FSTYPES:
                # statvfs on a dead NFS/CIFS mount blocks for seconds inside
                # the kernel with no way to time it out from here.
                skipped.append({"device": source,
                                "reason": f"network filesystem ({fstype}) -- "
                                          "not probed, it can hang the sampler"})
                continue
            if source in seen_devices:
                continue  # bind mounts and btrfs subvolumes repeat the device
            seen_devices.add(source)
            try:
                usage = os.statvfs(mountpoint)
            except OSError as exc:
                skipped.append({"device": source, "reason": str(exc)})
                continue
            frsize = usage.f_frsize or usage.f_bsize
            total = usage.f_blocks * frsize
            if total == 0:
                continue
            # f_bavail, not f_bfree: ext4 reserves ~5% for root, and reporting
            # root's number to a user overstates what they can actually write.
            free = usage.f_bavail * frsize
            reserved = max(0, (usage.f_bfree - usage.f_bavail)) * frsize
            used = total - usage.f_bfree * frsize
            usable = used + free
            volumes.append({
                "device": source,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "opts": options,
                "readonly": "ro" in options.split(","),
                "label": _label_for(source),
                "total": total,
                "used": used,
                "free": free,
                "reserved": reserved,
                "percent": round(100.0 * used / usable, 1) if usable else 0.0,
            })
        volumes.sort(key=lambda v: v["mountpoint"])

        if self._media is None:
            self._media = _block_media()

        return {
            "volumes": volumes,
            "skipped": skipped,
            "media": self._media or [],
        }


# --------------------------------------------------------------------- helpers
def _whole_devices() -> dict[str, dict[str, object]]:
    """Whole block devices (not partitions), minus loop/ram noise.

    /sys/block only lists whole devices, which is exactly the split needed --
    partition rows in diskstats double-count everything.
    """
    out: dict[str, dict[str, object]] = {}
    try:
        names = os.listdir("/sys/block")
    except OSError:
        return out
    for name in names:
        if name.startswith(("loop", "ram", "zram", "sr", "fd")):
            continue
        rotational = linux.read_int(f"/sys/block/{name}/queue/rotational")
        # Layered devices (dm-*, md*) sit on top of real disks; counting both
        # double-counts every IO in the totals. They stay in the per-disk rows
        # (their queue depth is real information) but are flagged out of sums.
        layered = False
        try:
            layered = bool(os.listdir(f"/sys/block/{name}/slaves"))
        except OSError:
            pass
        out[name] = {
            "rotational": bool(rotational) if rotational is not None else None,
            "layered": layered,
        }
    return out


_DISKSTAT_FIELDS = (
    "reads", "reads_merged", "sectors_read", "ms_reading",
    "writes", "writes_merged", "sectors_written", "ms_writing",
    "ios_in_progress", "ms_doing_io", "weighted_ms_doing_io",
)


def _read_diskstats(devices: dict[str, dict]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    text = linux.read_text("/proc/diskstats") or ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if name not in devices:
            continue
        try:
            values = [int(v) for v in parts[3:3 + len(_DISKSTAT_FIELDS)]]
        except ValueError:
            continue
        out[name] = dict(zip(_DISKSTAT_FIELDS, values))
    return out


def _mounts() -> list[dict[str, str]]:
    """Parse /proc/self/mountinfo -- unlike /proc/mounts it survives odd mount
    namespaces and separates the optional fields unambiguously."""
    out = []
    text = linux.read_text("/proc/self/mountinfo") or ""
    for line in text.splitlines():
        # ... mountpoint options optional... - fstype source superopts
        left, _, right = line.partition(" - ")
        left_parts = left.split()
        right_parts = right.split()
        if len(left_parts) < 6 or len(right_parts) < 2:
            continue
        out.append({
            "mountpoint": _unescape(left_parts[4]),
            "options": left_parts[5],
            "fstype": right_parts[0],
            "source": right_parts[1],
        })
    return out


def _unescape(text: str) -> str:
    """mountinfo escapes space/tab/newline/backslash as octal."""
    if "\\" not in text:
        return text
    for code, char in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"),
                       ("\\134", "\\")):
        text = text.replace(code, char)
    return text


def _label_for(source: str) -> str | None:
    try:
        for label in os.listdir("/dev/disk/by-label"):
            target = os.path.realpath(f"/dev/disk/by-label/{label}")
            if target == os.path.realpath(source):
                return _unescape(label.replace("\\x20", " "))
    except OSError:
        pass
    return None


def _block_media() -> list[dict[str, object]]:
    """Identity per whole device from lsblk, plus honest health degradation.

    smartctl/nvme-cli give real SMART data but need CAP_SYS_RAWIO or root (and
    are frequently not installed); their absence is reported as *unknown*,
    never as healthy.
    """
    payload = linux.run_json([
        "lsblk", "--json", "-d", "-b",
        "-o", "NAME,TYPE,SIZE,ROTA,MODEL,SERIAL,TRAN,REV,VENDOR",
    ])
    out: list[dict[str, object]] = []
    devices = (payload or {}).get("blockdevices") if isinstance(payload, dict) else None
    smart_reason = _smart_unavailable_reason()
    for dev in devices or []:
        if dev.get("type") != "disk" or str(dev.get("name", "")).startswith(
                ("loop", "ram", "zram")):
            continue
        rota = dev.get("rota")
        out.append({
            "index": None,
            "name": dev.get("name"),
            "model": (str(dev.get("model") or "").strip()
                      or str(dev.get("vendor") or "").strip() or None),
            "interface": dev.get("tran"),
            "media_type": ("HDD (rotational)" if rota
                           else "SSD" if rota is False else None),
            "size": dev.get("size"),
            "serial": str(dev.get("serial") or "").strip() or None,
            "firmware": str(dev.get("rev") or "").strip() or None,
            "status": None,
            "smart_reason": smart_reason,
        })
    return out


def _smart_unavailable_reason() -> str | None:
    import shutil

    if not (shutil.which("smartctl") or shutil.which("nvme")):
        return ("smartctl / nvme-cli are not installed "
                "(sudo apt install smartmontools nvme-cli)")
    if os.geteuid() != 0 and "CAP_SYS_RAWIO" not in linux.capabilities():
        return "SMART queries need CAP_SYS_RAWIO or root"
    return None
