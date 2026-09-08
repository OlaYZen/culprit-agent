"""The Prognosis: what is wearing out, read from the hardware's own counters.

Every other doctor here looks at software. The Lag Doctor gates on pressure,
the Outage Doctor on things that stopped working, the Pulse on things that
stopped happening, the Coroner on a machine that stopped. All five point at
the hardware and none of them reads it: the Outage Doctor's storage item ends
with "check SMART and back up first", the Events view says "SMART data and
back up early", and `disks.py` carries SMART as a *reason it was not read*.

This is the layer under the kernel. It reads the wear and error counters the
hardware already keeps -- a disk's own SMART attributes, an SSD's endurance
estimate, the memory controller's ECC counts, the PCIe link's AER counters,
the SATA link's negotiated speed, a battery's design capacity -- and says
which part is on its way out, how far along it is, and what it is already
costing. A SMART exporter graphs those numbers and leaves you the vendor
semantics and the alert; this ships the sentence.

The rules the code keeps, each pinned by tools/check_prognosis.py:

1. **Read only. Never a self-test, never a wake-up.** SMART is read with
   `smartctl -n standby`, so a spun-down drive is reported as asleep and left
   asleep with its last values kept. There is no `-t` anywhere in this file,
   and the operator has to opt in (`prognosis_wake_disks`) before a sleeping
   disk is touched at all. Waking someone's archive shelf every half hour is
   not monitoring.
2. **Standard attributes only, each named by id.** ATA 5, 187, 188, 197, 198
   and 199, the drive's own `when_failed` flag, and the NVMe health log as
   the specification defines it. Everything else the drive reports is carried
   as an unread number under `raw` and never judged -- a vendor attribute
   means what that vendor says it means, and guessing is how monitoring tools
   invent failures.
3. **Rising beats non-zero beats absent.** A counter that moved since the
   last read is the finding. A non-zero counter that has not moved is a
   warning that says since when. A zero is a fact, not a bill of health, and
   a source that cannot be read is `available: False` with the exact unlock.
4. **A guest says so.** On a VM the disks are virtual, EDAC does not exist
   and the SATA links do not negotiate. The section says *run the agent on
   the hypervisor* rather than rendering a virtual disk as healthy.
5. **A forecast states its window.** The endurance date is host-side (it
   needs more days than an agent process lives) and always quotes how many
   days it was fitted over.

Cost: a few dozen small sysfs reads every events tick, and one `smartctl -j`
per disk every `prognosis_smart_interval_minutes` (default 30). smartctl
reads NVMe too, so nothing here needs an ioctl or a new dependency.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
from typing import Any

from .. import linux

log = logging.getLogger("culprit.prognosis")

_SEV = {"ok": 0, "info": 1, "warn": 2, "critical": 3}

# ---------------------------------------------------------------- constants

# The only ATA attributes judged, by id. Ids are stable across vendors where
# the *names* are not, which is why every sentence quotes the id.
ATA_ATTRS: dict[int, str] = {
    5: "Reallocated_Sector_Ct",
    187: "Reported_Uncorrect",
    188: "Command_Timeout",
    197: "Current_Pending_Sector",
    198: "Offline_Uncorrectable",
    199: "UDMA_CRC_Error_Count",
}
# Attributes about the platter: a rise in any of them is the drive giving up
# on data. 199 is deliberately not here -- see ATA_CABLE.
ATA_SURFACE = (5, 187, 188, 197, 198)
# Currently unreadable sectors. Non-zero is a warning even when it is not
# moving: the sector is unreadable *now*, whatever the trend says.
ATA_PENDING = (197, 198)
# The cable, connector, port or backplane -- never the platter.
ATA_CABLE = 199
# Endurance attributes. Judged only through the vendor's own `when_failed`
# flag, never from the raw value: 231 is "SSD life left" on one drive and
# "temperature" on the next.
ATA_ENDURANCE = (231, 233)

# NVMe critical_warning bits, in the specification's order, in words.
NVME_WARNING_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "spare capacity is below its threshold"),
    (0x02, "temperature is outside the range the drive was made for"),
    (0x04, "reliability is degraded: the media is wearing out or has faulted"),
    (0x08, "the media has been placed in read-only mode"),
    (0x10, "the volatile-memory backup device has failed"),
    (0x20, "the persistent-memory region is read-only or unreliable"),
)
# NVMe reports written data in 512 000-byte units (1 000 x 512), per the spec.
NVME_DATA_UNIT_BYTES = 512_000

# Endurance thresholds on `percentage_used`, the drive's own estimate.
WEAR_INFO = 70
WEAR_WARN = 90
WEAR_CRIT = 100

# One corrected memory error a day is already unusual on a healthy DIMM, and
# the *rate* is the signal -- a machine up for two years with 40 lifetime
# corrections is not the same as one that corrected 40 yesterday.
ECC_CE_PER_DAY = 1.0
# Corrected PCIe errors are retried and normal in small numbers; a link that
# is retrying this often is a link that is about to stop retrying.
AER_COR_PER_DAY = 100.0

# A battery below this fraction of its design capacity no longer holds the
# runtime the machine was specified with.
POWER_HEALTH_WARN = 70.0
POWER_HEALTH_CRIT = 50.0

# How many reads of each subject the agent keeps on disk, so "rose since the
# last read" survives a restart without waiting for the host.
RING_DEPTH = 8
# One smartctl call may not take longer than this; a drive that does not
# answer is reported as unread, never as a stalled tick.
SMART_TIMEOUT_S = 20.0
DEFAULT_SMART_INTERVAL_MINUTES = 30

# Models that are a hypervisor's fiction. Their counters describe nothing --
# a virtual disk has no platter to reallocate -- so they are never judged.
VIRTUAL_MODELS = ("qemu harddisk", "qemu dvd-rom", "virtual disk", "vbox harddisk",
                  "vbox cd-rom", "msft virtual disk", "vmware virtual", "virtual hd",
                  "vmware, vmware virtual s", "virtio")

# Every sysfs path in this file goes through here so tools/check_prognosis.py
# can point the whole collector at a fixture tree. Nothing else is injectable:
# the rest of the module is pure functions over what these reads returned.
SYSFS_ROOT = ""


def _sys(path: str) -> str:
    """`/sys/...` with the fixture prefix in front of it (empty in production)."""
    return f"{SYSFS_ROOT}{path}"


_ATA_PORT = re.compile(r"/ata(\d+)/")
_AER_LINE = re.compile(r"^(\w+)\s+(\d+)$")


# ------------------------------------------------------------------ access
def smart_access() -> dict[str, Any]:
    """Whether SMART can be read here, and which half is missing.

    One place names the unlock (sysinfo's access map reads this), so the
    Storage table, the Prognosis checks strip and the access panel cannot
    drift apart.
    """
    installed = bool(shutil.which("smartctl"))
    privileged = os.geteuid() == 0 or "CAP_SYS_RAWIO" in linux.capabilities()
    if not installed:
        reason = ("smartctl is not installed (sudo apt install smartmontools)"
                  if privileged else
                  "smartctl is not installed (sudo apt install smartmontools), and "
                  "SMART queries need CAP_SYS_RAWIO or root")
    elif not privileged:
        reason = "SMART queries need CAP_SYS_RAWIO or root"
    else:
        reason = None
    return {"ok": installed and privileged, "installed": installed,
            "privileged": privileged, "needs": "CAP_SYS_RAWIO or root for SMART health",
            "reason": reason}


def smartctl_argv(name: str, dev_type: str | None = None,
                  wake_disks: bool = False) -> list[str]:
    """The command line for one device. `-n standby` is not optional unless
    the operator has said so: without it every read spins up a sleeping
    drive, and there is no `-t` here at any setting -- this tool never asks
    hardware to do work."""
    argv = ["smartctl", "-j", "-H", "-A", "-l", "selftest"]
    if not wake_disks:
        argv += ["-n", "standby"]
    if dev_type:
        argv += ["-d", dev_type]
    argv.append(name if name.startswith("/dev/") else f"/dev/{name}")
    return argv


# -------------------------------------------------------------- parsing
def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return int(value)
    except (ValueError, OverflowError):
        return None


def _first_int(text: str) -> int | None:
    match = re.search(r"\d+", text or "")
    return int(match.group()) if match else None


def parse_attribute(entry: dict[str, Any]) -> dict[str, Any]:
    """One ATA attribute row, with the packed-raw case handled.

    Some vendors pack several counters into the 48-bit raw field (Seagate's
    seek-error rate is the famous one), so smartctl's `raw.value` can be an
    enormous number while `raw.string` shows the counter a human means. When
    the two disagree the first integer of the string wins and the row says
    `packed`, because a "12 000 000 000 reallocated sectors" sentence is
    worse than no sentence.
    """
    raw = entry.get("raw") if isinstance(entry.get("raw"), dict) else {}
    value = _int(raw.get("value"))
    string = str(raw.get("string") or "")
    packed = False
    from_string = _first_int(string)
    if from_string is not None and value is not None and from_string != value:
        value, packed = from_string, True
    elif value is None and from_string is not None:
        value = from_string
    when_failed = str(entry.get("when_failed") or "").strip() or None
    return {
        "name": str(entry.get("name") or "") or None,
        "raw": value,
        "raw_string": string or None,
        "packed": packed,
        "value": _int(entry.get("value")),
        "worst": _int(entry.get("worst")),
        "thresh": _int(entry.get("thresh")),
        # smartctl writes "-" for "never"; anything else is the drive saying
        # this attribute has been below its threshold.
        "when_failed": None if when_failed in (None, "-", "") else when_failed,
    }


def parse_smartctl(payload: dict[str, Any]) -> dict[str, Any]:
    """The judged counters and the drive's own verdicts from one `smartctl -j`.

    Everything the parser does not judge is kept under `raw` for the view's
    disclosure, so an operator can read the whole table without another tool
    and without this file pretending to understand it.
    """
    payload = payload if isinstance(payload, dict) else {}
    attributes: dict[str, dict[str, Any]] = {}
    table = ((payload.get("ata_smart_attributes") or {}).get("table")
             if isinstance(payload.get("ata_smart_attributes"), dict) else None)
    extra: list[dict[str, Any]] = []
    for entry in table or []:
        if not isinstance(entry, dict):
            continue
        ident = _int(entry.get("id"))
        if ident is None:
            continue
        parsed = parse_attribute(entry)
        parsed["id"] = ident
        if ident in ATA_ATTRS or ident in ATA_ENDURANCE:
            attributes[str(ident)] = parsed
        else:
            extra.append(parsed)

    nvme = None
    log_block = payload.get("nvme_smart_health_information_log")
    if isinstance(log_block, dict):
        warning = _int(log_block.get("critical_warning")) or 0
        written = _int(log_block.get("data_units_written"))
        nvme = {
            "critical_warning": warning,
            "critical_warning_bits": [word for bit, word in NVME_WARNING_BITS
                                      if warning & bit],
            "available_spare": _int(log_block.get("available_spare")),
            "available_spare_threshold": _int(log_block.get("available_spare_threshold")),
            "percentage_used": _int(log_block.get("percentage_used")),
            "media_errors": _int(log_block.get("media_errors")),
            "unsafe_shutdowns": _int(log_block.get("unsafe_shutdowns")),
            "power_on_hours": _int(log_block.get("power_on_hours")),
            "data_units_written": written,
            "bytes_written": None if written is None else written * NVME_DATA_UNIT_BYTES,
            "temperature_c": _int(log_block.get("temperature")),
            "error_log_entries": _int(log_block.get("num_err_log_entries")),
        }

    status = payload.get("smart_status")
    passed = status.get("passed") if isinstance(status, dict) else None

    selftest, selftest_passed = _selftest(payload)
    temperature = _int((payload.get("temperature") or {}).get("current")
                       if isinstance(payload.get("temperature"), dict) else None)
    if temperature is None and nvme:
        temperature = nvme.get("temperature_c")
    hours = _int((payload.get("power_on_time") or {}).get("hours")
                 if isinstance(payload.get("power_on_time"), dict) else None)
    if hours is None and nvme:
        hours = nvme.get("power_on_hours")

    return {
        "passed": passed if isinstance(passed, bool) else None,
        "attributes": attributes,
        "nvme": nvme,
        "selftest": selftest,
        "selftest_passed": selftest_passed,
        "power_on_hours": hours,
        "temperature_c": temperature,
        "model": str(payload.get("model_name") or "").strip() or None,
        "serial": str(payload.get("serial_number") or "").strip() or None,
        "firmware": str(payload.get("firmware_version") or "").strip() or None,
        "capacity": _int((payload.get("user_capacity") or {}).get("bytes")
                         if isinstance(payload.get("user_capacity"), dict) else None),
        "rotation_rate": _int(payload.get("rotation_rate")),
        # Read, kept, never judged (rule 2).
        "raw": {"vendor_attributes": extra,
                "messages": [str(m.get("string") or "")[:200]
                             for m in ((payload.get("smartctl") or {}).get("messages") or [])
                             if isinstance(m, dict)][:8]},
    }


def _selftest(payload: dict[str, Any]) -> tuple[str | None, bool | None]:
    """The most recent self-test the drive has a record of. The Prognosis
    never *starts* one; it reads what someone or the vendor's firmware
    already ran."""
    for key in ("ata_smart_self_test_log", "nvme_self_test_log"):
        block = payload.get(key)
        if not isinstance(block, dict):
            continue
        table = block.get("table")
        if not isinstance(table, list):
            # ATA nests one level deeper: standard / extended.
            for nested in block.values():
                if isinstance(nested, dict) and isinstance(nested.get("table"), list):
                    table = nested["table"]
                    break
        if not isinstance(table, list) or not table:
            continue
        first = table[0]
        if not isinstance(first, dict):
            continue
        status = first.get("status") if isinstance(first.get("status"), dict) else {}
        text = str(status.get("string") or "").strip() or None
        passed = status.get("passed")
        return text, passed if isinstance(passed, bool) else None
    return None, None


def counters_of(smart: dict[str, Any]) -> dict[str, int]:
    """The flat set of judged numbers for one disk -- what the ring keeps and
    what the host stores one row of per day. Deliberately small: the whole
    point of the wear table is that a year of it is a few thousand rows."""
    out: dict[str, int] = {}
    for ident, entry in (smart.get("attributes") or {}).items():
        raw = entry.get("raw")
        if isinstance(raw, int):
            out[ident] = raw
    nvme = smart.get("nvme") or {}
    for key in ("percentage_used", "media_errors", "available_spare",
                "available_spare_threshold", "critical_warning", "unsafe_shutdowns"):
        value = nvme.get(key)
        if isinstance(value, int):
            out[key] = value
    for key in ("power_on_hours", "temperature_c"):
        value = smart.get(key)
        if isinstance(value, int):
            out[key] = value
    return out


def parse_aer(text: str | None) -> dict[str, int]:
    """`aer_dev_correctable` and friends: one `Name Count` pair per line."""
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        match = _AER_LINE.match(line.strip())
        if match:
            out[match.group(1)] = int(match.group(2))
    return out


# ------------------------------------------------------------------ sentences
def build_detail(item: dict[str, Any]) -> str:
    """One item's detail, from its parts.

    The agent knows what a counter is doing between its own reads; the host
    knows what it has been doing for months. Both build the sentence here, so
    "unchanged across the 8 reads this agent has made" and "unchanged since
    3 Aug" are two renderings of one function rather than two texts that can
    disagree.
    """
    parts = [str(s) for s in (item.get("says") or []) if s]
    for entry in item.get("stable") or []:
        parts.append(_stable_sentence(entry))
    forecast = item.get("forecast")
    if isinstance(forecast, dict) and forecast.get("reaches_at"):
        parts.append(_forecast_sentence(forecast))
    if item.get("closing"):
        parts.append(str(item["closing"]))
    return " ".join(parts)


def _forecast_sentence(forecast: dict[str, Any]) -> str:
    """The one sentence a forecast is allowed to say -- and it always says
    what it was fitted over. A date with no window behind it is a guess
    wearing a calendar."""
    unit = str(forecast.get("unit") or "%")
    when = time.strftime("%-d %b %Y", time.localtime(float(forecast["reaches_at"])))
    return (f"At {_number(forecast.get('per_day'))} {unit} a day over the last "
            f"{forecast.get('fitted_days')} days it reaches "
            f"{_number(forecast.get('target', 100))} {unit} around {when}.")


def _number(value: Any) -> str:
    """Two significant digits for a rate. A slope carried to four decimals
    claims a precision the fit does not have."""
    if isinstance(value, float):
        return str(int(value)) if value == int(value) else f"{value:.2g}"
    return str(value)


def _stable_sentence(entry: dict[str, Any]) -> str:
    label = entry.get("label") or entry.get("name") or entry.get("id")
    value = entry.get("value")
    day = entry.get("since_day")
    if day:
        when = time.strftime("%-d %b %Y", time.localtime(float(day)))
        if entry.get("since_all"):
            # The run reaches the oldest row there is, so the honest claim is
            # about the record, not about the drive.
            return (f"{label} is {value}, unchanged for as long as this host has "
                    f"watched it (since {when}).")
        return f"{label} is {value}, unchanged since {when}."
    reads = int(entry.get("reads") or 1)
    return (f"{label} is {value}, unchanged across the {reads} read"
            f"{'' if reads == 1 else 's'} this agent has made.")


def _attr_label(ident: str, attributes: dict[str, Any]) -> str:
    name = (attributes.get(ident) or {}).get("name") or ATA_ATTRS.get(int(ident), ident)
    return f"{name} ({ident})"


# ------------------------------------------------------------------ the ring
class _Ring:
    """The last few reads per subject, on disk beside the flight recorder.

    Without it a restarted agent would report every counter as "first seen"
    and could not say *rising* until the host had two days of rows. A few KB,
    rewritten atomically after each pass; a corrupt file is ignored, never
    fatal -- it is a convenience, not a record.
    """

    def __init__(self, path: str | None) -> None:
        self.path = path
        self._data: dict[str, list[dict[str, Any]]] = {}
        self.load()

    def load(self) -> None:
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError) as exc:
            log.debug("prognosis ring not read (%s); starting fresh", exc)
            return
        if not isinstance(raw, dict):
            log.debug("prognosis ring is not an object; starting fresh")
            return
        for subject, reads in (raw.get("subjects") or {}).items():
            if not isinstance(subject, str) or not isinstance(reads, list):
                continue
            clean = [r for r in reads[-RING_DEPTH:]
                     if isinstance(r, dict) and isinstance(r.get("counters"), dict)]
            if clean:
                self._data[subject] = clean

    def save(self) -> None:
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump({"subjects": self._data}, handle, separators=(",", ":"))
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            log.debug("could not write the prognosis ring: %s", exc)

    def previous(self, subject: str) -> dict[str, Any] | None:
        reads = self._data.get(subject) or []
        return reads[-1] if reads else None

    def reads(self, subject: str) -> list[dict[str, Any]]:
        return list(self._data.get(subject) or [])

    def push(self, subject: str, counters: dict[str, int], ts: float) -> None:
        reads = self._data.setdefault(subject, [])
        reads.append({"ts": float(ts), "counters": dict(counters)})
        del reads[:-RING_DEPTH]

    def forget_all_but(self, subjects: set[str]) -> None:
        for subject in [s for s in self._data if s not in subjects]:
            del self._data[subject]

    def stable_reads(self, subject: str, key: str, value: int) -> int:
        """How many consecutive reads (this one included) held this value."""
        count = 1
        for read in reversed(self.reads(subject)):
            if read.get("counters", {}).get(key) == value:
                count += 1
            else:
                break
        return count


# ------------------------------------------------------------------- judges
def judge_disk(device: dict[str, Any], previous: dict[str, Any] | None,
               ring: _Ring | None = None,
               arrays: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Every item one disk earns. Pure apart from the ring lookup, which is
    only ever read."""
    if device.get("virtual"):
        return []                      # rule 4: a fiction has nothing to wear out
    smart = device.get("smart") or {}
    if not smart.get("read"):
        return []                      # unread is a check, not a finding
    subject = str(device.get("subject") or "")
    name = str(device.get("name") or subject)
    attributes = smart.get("attributes") or {}
    nvme = smart.get("nvme") or {}
    now_counters = device.get("counters") or {}
    prev_counters = (previous or {}).get("counters") or {}
    prev_at = (previous or {}).get("ts")
    array = _array_of(name, arrays)

    items: list[dict[str, Any]] = []
    says: list[str] = []
    stable: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    severity = "ok"
    rising_since = None

    def rose(key: str) -> tuple[bool, int | None, int | None]:
        now = now_counters.get(key)
        was = prev_counters.get(key)
        if not isinstance(now, int) or not isinstance(was, int):
            return False, now, was
        return now > was, now, was

    # --- the drive's own verdicts ----------------------------------------
    if smart.get("passed") is False:
        severity = "critical"
        says.append(f"{name}'s own SMART status says FAILING: the drive has crossed a "
                    "threshold its manufacturer set for it.")
        evidence.append({"label": "smart_status", "value": "FAILING"})
    elif smart.get("passed") is True:
        evidence.append({"label": "smart_status", "value": "PASSED"})
    if smart.get("selftest_passed") is False:
        severity = "critical"
        says.append(f"The last self-test in the drive's log ended in "
                    f"\"{smart.get('selftest')}\".")
        evidence.append({"label": "last self-test", "value": str(smart.get("selftest"))})

    for ident in ATA_ENDURANCE:
        entry = attributes.get(str(ident))
        if entry and entry.get("when_failed"):
            severity = "critical"
            says.append(f"{_attr_label(str(ident), attributes)} is flagged failed by the "
                        f"drive itself ({entry['when_failed']}).")

    # --- the surface counters --------------------------------------------
    for ident in ATA_SURFACE:
        key = str(ident)
        entry = attributes.get(key)
        if entry is None or not isinstance(now_counters.get(key), int):
            continue
        label = _attr_label(key, attributes)
        moved, now_value, was = rose(key)
        if entry.get("when_failed"):
            severity = "critical"
            says.append(f"{label} is flagged failed by the drive itself.")
        if moved:
            severity = "critical"
            rising_since = rising_since or prev_at
            when = f" at {time.strftime('%H:%M', time.localtime(prev_at))}" if prev_at else ""
            says.append(f"{label} is {now_value}, up from {was}{when}.")
            evidence.append({"label": label, "value": f"{now_value} (was {was})"})
        elif now_value:
            if ident in ATA_PENDING:
                severity = _worse(severity, "warn")
                says.append(f"{label} is {now_value}: that many sectors are unreadable "
                            "right now, whatever the trend says.")
                evidence.append({"label": label, "value": str(now_value)})
            else:
                severity = _worse(severity, "warn")
                stable.append({"id": key, "label": label, "value": now_value,
                               "reads": ring.stable_reads(subject, key, now_value)
                               if ring else 1, "since_day": None})
                evidence.append({"label": label, "value": str(now_value)})

    # --- NVMe -------------------------------------------------------------
    if nvme:
        warning_words = nvme.get("critical_warning_bits") or []
        if warning_words:
            severity = "critical"
            says.append(f"The drive's critical warning flag is set: {'; '.join(warning_words)}.")
            evidence.append({"label": "critical_warning",
                             "value": f"0x{int(nvme.get('critical_warning') or 0):02x}"})
        spare, floor = nvme.get("available_spare"), nvme.get("available_spare_threshold")
        if isinstance(spare, int) and isinstance(floor, int) and spare < floor:
            severity = "critical"
            says.append(f"Spare capacity is {spare} %, below the {floor} % floor the "
                        "drive was shipped with.")
            evidence.append({"label": "available_spare", "value": f"{spare} % (floor {floor} %)"})
        moved, now_value, was = rose("media_errors")
        if moved:
            severity = "critical"
            rising_since = rising_since or prev_at
            says.append(f"media_errors is {now_value}, up from {was}: that many reads "
                        "returned data the drive could not correct.")
            evidence.append({"label": "media_errors", "value": f"{now_value} (was {was})"})
        elif isinstance(now_value, int) and now_value:
            severity = _worse(severity, "warn")
            stable.append({"id": "media_errors", "label": "media_errors",
                           "value": now_value,
                           "reads": ring.stable_reads(subject, "media_errors", now_value)
                           if ring else 1, "since_day": None})

    if says or stable:
        for label, value in (("power on", _hours(smart.get("power_on_hours"))),
                             ("temperature", _degrees(smart.get("temperature_c")))):
            if value:
                evidence.append({"label": label, "value": value})
        closing = None
        if smart.get("passed") is True and severity == "critical":
            closing = ("The drive's own SMART status still says PASSED, which it does "
                       "until the thresholds it shipped with are crossed -- those "
                       "thresholds are set for warranty returns, not for your data.")
        item = {
            "key": f"disk_failing:{subject}", "kind": "disk", "subject": subject,
            "severity": severity if severity != "ok" else "warn",
            "title": _failing_title(name, says, severity),
            "says": says, "stable": stable, "closing": closing,
            "device": _identity(device), "evidence": evidence,
            "raid": array, "rising_since": rising_since,
            "fix": _replace_fix(name, array),
        }
        item["detail"] = build_detail(item)
        items.append(item)

    # --- the cable (199), never the platter -------------------------------
    cable_key = str(ATA_CABLE)
    moved, now_value, was = rose(cable_key)
    if moved:
        label = _attr_label(cable_key, attributes)
        link = device.get("link") or {}
        item = {
            "key": f"disk_cable:{subject}", "kind": "disk", "subject": subject,
            "severity": "warn",
            "title": f"{name} is losing frames on the wire, not on the platter",
            "says": [f"{label} is {now_value}, up from {was}. That counter is the "
                     "interface: the cable, the connector, the port or the backplane "
                     f"between the controller and {name}"
                     + (f" (ATA {link.get('ata')})" if link.get("ata") else "")
                     + ". The data is retried and arrives, so nothing is lost; what it "
                       "costs is latency, which the Lag Doctor sees as slow IO."],
            "stable": [], "closing": None,
            "device": _identity(device),
            "evidence": [{"label": label, "value": f"{now_value} (was {was})"}],
            "raid": array, "rising_since": prev_at,
            "fix": f"reseat both ends of {name}'s data cable (or swap it); check the "
                   "backplane slot if it is hot-swap",
        }
        item["detail"] = build_detail(item)
        items.append(item)

    # --- endurance --------------------------------------------------------
    used = nvme.get("percentage_used")
    if isinstance(used, int):
        wear_severity = ("critical" if used >= WEAR_CRIT else "warn" if used >= WEAR_WARN
                         else "info" if used >= WEAR_INFO else None)
        if wear_severity:
            past = used >= WEAR_CRIT
            item = {
                "key": f"disk_wear:{subject}", "kind": "disk", "subject": subject,
                "severity": wear_severity,
                "title": (f"{name} is past its rated endurance ({used} %)" if past
                          else f"{name} has used {used} % of its rated endurance"),
                "says": [f"percentage_used is {used}: the drive's own estimate of how "
                         "much of the write endurance it was rated for has been spent."],
                "stable": [], "forecast": None,
                "closing": ("Past 100 % the drive keeps working, but it is outside its "
                            "warranty and its error rate is no longer characterised."
                            if past else
                            "Nothing is wrong yet. This is the number that says when to "
                            "buy the replacement rather than when to look for one."),
                "device": _identity(device),
                "evidence": [{"label": "percentage_used", "value": f"{used} %"},
                             {"label": "written", "value": _written(nvme)},
                             {"label": "power on", "value": _hours(smart.get("power_on_hours"))}],
                "raid": array, "rising_since": None,
                "fix": None,
            }
            item["evidence"] = [e for e in item["evidence"] if e["value"]]
            item["detail"] = build_detail(item)
            items.append(item)
    return items


def _failing_title(name: str, says: list[str], severity: str) -> str:
    if severity == "critical":
        first = (says[0] if says else "").lower()
        if "up from" in first:
            return f"{name} is failing: its error counters are rising"
        return f"{name} is failing"
    return f"{name} has damage it is not adding to"


def _worse(current: str, candidate: str) -> str:
    return candidate if _SEV.get(candidate, 0) > _SEV.get(current, 0) else current


def _identity(device: dict[str, Any]) -> dict[str, Any]:
    return {key: device.get(key) for key in
            ("name", "model", "serial", "transport", "rotational", "size", "firmware")}


def _array_of(name: str, arrays: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """The md array this disk is a member of, if any -- members are named by
    partition (`sda1`), so the match is on the prefix."""
    for array in arrays or []:
        members = [str(m) for m in (array.get("members") or [])]
        if any(m == name or m.startswith(name) for m in members):
            return {"array": array.get("name"), "level": array.get("level"),
                    "degraded": bool(array.get("degraded"))}
    return None


def _replace_fix(name: str, array: dict[str, Any] | None) -> str:
    fix = (f"Back up what is on it first. Confirm with: smartctl -a /dev/{name}. "
           "Then replace the drive")
    if array and array.get("array"):
        return (fix + f"; {array['array']} will rebuild onto the new member "
                f"(mdadm --manage /dev/{array['array']} --fail /dev/{name} --remove "
                f"/dev/{name}, then --add the replacement). A rebuild reads every "
                "other member end to end, which is when a second tired disk tends "
                "to fail -- so back up before, not after.")
    return fix + "."


def _hours(hours: Any) -> str | None:
    if not isinstance(hours, int) or hours <= 0:
        return None
    years = hours / 8760.0
    return f"{years:.1f} years ({hours:,} h)" if years >= 1 else f"{hours:,} h"


def _degrees(value: Any) -> str | None:
    return f"{value} °C" if isinstance(value, int) else None


def _written(nvme: dict[str, Any]) -> str | None:
    written = nvme.get("bytes_written")
    if not isinstance(written, int) or written <= 0:
        return None
    return f"{written / 1024 ** 4:.1f} TB written"


def judge_link(link: dict[str, Any]) -> dict[str, Any] | None:
    """A SATA link that negotiated below what it is capable of. The disk is
    fine and the cable may be too; the ceiling is what changed."""
    if not link.get("downgraded"):
        return None
    disk = link.get("disk") or link.get("ata")
    item = {
        "key": f"sata_downgraded:{link.get('ata')}", "kind": "link",
        "subject": str(link.get("ata")), "severity": "warn",
        "title": f"{disk} negotiated {link.get('speed')} on a {link.get('max')} link",
        "says": [f"The SATA link {link.get('ata')} came up at {link.get('speed')} "
                 f"although both ends can do {link.get('max')}. Nothing on the machine "
                 "chose this: it is a ceiling the hardware negotiated, usually after a "
                 "cable, connector or backplane went marginal, and it caps every read "
                 f"and write to {disk} for as long as it holds."],
        "stable": [], "closing": None,
        "device": {"name": disk}, "rising_since": None,
        "evidence": [{"label": "negotiated", "value": str(link.get("speed"))},
                     {"label": "capable of", "value": str(link.get("max"))}],
        "fix": f"reseat or replace {disk}'s data cable, then check the link again "
               f"(cat /sys/class/ata_link/{link.get('ata')}/sata_spd); a reboot "
               "renegotiates it",
    }
    item["detail"] = build_detail(item)
    return item


def judge_nic(nic: dict[str, Any]) -> dict[str, Any] | None:
    """A physical interface that is up at less than the fastest this machine
    has ever seen it run. The machine's own past is the ceiling: reading the
    driver's supported-mode list would need an ethtool ioctl, and what the
    link *did* is a better claim than what it could."""
    speed, best = nic.get("speed_mbps"), nic.get("best_seen_mbps")
    if not nic.get("physical") or not nic.get("up"):
        return None
    if not isinstance(speed, int) or not isinstance(best, int) or speed >= best:
        return None
    name = str(nic.get("name"))
    duplex = f" ({nic.get('duplex')} duplex)" if nic.get("duplex") else ""
    item = {
        "key": f"link_downgraded:{name}", "kind": "nic",
        "subject": name, "severity": "warn",
        "title": f"{name} is up at {_mbit(speed)}, not the {_mbit(best)} it has run at",
        "says": [f"{name} negotiated {_mbit(speed)}{duplex}. "
                 f"This machine has seen the same interface at {_mbit(best)}, so the "
                 "link is negotiating below what this cable and this switch port have "
                 "already proved they can do -- a damaged pair, a dirty connector or a "
                 "switch port that has fallen back."],
        "stable": [], "closing": None, "rising_since": None,
        "device": {"name": nic.get("name"), "model": nic.get("driver")},
        "evidence": [{"label": "now", "value": _mbit(speed)},
                     {"label": "seen at", "value": _mbit(best)},
                     {"label": "driver", "value": str(nic.get("driver") or "?")}],
        "fix": f"reseat both ends of {nic.get('name')}'s cable; then ethtool "
               f"{nic.get('name')} to see what the driver and the switch agree on",
    }
    item["detail"] = build_detail(item)
    return item


def _mbit(value: Any) -> str:
    if not isinstance(value, int):
        return "?"
    return f"{value / 1000:g} Gbit/s" if value >= 1000 else f"{value} Mbit/s"


def judge_memory(controllers: list[dict[str, Any]], previous: dict[str, Any] | None,
                 elapsed: float) -> list[dict[str, Any]]:
    """ECC: an uncorrected error is always critical, a corrected *rate* is the
    warning. Lifetime corrected counts are not: a machine up for two years
    with forty of them is nothing like one that corrected forty yesterday."""
    prev = (previous or {}).get("counters") or {}
    out: list[dict[str, Any]] = []
    for controller in controllers:
        mc = str(controller.get("name") or "mc")
        ue = controller.get("ue_count")
        if isinstance(ue, int) and ue > 0:
            culprit_dimms = [d for d in (controller.get("dimms") or [])
                             if int(d.get("ue_count") or 0) > 0]
            where = (", ".join(str(d.get("label") or d.get("name")) for d in culprit_dimms)
                     if culprit_dimms else "a module this controller cannot localise")
            item = {
                "key": f"ecc_uncorrected:{mc}", "kind": "memory", "subject": mc,
                "severity": "critical",
                "title": f"Memory on {mc} returned data it could not correct",
                "says": [f"{ue} uncorrectable ECC error{'' if ue == 1 else 's'} on {mc} "
                         f"({where}). ECC caught it, which means the machine was told "
                         "the data was wrong rather than being handed it silently -- "
                         "but a module doing this is failing, and the next one may land "
                         "in kernel memory."],
                "stable": [], "closing": None, "rising_since": None,
                "device": {"name": mc, "model": controller.get("mem_type")},
                "evidence": [{"label": "ue_count", "value": str(ue)},
                             {"label": "modules", "value": where}],
                "fix": "identify the module (edac-util -v, or dmidecode -t memory "
                       "for the slot), replace it, and run a memtest pass on the rest",
            }
            item["detail"] = build_detail(item)
            out.append(item)
        ce = controller.get("ce_count")
        was = prev.get(f"{mc}:ce")
        if isinstance(ce, int) and isinstance(was, int) and elapsed > 0 and ce > was:
            per_day = (ce - was) / (elapsed / 86400.0)
            if per_day >= ECC_CE_PER_DAY:
                dimms = [d for d in (controller.get("dimms") or [])
                         if int(d.get("ce_count") or 0) > int(prev.get(
                             f"{mc}:{d.get('name')}:ce") or 0)]
                where = (", ".join(str(d.get("label") or d.get("name")) for d in dimms)
                         if dimms else None)
                item = {
                    "key": f"ecc_rising:{mc}" + (f"/{dimms[0].get('name')}" if len(dimms) == 1 else ""),
                    "kind": "memory", "subject": mc, "severity": "warn",
                    "title": (f"{where} is correcting memory errors" if where
                              else f"Memory on {mc} is correcting errors"),
                    "says": [f"{ce - was} corrected ECC error"
                             f"{'' if ce - was == 1 else 's'} in the last "
                             f"{_span(elapsed)} ({per_day:.0f} a day at this rate)"
                             + (f", localised to {where}" if where else "")
                             + ". Corrected means nothing was lost. A module that "
                               "corrects at a rate is a module on its way to an error "
                               "it cannot correct."],
                    "stable": [], "closing": None, "rising_since": None,
                    "device": {"name": where or mc, "model": controller.get("mem_type")},
                    "evidence": [{"label": "ce_count", "value": f"{ce} (was {was})"},
                                 {"label": "rate", "value": f"{per_day:.0f}/day"}],
                    "fix": "edac-util -v to name the module; swap it at the next "
                           "window and watch whether the rate follows the module or "
                           "the slot",
                }
                item["detail"] = build_detail(item)
                out.append(item)
    return out


def _span(seconds: float) -> str:
    if seconds >= 86400:
        return f"{seconds / 86400:.1f} days"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 60:.0f} min"


def judge_pci(devices: list[dict[str, Any]], previous: dict[str, Any] | None,
              elapsed: float) -> list[dict[str, Any]]:
    """PCIe AER. Fatal and non-fatal errors are the link failing; correctable
    ones are the link retrying, which is normal in ones and twos and is a
    symptom in thousands."""
    prev = (previous or {}).get("counters") or {}
    out: list[dict[str, Any]] = []
    for device in devices:
        bdf = str(device.get("bdf"))
        label = device.get("label") or bdf
        fatal, nonfatal = device.get("fatal") or 0, device.get("nonfatal") or 0
        if fatal or nonfatal:
            severity = "critical" if fatal else "warn"
            item = {
                "key": f"pcie_errors:{bdf}", "kind": "pci", "subject": bdf,
                "severity": severity,
                "title": f"{label} reported {'fatal' if fatal else 'non-fatal'} PCIe errors",
                "says": [f"The PCIe link to {label} at {bdf} has logged {fatal} fatal and "
                         f"{nonfatal} non-fatal error{'' if nonfatal == 1 else 's'}. "
                         "These are not retried: the transaction failed and the driver "
                         "was told. A card, a riser, a slot or the cabling to it is at "
                         "fault, not the software using it."],
                "stable": [], "closing": None, "rising_since": None,
                "device": {"name": bdf, "model": device.get("label"),
                           "driver": device.get("driver")},
                "evidence": [{"label": "fatal", "value": str(fatal)},
                             {"label": "non-fatal", "value": str(nonfatal)},
                             {"label": "driver", "value": str(device.get("driver") or "?")}],
                "fix": f"reseat the card at {bdf} (and its riser); lspci -vv -s {bdf} "
                       "shows the link's own status bits",
            }
            item["detail"] = build_detail(item)
            out.append(item)
            continue
        now = device.get("correctable")
        was = prev.get(f"{bdf}:cor")
        if not (isinstance(now, int) and isinstance(was, int) and elapsed > 0 and now > was):
            continue
        per_day = (now - was) / (elapsed / 86400.0)
        if per_day < AER_COR_PER_DAY:
            continue
        item = {
            "key": f"pcie_errors:{bdf}", "kind": "pci", "subject": bdf, "severity": "warn",
            "title": f"{label} is retrying on the PCIe link",
            "says": [f"{now - was} corrected link errors in the last {_span(elapsed)} "
                     f"({per_day:.0f} a day at this rate) on {bdf}. Every one of them "
                     "was retried and succeeded, so no data was lost; the link is "
                     "spending its margin, and links that spend it usually go on to "
                     "throw the errors that are not corrected."],
            "stable": [], "closing": None, "rising_since": None,
            "device": {"name": bdf, "model": device.get("label"),
                       "driver": device.get("driver")},
            "evidence": [{"label": "TOTAL_ERR_COR", "value": f"{now} (was {was})"},
                         {"label": "rate", "value": f"{per_day:.0f}/day"},
                         {"label": "driver", "value": str(device.get("driver") or "?")}],
            "fix": f"reseat the card at {bdf} and its riser; lspci -vv -s {bdf} shows "
                   "the negotiated width and speed, which a marginal link often drops",
        }
        item["detail"] = build_detail(item)
        out.append(item)
    return out


def judge_power(supplies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A battery or UPS that no longer holds what it was built to hold. This
    is the one subject whose failure is silent until the power goes."""
    out: list[dict[str, Any]] = []
    for supply in supplies:
        health = supply.get("health_pct")
        if not isinstance(health, (int, float)) or health >= POWER_HEALTH_WARN:
            continue
        name = str(supply.get("name"))
        severity = "warn" if health >= POWER_HEALTH_CRIT else "critical"
        cycles = supply.get("cycle_count")
        item = {
            "key": f"power_worn:{name}", "kind": "power", "subject": name,
            "severity": severity,
            "title": f"{name} holds {health:.0f} % of the charge it was built for",
            "says": [f"Full charge is {health:.0f} % of the design capacity"
                     + (f" after {cycles} cycles" if isinstance(cycles, int) and cycles else "")
                     + ". Nothing reports this until the power actually goes, and then "
                       "the machine gets whatever fraction of the runtime it was "
                       "specified with."],
            "stable": [], "closing": None, "rising_since": None,
            "device": {"name": name, "model": supply.get("model"),
                       "manufacturer": supply.get("manufacturer")},
            "evidence": [{"label": "full charge", "value": f"{health:.0f} % of design"},
                         {"label": "cycles", "value": str(cycles) if cycles else "?"},
                         {"label": "status", "value": str(supply.get("status") or "?")}],
            "fix": f"replace the {'UPS ' if supply.get('type') == 'UPS' else ''}battery; "
                   "until then treat the machine as having no ride-through",
        }
        item["detail"] = build_detail(item)
        out.append(item)
    return out


# ------------------------------------------------------------------ collector
class PrognosisCollector:
    """The events-tier pass. Holds the ring, the smartctl cadence and the last
    read of each sysfs subject; everything it decides is in the pure judges
    above so the offline tool can drive them with fixtures."""

    def __init__(self, data_dir: str | None = None) -> None:
        self._ring = _Ring(os.path.join(data_dir, "prognosis.json") if data_dir else None)
        self._smart_at: float | None = None
        self._smart: dict[str, dict[str, Any]] = {}    # subject -> last smart block
        self._smart_pass_ms: float | None = None
        self._since: dict[str, float] = {}
        self._started = time.time()
        self._best_speed: dict[str, int] = {}
        self._sysfs_prev: dict[str, dict[str, Any]] = {}

    # ----------------------------------------------------------------- sample
    def sample(self, volumes: dict | None = None, network: dict | None = None,
               kernel: dict | None = None, system: dict | None = None,
               changes: Any = None, settings: dict | None = None,
               now: float | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        now = time.time() if now is None else now
        settings = settings or {}
        if settings.get("enabled") is False:
            return {"available": False, "reason": "disabled in settings", "ts": now,
                    "status": "unknown", "severity": "ok", "items": [], "count": 0,
                    "devices": [], "links": [], "nics": [],
                    "memory": {"available": False, "reason": "disabled in settings",
                               "controllers": []},
                    "pci": [], "power": [], "checks": {}}

        checks: dict[str, Any] = {}
        virt = str((system or {}).get("virtualization") or "") or None
        items: list[dict[str, Any]] = []

        links = self._links(checks)
        devices = self._disks(volumes, links, virt, checks, settings, now)
        nics = self._nics(network, checks)
        memory = self._memory(checks)
        pci = self._pci(checks)
        power = self._power(checks)
        checks["guest"] = self._guest_check(virt, devices)

        arrays = ((kernel or {}).get("mdstat") or {}).get("arrays") or []
        for device in devices:
            items += judge_disk(device, self._ring.previous(device["subject"]),
                                self._ring, arrays)
        for link in links:
            item = judge_link(link)
            if item:
                items.append(item)
        for nic in nics:
            item = judge_nic(nic)
            if item:
                items.append(item)
        items += judge_memory(memory.get("controllers") or [],
                              self._ring.previous("memory"),
                              self._elapsed("memory", now))
        items += judge_pci(pci, self._ring.previous("pci"), self._elapsed("pci", now))
        items += judge_power(power)

        self._remember(devices, memory, pci, now)

        # `since` and the change log, exactly as the Outage Doctor keeps them:
        # an item present on the first sample predates the record, and the
        # changes around the agent's own start are startup noise.
        live = {item["key"] for item in items}
        for key in [k for k in self._since if k not in live]:
            del self._since[key]
        for item in items:
            since = self._since.setdefault(item["key"], now)
            item["since"] = since
            item["since_start"] = since - self._started < 90.0
            item["changes"] = []
            if changes is not None and not item["since_start"]:
                try:
                    item["changes"] = changes.around(since)
                except Exception:  # noqa: BLE001 -- a missing log is not a failure
                    item["changes"] = []

        items.sort(key=lambda i: (-_SEV.get(i["severity"], 0), i["key"]))
        worst = "ok"
        for item in items:
            worst = _worse(worst, item["severity"])
        failing = [i for i in items if i["severity"] == "critical"]
        wearing = [i for i in items if i["severity"] == "warn"]
        # "ok" is a claim, so it needs something read. A link speed and an
        # interface speed are not a health check: with no disk read, no ECC
        # controller and no battery, the honest word is *unknown*, and the
        # checks strip below says why.
        judged = (any((d["smart"] or {}).get("read") for d in devices)
                  or bool(memory.get("controllers")) or bool(power))
        return {
            "available": True, "reason": None, "ts": now,
            "status": ("failing" if failing else "wearing" if wearing
                       else "ok" if judged else "unknown"),
            "severity": worst,
            "items": items, "count": len(items),
            "failing": len(failing), "wearing": len(wearing),
            "devices": devices, "links": links, "nics": nics,
            "memory": memory, "pci": pci, "power": power,
            "checks": checks,
            "sample_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    # ------------------------------------------------------------------ disks
    def _disks(self, volumes: dict | None, links: list[dict[str, Any]],
               virt: str | None, checks: dict[str, Any], settings: dict,
               now: float) -> list[dict[str, Any]]:
        media = [m for m in ((volumes or {}).get("media") or []) if isinstance(m, dict)]
        identities = [_from_media(m) for m in media] if media else _sysfs_disks()
        link_by_disk = {str(link.get("disk")): link for link in links if link.get("disk")}

        access = smart_access()
        interval = float(settings.get("smart_interval_minutes")
                         or DEFAULT_SMART_INTERVAL_MINUTES) * 60.0
        wake = bool(settings.get("wake_disks"))
        # None means never: the first events tick pays for the first pass, so
        # a fresh agent has real numbers within two minutes rather than half
        # an hour of "not read yet".
        due = bool(access["ok"] and identities
                   and (self._smart_at is None or now - self._smart_at >= interval))
        if due:
            self._smart_pass(identities, wake)
            self._smart_at = now

        devices: list[dict[str, Any]] = []
        for identity in identities:
            subject = _subject_of(identity)
            smart = dict(self._smart.get(subject) or {})
            if not smart:
                smart = {"read": False, "asleep": False, "stale_since": None,
                         "reason": access["reason"] or
                         ("not read yet" if access["ok"] else "SMART is not readable here")}
            device = {
                "kind": "disk", "subject": subject, **identity,
                "virtual": _is_virtual(identity, virt),
                "smart": smart,
                "counters": counters_of(smart) if smart.get("read") else {},
                "link": {k: v for k, v in (link_by_disk.get(str(identity.get("name"))) or {}).items()
                         if k in ("ata", "speed", "max", "downgraded")} or None,
            }
            devices.append(device)

        read = sum(1 for d in devices if (d["smart"] or {}).get("read"))
        asleep = sum(1 for d in devices if (d["smart"] or {}).get("asleep"))
        checks["smart"] = {
            "available": bool(access["ok"] and devices),
            "reason": access["reason"] if not access["ok"] else
                      (None if devices else "no whole disks found"),
            "installed": access["installed"], "privileged": access["privileged"],
            "devices": len(devices), "read": read, "asleep": asleep,
            "virtual": sum(1 for d in devices if d["virtual"]),
            "wake_disks": wake,
            "last_pass": self._smart_at,
            "next_pass": None if self._smart_at is None else self._smart_at + interval,
            "pass_ms": self._smart_pass_ms,
        }
        return devices

    def _smart_pass(self, identities: list[dict[str, Any]], wake: bool) -> None:
        """One `smartctl -j` per disk. The whole pass is bounded per device, so
        a drive that has stopped answering costs one timeout, not the tick."""
        started = time.perf_counter()
        types = _scan_types()
        for identity in identities:
            name = str(identity.get("name") or "")
            if not name:
                continue
            subject = _subject_of(identity)
            previous = self._smart.get(subject) or {}
            argv = smartctl_argv(name, types.get(f"/dev/{name}"), wake)
            result = linux.run_status(argv, timeout=SMART_TIMEOUT_S)
            if result is None:
                self._smart[subject] = {**previous, "read": False, "asleep": False,
                                        "reason": f"smartctl did not answer in "
                                                  f"{SMART_TIMEOUT_S:.0f} s"}
                continue
            code, text = result
            try:
                payload = json.loads(text) if text else {}
            except ValueError:
                payload = {}
            messages = " ".join(
                str(m.get("string") or "") for m in
                ((payload.get("smartctl") or {}).get("messages") or [])
                if isinstance(m, dict)).lower()
            if code & 0x02 and not payload.get("ata_smart_attributes") \
                    and not payload.get("nvme_smart_health_information_log"):
                if "standby" in messages or "sleep" in messages or "low power" in messages:
                    # Rule 1: it stays asleep, and the last values stay with it.
                    self._smart[subject] = {**previous, "read": False, "asleep": True,
                                            "stale_since": previous.get("at"),
                                            "reason": "the drive is in standby and was "
                                                      "left there"}
                else:
                    self._smart[subject] = {
                        **previous, "read": False, "asleep": False,
                        "reason": (messages[:160] or
                                   "smartctl could not open the device (a USB bridge or "
                                   "RAID controller it does not support)")}
                continue
            parsed = parse_smartctl(payload)
            if not parsed["attributes"] and not parsed["nvme"] and parsed["passed"] is None:
                self._smart[subject] = {
                    **previous, "read": False, "asleep": False,
                    "reason": messages[:160] or "the device returned no SMART data"}
                continue
            parsed.update({"read": True, "asleep": False, "stale_since": None,
                           "reason": None, "at": time.time(), "exit_status": code})
            self._smart[subject] = parsed
        self._smart_pass_ms = round((time.perf_counter() - started) * 1000, 1)

    # ------------------------------------------------------------------ links
    def _links(self, checks: dict[str, Any]) -> list[dict[str, Any]]:
        base = _sys("/sys/class/ata_link")
        try:
            names = sorted(os.listdir(base))
        except OSError:
            checks["links"] = {"available": False, "reason": "no ATA links "
                               "(/sys/class/ata_link is absent: NVMe, SAS or a guest)",
                               "negotiated": 0}
            return []
        ports = _ata_ports()
        out: list[dict[str, Any]] = []
        negotiated = 0
        for name in names:
            speed = linux.read_line(f"{base}/{name}/sata_spd")
            maximum = linux.read_line(f"{base}/{name}/sata_spd_max")
            port = _ata_port_of(os.path.realpath(f"{base}/{name}"))
            disk = ports.get(port) if port else None
            good = _gbps(speed), _gbps(maximum)
            if good[0] is not None and good[1] is not None:
                negotiated += 1
            out.append({
                "ata": name, "disk": disk,
                "speed": speed if good[0] is not None else None,
                "max": maximum if good[1] is not None else None,
                "downgraded": bool(disk and good[0] is not None and good[1] is not None
                                   and good[0] < good[1]),
                "note": None if good[0] is not None else
                        "not negotiated (a virtual controller, SAS, or no device)",
            })
        checks["links"] = {"available": True, "reason": None, "links": len(out),
                           "negotiated": negotiated,
                           "note": None if negotiated else
                           "these links do not report a negotiated speed: virtual SATA, "
                           "SAS or an empty port"}
        return out

    # ------------------------------------------------------------------- nics
    def _nics(self, network: dict | None, checks: dict[str, Any]) -> list[dict[str, Any]]:
        reported = {str(i.get("name")): i for i in ((network or {}).get("interfaces") or [])
                    if isinstance(i, dict)}
        out: list[dict[str, Any]] = []
        try:
            names = sorted(os.listdir(_sys("/sys/class/net")))
        except OSError:
            checks["nics"] = {"available": False, "reason": "/sys/class/net is not readable",
                              "physical": 0, "speed_known": 0}
            return []
        for name in names:
            if name == "lo":
                continue
            physical = os.path.exists(_sys(f"/sys/class/net/{name}/device"))
            if not physical:
                continue    # a bridge or veth has no wire to degrade
            live = reported.get(name) or {}
            speed = live.get("speed_mbps")
            if not isinstance(speed, int):
                raw = linux.read_int(_sys(f"/sys/class/net/{name}/speed"))
                speed = raw if isinstance(raw, int) and raw > 0 else None
            operstate = linux.read_line(_sys(f"/sys/class/net/{name}/operstate"))
            up = bool(live.get("up")) if "up" in live else operstate == "up"
            if isinstance(speed, int) and up:
                self._best_speed[name] = max(self._best_speed.get(name, 0), speed)
            out.append({
                "name": name, "physical": True, "up": up, "operstate": operstate,
                "driver": _driver_of(name),
                "speed_mbps": speed,
                "duplex": live.get("duplex") or linux.read_line(_sys(f"/sys/class/net/{name}/duplex")),
                "best_seen_mbps": self._best_speed.get(name) or None,
                "note": None if speed is not None else
                        "speed not reported by the driver (a virtual NIC, or the link is down)",
            })
        checks["nics"] = {"available": True, "reason": None, "physical": len(out),
                          "speed_known": sum(1 for n in out if n["speed_mbps"] is not None)}
        return out

    # ----------------------------------------------------------------- memory
    def _memory(self, checks: dict[str, Any]) -> dict[str, Any]:
        base = _sys("/sys/devices/system/edac/mc")
        try:
            names = sorted(n for n in os.listdir(base) if n.startswith("mc"))
        except OSError:
            names = []
        if not names:
            reason = ("no EDAC memory controller is registered: non-ECC memory, the "
                      "driver for this chipset is not loaded, or this is a guest")
            checks["memory"] = {"available": False, "reason": reason, "controllers": 0}
            return {"available": False, "reason": reason, "controllers": []}
        controllers: list[dict[str, Any]] = []
        for name in names:
            path = f"{base}/{name}"
            dimms = []
            try:
                entries = sorted(e for e in os.listdir(path)
                                 if e.startswith(("dimm", "rank", "csrow")))
            except OSError:
                entries = []
            for entry in entries:
                dimms.append({
                    "name": entry,
                    "label": linux.read_line(f"{path}/{entry}/dimm_label"),
                    "size_mb": linux.read_int(f"{path}/{entry}/size"),
                    "mem_type": linux.read_line(f"{path}/{entry}/dimm_mem_type"),
                    "ce_count": linux.read_int(f"{path}/{entry}/dimm_ce_count"),
                    "ue_count": linux.read_int(f"{path}/{entry}/dimm_ue_count"),
                })
            controllers.append({
                "name": name,
                "mem_type": linux.read_line(f"{path}/mc_name"),
                "size_mb": linux.read_int(f"{path}/size_mb"),
                "ce_count": linux.read_int(f"{path}/ce_count"),
                "ue_count": linux.read_int(f"{path}/ue_count"),
                "ce_noinfo_count": linux.read_int(f"{path}/ce_noinfo_count"),
                "dimms": dimms,
            })
        checks["memory"] = {"available": True, "reason": None,
                            "controllers": len(controllers),
                            "dimms": sum(len(c["dimms"]) for c in controllers)}
        return {"available": True, "reason": None, "controllers": controllers}

    # -------------------------------------------------------------------- pci
    def _pci(self, checks: dict[str, Any]) -> list[dict[str, Any]]:
        base = _sys("/sys/bus/pci/devices")
        out: list[dict[str, Any]] = []
        try:
            names = sorted(os.listdir(base))
        except OSError:
            checks["pci"] = {"available": False, "reason": "/sys/bus/pci/devices is "
                             "not readable", "devices": 0}
            return out
        for bdf in names:
            path = f"{base}/{bdf}"
            if not os.path.exists(f"{path}/aer_dev_correctable"):
                continue
            correctable = parse_aer(linux.read_text(f"{path}/aer_dev_correctable"))
            nonfatal = parse_aer(linux.read_text(f"{path}/aer_dev_nonfatal"))
            fatal = parse_aer(linux.read_text(f"{path}/aer_dev_fatal"))
            out.append({
                "bdf": bdf,
                "label": _pci_label(path),
                "driver": _driver_of_path(path),
                "correctable": correctable.get("TOTAL_ERR_COR"),
                "nonfatal": nonfatal.get("TOTAL_ERR_NONFATAL"),
                "fatal": fatal.get("TOTAL_ERR_FATAL"),
            })
        checks["pci"] = {
            "available": bool(out), "devices": len(out),
            "reason": None if out else "no PCIe device exposes AER counters "
                      "(no AER support in this firmware, or a guest)"}
        return out

    # ------------------------------------------------------------------ power
    def _power(self, checks: dict[str, Any]) -> list[dict[str, Any]]:
        base = _sys("/sys/class/power_supply")
        try:
            names = sorted(os.listdir(base))
        except OSError:
            names = []
        out: list[dict[str, Any]] = []
        for name in names:
            path = f"{base}/{name}"
            kind = linux.read_line(f"{path}/type")
            if kind == "Mains":
                continue
            full = linux.read_int(f"{path}/energy_full") or linux.read_int(f"{path}/charge_full")
            design = (linux.read_int(f"{path}/energy_full_design")
                      or linux.read_int(f"{path}/charge_full_design"))
            health = round(full / design * 100.0, 1) if full and design else None
            out.append({
                "name": name, "type": kind,
                "manufacturer": linux.read_line(f"{path}/manufacturer"),
                "model": linux.read_line(f"{path}/model_name"),
                "health_pct": health,
                "cycle_count": linux.read_int(f"{path}/cycle_count"),
                "status": linux.read_line(f"{path}/status"),
                "capacity": linux.read_int(f"{path}/capacity"),
                "health": linux.read_line(f"{path}/health"),
            })
        checks["power"] = {
            "available": bool(out), "supplies": len(out),
            "reason": None if out else "no battery or UPS is exposed in "
                      "/sys/class/power_supply"}
        return out

    # ------------------------------------------------------------------ guest
    def _guest_check(self, virt: str | None, devices: list[dict[str, Any]]) -> dict[str, Any]:
        virtual = [d["name"] for d in devices if d.get("virtual")]
        if not virt and not virtual:
            return {"virtualization": None, "note": None}
        note = None
        if virt:
            note = (f"this machine runs under {virt}: the disks it sees are the "
                    "hypervisor's files or volumes, EDAC and PCIe AER describe hardware "
                    "it has no access to, and the SATA links do not negotiate. Wear on "
                    "the real hardware is only visible to an agent running on the "
                    "hypervisor itself.")
        elif virtual:
            note = (f"{', '.join(virtual)} report a virtual model: their counters "
                    "describe no physical medium and are not judged.")
        return {"virtualization": virt, "virtual_disks": virtual, "note": note}

    # ----------------------------------------------------------------- memory
    def _remember(self, devices: list[dict[str, Any]], memory: dict[str, Any],
                  pci: list[dict[str, Any]], now: float) -> None:
        """Fold this pass into the ring. Disks are only pushed when SMART was
        actually read: a standby drive must not overwrite the values that
        "rose since the last read" is measured against."""
        subjects = set()
        for device in devices:
            if not (device["smart"] or {}).get("read") or device.get("virtual"):
                continue
            subject = device["subject"]
            subjects.add(subject)
            previous = self._ring.previous(subject)
            if (previous or {}).get("counters") != device["counters"]:
                self._ring.push(subject, device["counters"], now)
            elif previous is None:
                self._ring.push(subject, device["counters"], now)
        ecc: dict[str, int] = {}
        for controller in memory.get("controllers") or []:
            mc = str(controller.get("name"))
            for key, value in (("ce", controller.get("ce_count")),
                               ("ue", controller.get("ue_count"))):
                if isinstance(value, int):
                    ecc[f"{mc}:{key}"] = value
            for dimm in controller.get("dimms") or []:
                if isinstance(dimm.get("ce_count"), int):
                    ecc[f"{mc}:{dimm.get('name')}:ce"] = int(dimm["ce_count"])
        if ecc:
            self._ring.push("memory", ecc, now)
            subjects.add("memory")
        aer = {f"{d['bdf']}:cor": d["correctable"] for d in pci
               if isinstance(d.get("correctable"), int)}
        if aer:
            self._ring.push("pci", aer, now)
            subjects.add("pci")
        subjects |= {d["subject"] for d in devices}
        self._ring.forget_all_but(subjects)
        self._ring.save()

    def _elapsed(self, subject: str, now: float) -> float:
        previous = self._ring.previous(subject)
        return max(0.0, now - float((previous or {}).get("ts") or now))

    def close(self) -> None:
        self._ring.save()


# ---------------------------------------------------------------- identities
def _from_media(media: dict[str, Any]) -> dict[str, Any]:
    """One `volumes.media[]` row (lsblk) as the Prognosis's identity. Identity
    stays where it was collected; only health moved here."""
    rotational = media.get("media_type")
    return {
        "name": str(media.get("name") or ""),
        "model": media.get("model"),
        "serial": media.get("serial"),
        "transport": media.get("interface"),
        "rotational": (True if rotational and "rotational" in str(rotational)
                       else False if rotational else None),
        "size": media.get("size"),
        "firmware": media.get("firmware"),
    }


def _sysfs_disks() -> list[dict[str, Any]]:
    """The whole disks, straight from sysfs -- the fallback for the first
    events tick, before a slow tick has produced the volume list."""
    out: list[dict[str, Any]] = []
    try:
        names = sorted(os.listdir(_sys("/sys/block")))
    except OSError:
        return out
    for name in names:
        if name.startswith(("loop", "ram", "zram", "dm-", "md", "sr")):
            continue
        device = _sys(f"/sys/block/{name}/device")
        if not os.path.exists(device):
            continue
        sectors = linux.read_int(_sys(f"/sys/block/{name}/size"))
        model = linux.read_line(f"{device}/model") or linux.read_line(f"{device}/name")
        rotational = linux.read_int(_sys(f"/sys/block/{name}/queue/rotational"))
        out.append({
            "name": name,
            "model": (model or "").strip() or None,
            "serial": (linux.read_line(f"{device}/serial") or "").strip() or None,
            "transport": "nvme" if name.startswith("nvme") else None,
            "rotational": None if rotational is None else bool(rotational),
            "size": sectors * 512 if isinstance(sectors, int) else None,
            "firmware": (linux.read_line(f"{device}/rev")
                         or linux.read_line(f"{device}/firmware_rev") or "").strip() or None,
        })
    return out


def _subject_of(identity: dict[str, Any]) -> str:
    """A disk's identity across reboots and controller renames: the serial if
    it has one, otherwise model and kernel name. A replaced disk is therefore
    a *new* subject and the old one's items simply stop -- which is the honest
    outcome, since nothing was fixed, something was swapped."""
    serial = str(identity.get("serial") or "").strip()
    if serial:
        return serial
    model = str(identity.get("model") or "").strip()
    return f"{model}:{identity.get('name')}" if model else str(identity.get("name"))


def _is_virtual(identity: dict[str, Any], virt: str | None) -> bool:
    model = str(identity.get("model") or "").strip().lower()
    if not model:
        # No model at all on a guest is the hypervisor's disk too; on metal a
        # nameless disk is unusual but real, so only the guest case counts.
        return bool(virt)
    return any(marker in model for marker in VIRTUAL_MODELS)


def _scan_types() -> dict[str, str]:
    """`smartctl --scan-open` device -> the `-d` type it wants. This is how a
    USB bridge smartctl *can* speak to is addressed; one it cannot simply does
    not appear, and the disk is reported unread with that reason."""
    payload = linux.run_json(["smartctl", "--scan-open", "-j"], timeout=10)
    out: dict[str, str] = {}
    for entry in (payload or {}).get("devices") or [] if isinstance(payload, dict) else []:
        if isinstance(entry, dict) and entry.get("name") and entry.get("type"):
            out[str(entry["name"])] = str(entry["type"])
    return out


def _ata_ports() -> dict[str, str]:
    """ata port number -> the block device on it, from each disk's own sysfs
    path (`.../ata3/host2/target.../block/sda`)."""
    out: dict[str, str] = {}
    try:
        names = os.listdir(_sys("/sys/block"))
    except OSError:
        return out
    for name in names:
        try:
            real = os.path.realpath(_sys(f"/sys/block/{name}/device"))
        except OSError:
            continue
        port = _ata_port_of(real)
        if port:
            out[port] = name
    return out


def _ata_port_of(path: str) -> str | None:
    match = _ATA_PORT.search(path + "/")
    return match.group(1) if match else None


def _gbps(text: str | None) -> float | None:
    """'6.0 Gbps' -> 6.0; '<unknown>' and an empty file -> None."""
    if not text or "unknown" in text.lower():
        return None
    match = re.search(r"([\d.]+)\s*Gbps", text, re.I)
    return float(match.group(1)) if match else None


def _driver_of(interface: str) -> str | None:
    return _driver_of_path(_sys(f"/sys/class/net/{interface}/device"))


def _driver_of_path(path: str) -> str | None:
    try:
        return os.path.basename(os.readlink(f"{path}/driver"))
    except OSError:
        return None


# A small vendor map, the same shape as sysinfo's for GPUs: enough to say
# whose card is retrying without shipping the PCI id database.
PCI_VENDORS = {
    "8086": "Intel", "10de": "NVIDIA", "1002": "AMD", "1022": "AMD",
    "144d": "Samsung", "1c5c": "SK hynix", "15b7": "Western Digital",
    "1179": "Toshiba", "1344": "Micron", "1987": "Phison", "126f": "Silicon Motion",
    "1af4": "virtio", "1234": "QEMU", "15ad": "VMware", "1b36": "QEMU",
    "14e4": "Broadcom", "1425": "Chelsio", "15b3": "Mellanox", "1d6a": "Aquantia",
    "10ec": "Realtek", "1969": "Qualcomm Atheros", "9005": "Adaptec",
    "1000": "Broadcom/LSI", "1b4b": "Marvell", "197b": "JMicron", "1b21": "ASMedia",
}
# PCI class (the top byte) -> what it is, so an operator reads "the NVMe
# controller" rather than a hex code.
PCI_CLASSES = {
    "01": "storage controller", "02": "network controller", "03": "display controller",
    "04": "multimedia device", "06": "bridge", "0c": "serial bus controller",
    "08": "system peripheral", "0d": "wireless controller",
}


def _pci_label(path: str) -> str:
    vendor = (linux.read_line(f"{path}/vendor") or "").removeprefix("0x")
    device = (linux.read_line(f"{path}/device") or "").removeprefix("0x")
    klass = (linux.read_line(f"{path}/class") or "").removeprefix("0x")[:2]
    what = PCI_CLASSES.get(klass, "device")
    if klass == "01" and (linux.read_line(f"{path}/class") or "").removeprefix("0x")[2:4] == "08":
        what = "NVMe controller"
    who = PCI_VENDORS.get(vendor)
    return f"{who} {what}" if who else f"{what} ({vendor}:{device})"
