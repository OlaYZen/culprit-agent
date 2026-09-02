"""Network throughput, interfaces, sockets and connectivity health.

Two collectors again: per-interface byte counters are cheap enough for the fast
tick, while interface configuration, the socket table and reachability probes
run on the slow tick.

Interface config comes from /sys/class/net plus `ip -json route` and
systemd-resolved (falling back to /etc/resolv.conf) -- no daemon dependency.
Sockets come from psutil (which reads /proc/net/*): measured at ~3ms for this
machine's table, so the netlink sock_diag upgrade the porting notes suggest
was not worth a hand-rolled netlink client here; PID attribution would still
be fd-scanning either way. Sockets owned by other users list with pid=null
and the payload says how many.

Reachability keeps the Windows build's hardest-won lesson verbatim: probe with
TCP (not ICMP), try several ports, run them concurrently, and report a silent
host as **"filtered", not "down"** -- managed gateways routinely drop
everything they are not obliged to answer.
"""

from __future__ import annotations

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

from .. import linux
from ..util import rate

log = logging.getLogger("culprit.network")

# Interface name prefixes -> kind. Predictable-naming prefixes (en*, wl*) plus
# the classic ones; VPN and container plumbing by the names their drivers use.
_KIND_PREFIXES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("lo",), "loopback"),
    (("wg", "tun", "tap", "ppp", "tailscale", "zt", "nordlynx", "proton"), "vpn"),
    (("docker", "veth", "br-", "virbr", "lxc", "lxd", "cni", "flannel",
      "kube", "vnet"), "virtual"),
    (("wl",), "wifi"),
    (("en", "eth", "em", "eno", "ens", "enp"), "ethernet"),
    (("ww",), "cellular"),
    (("bond", "team"), "bond"),
)


def _classify(name: str) -> str:
    lowered = name.lower()
    for prefixes, kind in _KIND_PREFIXES:
        if lowered.startswith(prefixes):
            return kind
    # /sys uevent DEVTYPE catches renamed wifi/bridge interfaces.
    devtype = linux.parse_kv_file(f"/sys/class/net/{name}/uevent", sep="=").get(
        "DEVTYPE")
    if devtype == "wlan":
        return "wifi"
    if devtype in ("bridge", "vlan"):
        return "virtual"
    if devtype == "wwan":
        return "cellular"
    return "other"


class NetworkRateCollector:
    """Fast-tick per-interface throughput."""

    # Link speed and MTU change only on reconfiguration; net_if_stats() is the
    # expensive half of this collector, so it refreshes on a slow TTL.
    _STATS_TTL = 10.0

    def __init__(self) -> None:
        self._prev: dict[str, object] = {}
        self._prev_at = time.monotonic()
        self._stats: dict[str, object] = {}
        self._stats_at = 0.0
        try:
            self._prev = psutil.net_io_counters(pernic=True)
        except Exception:  # noqa: BLE001
            self._prev = {}

    def sample(self) -> dict[str, object]:
        moment = time.monotonic()
        elapsed = moment - self._prev_at
        try:
            current = psutil.net_io_counters(pernic=True)
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": str(exc), "interfaces": []}

        if moment - self._stats_at > self._STATS_TTL:
            try:
                self._stats = psutil.net_if_stats()
            except Exception:  # noqa: BLE001
                self._stats = {}
            self._stats_at = moment
        stats = self._stats

        interfaces = []
        total_sent = total_recv = 0.0
        for name, counters in current.items():
            kind = _classify(name)
            if kind == "loopback":
                continue
            previous = self._prev.get(name)
            sent_rate = rate(counters.bytes_sent,
                             getattr(previous, "bytes_sent", None), elapsed)
            recv_rate = rate(counters.bytes_recv,
                             getattr(previous, "bytes_recv", None), elapsed)
            stat = stats.get(name)
            is_up = bool(getattr(stat, "isup", False))
            # A down interface with zero traffic is clutter; one that was just
            # carrying traffic is a symptom, so recently active ones stay.
            if not is_up and sent_rate == 0 and recv_rate == 0 and counters.bytes_recv == 0:
                continue
            total_sent += sent_rate
            total_recv += recv_rate
            speed = getattr(stat, "speed", 0)
            interfaces.append({
                "name": name,
                "up": is_up,
                "operstate": linux.read_line(f"/sys/class/net/{name}/operstate"),
                "speed_mbps": speed if speed and speed > 0 else None,
                "mtu": getattr(stat, "mtu", None),
                "duplex": _duplex(getattr(stat, "duplex", 0)),
                "sent_bytes_sec": round(sent_rate),
                "recv_bytes_sec": round(recv_rate),
                "sent_total": counters.bytes_sent,
                "recv_total": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errors": counters.errin + counters.errout,
                "drops": counters.dropin + counters.dropout,
                "kind": kind,
            })

        interfaces.sort(key=lambda i: -(i["sent_bytes_sec"] + i["recv_bytes_sec"]))
        self._prev = current
        self._prev_at = moment

        return {
            "available": True,
            "reason": None,
            "interfaces": interfaces,
            "total": {
                "sent_bytes_sec": round(total_sent),
                "recv_bytes_sec": round(total_recv),
            },
        }


class NetworkDetailCollector:
    """Slow-tick interface config, socket table and connectivity probes."""

    def __init__(self) -> None:
        self._config: list[dict[str, object]] | None = None
        self._config_at = 0.0
        self._probe_cache: dict[str, object] = {}
        self._probe_at = 0.0

    def sample(self) -> dict[str, object]:
        now = time.monotonic()
        # Config changes on VPN connect/disconnect and DHCP renewal, so it
        # refreshes every 60s rather than caching for the process lifetime.
        if self._config is None or now - self._config_at > 60:
            self._config = _adapter_config()
            self._config_at = now

        sockets = _socket_table()

        if now - self._probe_at > 30:
            self._probe_cache = _connectivity(self._config or [])
            self._probe_at = now

        vpn_active = [
            adapter for adapter in (self._config or [])
            if adapter.get("kind") == "vpn" and adapter.get("ip_addresses")
        ]

        return {
            "adapters": self._config or [],
            "sockets": sockets,
            "connectivity": self._probe_cache,
            "vpn": {
                "active": bool(vpn_active),
                "adapters": [a["description"] for a in vpn_active],
            },
        }


def _adapter_config() -> list[dict[str, object]]:
    """IP / gateway / DNS per interface from psutil, ip(8) and resolved."""
    try:
        addrs = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001
        addrs = {}

    routes = linux.run_json(["ip", "-json", "route", "show", "default"],
                            timeout=5)
    gateway_by_dev: dict[str, list[str]] = {}
    for route in routes if isinstance(routes, list) else []:
        dev = route.get("dev")
        gw = route.get("gateway")
        if dev and gw:
            gateway_by_dev.setdefault(dev, []).append(str(gw))

    dns_servers, dns_domain, dns_source = _dns_config()

    out: list[dict[str, object]] = []
    for name, entries in addrs.items():
        kind = _classify(name)
        if kind == "loopback":
            continue
        ips, subnets, mac = [], [], None
        for entry in entries:
            family = getattr(entry.family, "name", str(entry.family))
            if family in ("AF_INET", "AF_INET6"):
                address = entry.address.split("%")[0]
                ips.append(address)
                if entry.netmask:
                    subnets.append(entry.netmask)
            elif family in ("AF_LINK", "AF_PACKET"):
                mac = entry.address
        gateways = gateway_by_dev.get(name, [])
        out.append({
            "description": name,
            "kind": kind,
            "ip_addresses": ips,
            "subnets": subnets,
            "gateways": gateways,
            # DNS on Linux is system-wide (resolved/resolv.conf), not
            # per-adapter; every row shows the same resolver set and its
            # provenance rather than pretending per-NIC DNS exists.
            "dns_servers": dns_servers,
            "dns_domain": dns_domain,
            "dns_source": dns_source,
            "dhcp": None,  # not knowable generically without the DHCP client's state
            "dhcp_server": None,
            "mac": mac,
            "operstate": linux.read_line(f"/sys/class/net/{name}/operstate"),
        })
    # Interfaces with a default route first -- they are the ones that matter.
    out.sort(key=lambda a: (0 if a["gateways"] else 1, str(a["description"])))
    return out


def _dns_config() -> tuple[list[str], str | None, str]:
    """Resolver list, preferring the real upstreams from systemd-resolved.

    /etc/resolv.conf frequently just says 127.0.0.53 (the resolved stub),
    which is true but useless for "is my DNS server reachable".
    """
    # `resolvectl dns` output is line-per-link: "Link 2 (enp6s18): 1.2.3.4".
    # (resolvectl 255 has no JSON mode for status; the text here is stable.)
    text = linux.run(["resolvectl", "dns"], timeout=5)
    if text:
        servers: list[str] = []
        for line in text.splitlines():
            _, found, tail = line.partition(":")
            if not found:
                continue
            for address in tail.split():
                if address not in servers:
                    servers.append(address)
        if servers:
            domain = None
            domain_text = linux.run(["resolvectl", "domain"], timeout=5) or ""
            for line in domain_text.splitlines():
                _, found, tail = line.partition(":")
                if found and tail.strip():
                    domain = tail.split()[0]
                    break
            return servers, domain, "systemd-resolved"
    servers = []
    domain = None
    for line in (linux.read_text("/etc/resolv.conf") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
        elif len(parts) >= 2 and parts[0] in ("domain", "search"):
            domain = domain or parts[1]
    return servers, domain, "/etc/resolv.conf"


def _socket_table() -> dict[str, object]:
    """Aggregate socket state plus listeners and peers per process.

    /proc/net/* is world-readable, but mapping a socket inode to its owning
    PID needs that process's /proc/<pid>/fd -- so other users' sockets appear
    with pid=null. Counted and reported, never hidden.
    """
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        return {"available": False, "reason": f"access denied: {exc}",
                "by_state": {}, "entries": []}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": str(exc), "by_state": {},
                "entries": []}

    by_state: dict[str, int] = {}
    by_pid: dict[int, dict[str, object]] = {}
    listeners: list[dict[str, object]] = []
    established: list[dict[str, object]] = []
    unattributed = 0

    for conn in connections:
        state = conn.status or "NONE"
        by_state[state] = by_state.get(state, 0) + 1
        pid = conn.pid or 0
        if not conn.pid:
            unattributed += 1
        slot = by_pid.setdefault(pid, {"pid": pid, "established": 0,
                                       "listening": 0, "other": 0})
        local = _addr(conn.laddr)
        remote = _addr(conn.raddr)
        if state == psutil.CONN_LISTEN:
            slot["listening"] = int(slot["listening"]) + 1  # type: ignore[arg-type]
            listeners.append({"pid": pid, "local": local,
                              "family": "IPv6" if conn.family.name == "AF_INET6"
                                        else "IPv4"})
        elif state == psutil.CONN_ESTABLISHED:
            slot["established"] = int(slot["established"]) + 1  # type: ignore[arg-type]
            established.append({"pid": pid, "local": local, "remote": remote})
        else:
            slot["other"] = int(slot["other"]) + 1  # type: ignore[arg-type]

    listeners.sort(key=lambda entry: str(entry["local"]))
    return {
        "available": True,
        "reason": None,
        "total": len(connections),
        "by_state": by_state,
        "by_pid": by_pid,
        "unattributed": unattributed,
        "unattributed_note": (
            f"{unattributed} socket(s) belong to other users' processes; "
            "attributing them needs CAP_SYS_PTRACE or root"
            if unattributed else None),
        "listeners": listeners[:200],
        "established": established[:400],
    }


def _connectivity(adapters: list[dict[str, object]]) -> dict[str, object]:
    """Probe the gateway, the DNS resolver, DNS itself and the open internet.

    Ported unchanged in design from the Windows build, where both lessons were
    learned the hard way:

    * **A gateway that ignores you is normal.** Several ports are tried, and
      if every one times out the verdict is *filtered* -- explicitly not the
      same as *down*.
    * **Probes must not be sequential.** Every (host, port) pair is its own
      concurrent job, so the worst case is one timeout, not the sum.
    """
    gateway = next((g for a in adapters for g in (a.get("gateways") or [])), None)
    dns = next(
        (d for a in adapters for d in (a.get("dns_servers") or [])
         if not str(d).startswith("127.")), None)

    targets: dict[str, tuple[str, tuple[int, ...]]] = {}
    if gateway:
        # Any answer proves the host is alive -- a RST counts just as well as
        # an accepted connection.
        targets["gateway"] = (str(gateway), (53, 80, 443, 22))
    if dns:
        targets["dns_server"] = (str(dns).split("#")[0], (53, 853))
    targets["internet"] = ("1.1.1.1", (443,))

    probes: list[tuple[str, str, int]] = [
        (label, host, port)
        for label, (host, ports) in targets.items()
        for port in ports
    ]

    results: dict[str, object] = {}
    per_target: dict[str, list[dict[str, object]]] = {label: [] for label in targets}

    with ThreadPoolExecutor(max_workers=min(12, len(probes) + 1),
                            thread_name_prefix="tpc-probe") as pool:
        futures = {
            pool.submit(_tcp_probe, host, port): (label, port)
            for label, host, port in probes
        }
        futures[pool.submit(_resolve_probe, "example.com")] = ("dns_resolution", 0)
        try:
            for future in as_completed(futures, timeout=5.0):
                label, port = futures[future]
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001
                    outcome = {"ok": False, "error": type(exc).__name__}
                if label == "dns_resolution":
                    results[label] = outcome
                else:
                    per_target[label].append(outcome)
        except TimeoutError:
            pass

    for label, attempts in per_target.items():
        host = targets[label][0]
        answered = next((a for a in attempts if a.get("ok")), None)
        if answered:
            results[label] = {**answered, "attempts": _slim_attempts(attempts)}
        else:
            ports = targets[label][1]
            results[label] = {
                "ok": False, "state": "filtered", "host": host,
                "attempts": _slim_attempts(attempts),
                "note": f"No response on {', '.join(str(p) for p in ports)}. The "
                        "host may be up but filtering traffic, which is normal "
                        "for a managed gateway. This is not proof it is down.",
            }

    results["checked_at"] = time.time()
    return results


def _slim_attempts(attempts: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        ({"port": a.get("port"), "ok": a.get("ok"), "state": a.get("state"),
          "latency_ms": a.get("latency_ms")} for a in attempts),
        key=lambda a: int(a["port"] or 0),
    )


def _tcp_probe(host: str, port: int, timeout: float = 0.7) -> dict[str, object]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"ok": True, "state": "open", "host": host, "port": port,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except ConnectionRefusedError:
        # Refused means something answered: the host is up, the port is closed.
        return {"ok": True, "state": "refused", "host": host, "port": port,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "state": "no answer", "host": host, "port": port,
                "error": type(exc).__name__}


def _resolve_probe(hostname: str) -> dict[str, object]:
    started = time.perf_counter()
    try:
        # A per-call timeout is not exposed by getaddrinfo, and mutating the
        # module-wide default from a worker thread would race with other
        # sockets, so this relies on the resolver's own timeout.
        socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        return {"ok": True, "host": hostname,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "host": hostname, "error": type(exc).__name__,
                "note": "DNS resolution failed. Package installs, sync clients "
                        "and most of the web will fail while this is broken."}


def _duplex(value: int) -> str | None:
    return {1: "half", 2: "full"}.get(int(value or 0))


def _addr(addr: object) -> str | None:
    if not addr:
        return None
    ip = getattr(addr, "ip", None)
    port = getattr(addr, "port", None)
    if ip is None:
        return None
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
