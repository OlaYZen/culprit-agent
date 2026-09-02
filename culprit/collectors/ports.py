"""The port map -- what is listening, and the one place to kill what holds a port.

Every other collector answers "what is this machine doing". This one answers a
question an operator asks constantly and no utilisation number can: *what is
listening on port N, and let me stop it.* It is `ss -tulnp` with the two chores
`ss` leaves you to do by hand -- resolve each socket to the service behind it,
then go find and signal that process -- folded into one row with a button.

Sockets come from psutil (which reads /proc/net/* and, for attribution, each
owner's /proc/<pid>/fd), exactly as `network.py` does, and the same permission
truth applies: a listener owned by another user shows with **no PID and is
counted, never hidden** -- attributing or killing it needs CAP_SYS_PTRACE or
root, and the payload says so. Process identity (name, cmdline, user) is read
straight from /proc for the handful of listening PIDs -- the cheap path
`processes.py` established -- and systemd unit attribution is threaded in from
the services collector's pid->unit map, so a row can name `nginx.service`, the
honest target of a `systemctl stop`.

**Killing a port is killing the process(es) bound to it**, so the action reuses
`processes.terminate` untouched: the critical-process guards (PID 1, kernel
threads, sshd/systemd/dbus/...) and the remote CommandBroker relay both apply
with no new code, and an agent kills a port with the same call the host does.

UDP has no LISTEN state, so a "listener" there is any bound UDP socket with no
peer -- that is what makes 53/udp (a resolver) show up beside 22/tcp.
"""

from __future__ import annotations

import logging
import os
import pwd
import socket

import psutil

from .. import linux
from . import processes as proc_mod

log = logging.getLogger("culprit.ports")


def _is_loopback(ip: str) -> bool:
    """A bind only reachable from the machine itself. Everything else -- a
    wildcard (0.0.0.0 / ::) or a concrete interface address -- is exposed."""
    if not ip:
        return False
    low = ip.lower()
    return low.startswith("127.") or low == "::1" or low.startswith("::ffff:127.")


class PortsCollector:
    """Slow-tick listening-port map with kill-ready process attribution."""

    def sample(self, service_map: dict[str, list] | None = None,
               unit_desc: dict[str, str] | None = None) -> dict[str, object]:
        service_map = service_map or {}
        unit_desc = unit_desc or {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            return {"available": False, "reason": f"access denied: {exc}",
                    "ports": [], "totals": {}, "unattributed_note": None}
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": str(exc),
                    "ports": [], "totals": {}, "unattributed_note": None}

        # (port, proto, ip, family, pid) for every listening socket, plus a
        # count of established inbound connections per local (port, proto) so a
        # row can show how busy a service is right now.
        listeners: list[tuple[int, str, str, str, int | None]] = []
        inbound: dict[tuple[int, str], int] = {}
        for conn in conns:
            laddr = conn.laddr
            port = getattr(laddr, "port", 0) if laddr else 0
            if not port:
                continue
            family = "IPv6" if conn.family.name == "AF_INET6" else "IPv4"
            proto = "udp" if conn.type == socket.SOCK_DGRAM else "tcp"
            ip = getattr(laddr, "ip", "") or ""
            if conn.status == psutil.CONN_LISTEN:
                listeners.append((port, proto, ip, family, conn.pid))
            elif proto == "udp" and not conn.raddr:
                # A bound UDP socket with no peer is a service listening.
                listeners.append((port, proto, ip, family, conn.pid))
            elif conn.status == psutil.CONN_ESTABLISHED:
                key = (port, proto)
                inbound[key] = inbound.get(key, 0) + 1

        by_port: dict[int, dict[str, object]] = {}
        for port, proto, ip, family, pid in listeners:
            slot = by_port.setdefault(port, {
                "protocols": set(), "addresses": set(), "families": set(),
                "pids": set(), "unattributed": 0, "public": False,
            })
            slot["protocols"].add(proto)  # type: ignore[union-attr]
            if ip:
                slot["addresses"].add(ip)  # type: ignore[union-attr]
            slot["families"].add(family)  # type: ignore[union-attr]
            if not _is_loopback(ip):
                slot["public"] = True
            if pid:
                slot["pids"].add(pid)  # type: ignore[union-attr]
            else:
                slot["unattributed"] = int(slot["unattributed"]) + 1  # type: ignore[arg-type]

        # Identity is resolved once per PID even when a process holds many ports.
        identities: dict[int, dict[str, object]] = {}

        def identify(pid: int) -> dict[str, object]:
            if pid not in identities:
                identities[pid] = _identity(pid, service_map, unit_desc)
            return identities[pid]

        ports_out: list[dict[str, object]] = []
        public_count = tcp_ports = udp_ports = total_conns = total_unattr = 0
        for port in sorted(by_port):
            slot = by_port[port]
            protocols = sorted(slot["protocols"])  # type: ignore[type-var]
            conns_here = sum(inbound.get((port, p), 0) for p in protocols)
            processes = [identify(pid)
                         for pid in sorted(slot["pids"])]  # type: ignore[union-attr]
            scope = "public" if slot["public"] else "local"
            unattr = int(slot["unattributed"])

            public_count += scope == "public"
            tcp_ports += "tcp" in protocols
            udp_ports += "udp" in protocols
            total_conns += conns_here
            total_unattr += unattr

            ports_out.append({
                "port": port,
                "protocols": protocols,
                "scope": scope,
                "addresses": sorted(slot["addresses"]),  # type: ignore[type-var]
                "families": sorted(slot["families"]),  # type: ignore[type-var]
                "connections": conns_here,
                "unattributed": unattr,
                "processes": processes,
                # A row is actionable only if at least one owner can be signalled
                # from here; the UI uses this to enable the Kill button.
                "killable": any(p["can_kill"] for p in processes),
            })

        return {
            "available": True,
            "reason": None,
            "ports": ports_out,
            "totals": {
                "ports": len(ports_out),
                "public": public_count,
                "local": len(ports_out) - public_count,
                "tcp": tcp_ports,
                "udp": udp_ports,
                "connections": total_conns,
                "unattributed": total_unattr,
            },
            "unattributed_note": (
                f"{total_unattr} listening socket(s) belong to other users' "
                "processes; naming and killing them needs CAP_SYS_PTRACE or root"
                if total_unattr else None),
        }


# systemd unit suffixes worth naming on a port. Ordered by preference: a
# process's own .service/.socket is the useful attribution; .scope/.slice are
# grouping.
_UNIT_SUFFIXES = (".service", ".socket", ".scope", ".mount", ".target")


def _unit_from_cgroup(pid: int) -> str | None:
    """The systemd unit owning a process, read from its own /proc/<pid>/cgroup.

    This is the reliable source and needs no systemctl / D-Bus, so it works
    where the services collector cannot reach the bus (notably an agent in a
    container). cgroup v2 is a single "0::<path>" line; the container view can
    prefix it with '..' (e.g. "0::/../ssh.service"), which we skip. We return the
    deepest real unit, preferring a .service/.socket over a wrapping .scope.
    """
    text = linux.read_text(f"/proc/{pid}/cgroup")
    if not text:
        return None
    for line in text.splitlines():
        parts = line.split(":", 2)
        path = parts[2] if len(parts) == 3 else line
        segments = [s for s in path.strip("/").split("/") if s and s != ".."]
        for suffix in _UNIT_SUFFIXES:
            for seg in reversed(segments):
                if seg.endswith(suffix):
                    return seg
    return None


def _identity(pid: int, service_map: dict[str, list],
              unit_desc: dict[str, str]) -> dict[str, object]:
    """Name, command line, owner and hosting unit for one listening PID.

    Read straight from /proc (comm/cmdline/status) rather than through psutil --
    the same reason `processes.py` does. `can_act` supplies the exact same
    kill-eligibility verdict, and reason, that the terminate endpoint will
    enforce, so the button's enabled state never disagrees with what pressing
    it would do.
    """
    name = linux.read_line(f"/proc/{pid}/comm") or f"pid-{pid}"
    try:
        exe: str | None = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = None
    raw = linux.read_text(f"/proc/{pid}/cmdline")
    cmdline = raw.replace("\x00", " ").strip() if raw else None

    username: str | None = None
    uid_row = linux.parse_kv_file(f"/proc/{pid}/status").get("Uid", "").split()
    if uid_row:
        try:
            username = pwd.getpwuid(int(uid_row[0])).pw_name
        except (KeyError, ValueError):
            username = uid_row[0] or None

    # Prefer the unit from the process's own cgroup (reliable, no systemctl);
    # describe it via the services map when available, else show the unit name.
    # Fall back to the MainPID map for a process whose cgroup names no unit.
    unit = _unit_from_cgroup(pid)
    if unit:
        units = [unit_desc.get(unit) or unit]
    else:
        units = (service_map.get(str(pid)) or [])[:4]

    can_kill, kill_reason = proc_mod.can_act(pid, "end")
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": cmdline or None,
        "username": username,
        "units": units,
        "can_kill": can_kill,
        "kill_reason": kill_reason,
        "is_self": pid == os.getpid(),
    }
