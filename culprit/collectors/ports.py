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
root, and the payload says so. What it *can* still show is *who* owns it: the
owner uid comes from world-readable /proc/net, so such a row is named by owner
even when the process itself is out of reach. Process identity (name, cmdline, user) is read
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


# /proc/net files carry the owner uid and inode of every socket, unlike psutil.
# TCP LISTEN is state 0A; a bound UDP socket (our "listener") is state 07.
_PROC_NET = (
    ("tcp", "IPv4", "/proc/net/tcp", "0A"),
    ("tcp", "IPv6", "/proc/net/tcp6", "0A"),
    ("udp", "IPv4", "/proc/net/udp", "07"),
    ("udp", "IPv6", "/proc/net/udp6", "07"),
)


def _proc_net_owners() -> dict[tuple[str, str, int], list[tuple[str, int]]]:
    """{(proto, family, port): [(inode, uid), ...]} for every listening socket.

    /proc/net/* is world-readable and names each socket's owner uid even when
    that owner's /proc/<pid>/fd is not -- so an unattributed port can still be
    named by *who* owns it. The inode lets us recover the PID via our own fd
    scan where psutil's attribution came up empty.
    """
    out: dict[tuple[str, str, int], list[tuple[str, int]]] = {}
    for proto, family, path, want_state in _PROC_NET:
        text = linux.read_text(path)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != want_state:
                continue
            _, _, hexport = fields[1].rpartition(":")
            try:
                port = int(hexport, 16)
                uid = int(fields[7])
            except ValueError:
                continue
            out.setdefault((proto, family, port), []).append((fields[9], uid))
    return out


def _inode_to_pid() -> dict[str, int]:
    """{socket-inode: pid} from our own /proc/<pid>/fd walk.

    psutil does the same scan, but this one runs in-process and skips nothing it
    can read, so it recovers PIDs psutil sometimes leaves unattributed in a
    container. Costs one readlink per open fd; only built when a port needs it.
    """
    out: dict[str, int] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{name}/fd")
        except OSError:
            continue  # gone, or not ours to read
        pid = int(name)
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{name}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                out[target[8:-1]] = pid
    return out


_uid_cache: dict[int, str] = {}


def _uid_name(uid: int) -> str:
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = f"uid {uid}"
    return _uid_cache[uid]


def _unattr_note(count: int, owners: list[str]) -> str | None:
    if not count:
        return None
    who = f" (owned by {', '.join(owners)})" if owners else ""
    return (f"{count} listening socket(s){who} could not be mapped to a "
            "process ID from here -- killing them needs CAP_SYS_PTRACE or root.")


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

        # Owner uid of every listening socket, straight from /proc/net (world-
        # readable). This is how a socket psutil can't attribute still gets a
        # name: even when /proc/<pid>/fd is unreadable, the uid is not.
        owners = _proc_net_owners()
        inode_pid: dict[str, int] | None = None  # our own fd scan, built lazily

        by_port: dict[int, dict[str, object]] = {}
        for port, proto, ip, family, pid in listeners:
            slot = by_port.setdefault(port, {
                "protocols": set(), "addresses": set(), "families": set(),
                "pids": set(), "unattributed": 0, "public": False,
                "owner_uids": set(),
            })
            slot["protocols"].add(proto)  # type: ignore[union-attr]
            if ip:
                slot["addresses"].add(ip)  # type: ignore[union-attr]
            slot["families"].add(family)  # type: ignore[union-attr]
            if not _is_loopback(ip):
                slot["public"] = True
            if not pid:
                # psutil left it unattributed. Try our own /proc/<pid>/fd scan
                # (more permissive than psutil's in some container sandboxes),
                # then fall back to the /proc/net uid so the row is at least
                # named by owner even when no PID is reachable.
                entries = owners.get((proto, family, port)) or []
                for inode, _uid in entries:
                    if inode_pid is None:
                        inode_pid = _inode_to_pid()
                    recovered = inode_pid.get(inode)
                    if recovered:
                        pid = recovered
                        break
                if not pid:
                    for _inode, uid in entries:
                        slot["owner_uids"].add(uid)  # type: ignore[union-attr]
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
        all_owners: set[str] = set()
        for port in sorted(by_port):
            slot = by_port[port]
            protocols = sorted(slot["protocols"])  # type: ignore[type-var]
            conns_here = sum(inbound.get((port, p), 0) for p in protocols)
            processes = [identify(pid)
                         for pid in sorted(slot["pids"])]  # type: ignore[union-attr]
            scope = "public" if slot["public"] else "local"
            unattr = int(slot["unattributed"])
            owner_names = sorted(_uid_name(uid)
                                 for uid in slot["owner_uids"])  # type: ignore[union-attr]
            all_owners.update(owner_names)

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
                # Owner login name(s) of any socket we couldn't map to a PID --
                # so the row names *who* owns it even when the process is out of
                # reach. Empty when everything on the port is attributed.
                "owners": owner_names,
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
            "unattributed_note": _unattr_note(total_unattr, sorted(all_owners)),
        }


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
    unit = linux.unit_from_cgroup(pid)
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
