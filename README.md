# culprit-agent

A **self-contained, deployable** monitoring agent for
[culprit](https://github.com/olayzen/culprit). Clone (or copy) this repo onto
any Linux server you want to watch — it carries its own copy of the runnable
`culprit` package, so at runtime it needs nothing from the host repo. It samples
the machine and pushes reports to the culprit host; it runs no dashboard and
**opens no listening ports**.

## Deploy

```bash
git clone https://github.com/olayzen/culprit-agent.git
cd culprit-agent
./agent.sh <host-url> <token>
#   e.g.  ./agent.sh http://192.168.1.5:8787 web-01.<secret>
#   get <token> from the host dashboard → Nodes → "Generate token"
```

`agent.sh` creates a local `.venv` (psutil only), saves `agent.json`, and runs
the agent, which pushes reports to the host over HTTP(S) and **opens no
listening ports**. Run it under `sudo` for full port/process attribution.

Keep it running across reboots with the systemd *user* unit:

```bash
mkdir -p ~/.config/systemd/user
cp culprit-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now culprit-agent
loginctl enable-linger $USER
```

The unit assumes the bundle lives at `~/culprit-agent`; edit its two paths if
you put it elsewhere.

## Docker

A prebuilt image is published to GitHub Container Registry on every push
(GitHub Actions → `ghcr.io/olayzen/culprit-agent`). The agent monitors the
**host** it runs on, so it needs the host's PID and network namespaces.

Configuration lives in an env file — copy the template and set your host + token
(on Portainer / TrueNAS SCALE, set the same variables as the stack's env):

```bash
cp .env.example .env      # then edit CULPRIT_HOST and CULPRIT_TOKEN
docker compose up -d
```

Or run the image directly with the same file:

```bash
docker run -d --name culprit-agent --restart unless-stopped \
  --network host --pid host --cap-add SYS_PTRACE \
  --security-opt apparmor=unconfined \
  --env-file .env \
  -v /etc/os-release:/etc/os-release:ro \
  -v /var/lib/ubuntu-advantage:/var/lib/ubuntu-advantage:ro \
  -v /var/log/journal:/var/log/journal:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  -v /run/systemd:/run/systemd:ro \
  -v /run/dbus:/run/dbus:ro \
  ghcr.io/olayzen/culprit-agent:latest
```

**Configuration is by environment variable** (the entrypoint turns them into the
agent's CLI): `CULPRIT_HOST` and `CULPRIT_TOKEN` are required; `CULPRIT_INTERVAL`,
`CULPRIT_INSECURE=1` (accept a self-signed host cert) and `CULPRIT_LOG_LEVEL` are
optional. The token may also be supplied via `CULPRIT_TOKEN_FILE` (a Docker
secret / mounted file).

**Why the flags and mounts:**

| Flag / mount | Unlocks |
|---|---|
| `--network host` | reaches the host node, and sees the host's interfaces and sockets |
| `--pid host` | sees the host's processes (and their per-process CPU/IO/FDs) |
| `--cap-add SYS_PTRACE` | reads other users' `/proc/<pid>/io`, fd counts, open files |
| `-v /etc/passwd + /etc/group` | *optional, off by default* — resolves host UIDs to real login names (else system users read as `uid 101`). Cosmetic only. **Portainer blocks stacks that mount `/etc/passwd` (a 403 on deploy)**, so add these two only when deploying from the CLI: `-v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro` |
| `--security-opt apparmor=unconfined` | attributes listening **ports** to their process — the default AppArmor profile blocks the `/proc/<pid>/fd` scan, so without it the Ports view shows every port as "another user's process". A no-op on hosts without AppArmor |
| `-v /var/log/journal + /etc/machine-id` | the **journal** (Events view) — `journalctl` reads it from files, no daemon needed. Persistent journal assumed; on a volatile-only host mount `/run/log/journal` instead |
| `-v /run/systemd + /run/dbus` | the **Services (systemd units)** view, the unit **descriptions** on Ports, and login **Sessions** — `systemctl`/`loginctl` reach the host's systemd + D-Bus over these sockets |
| `-v /etc/os-release` | the host's OS identity (else the image's Debian base) — also gates Ubuntu Pro |
| `-v /var/lib/ubuntu-advantage` | the Ubuntu Pro status row |

With all of the above, everything works: CPU, memory, PSI, disk, network,
**ports** (with the systemd unit behind each), processes, journal events,
sessions, systemd units, OS identity and Ubuntu Pro.

Two honest caveats. The **Ports** view names each listener's systemd unit from
the process's own cgroup, so the unit **name** shows even without the
`/run/systemd` mount (the mount adds the friendlier **description**). And
systemd-over-a-socket from inside a container can be **intermittent** — a
Services tick may occasionally read "unavailable", and the **Services** view
then falls back to listing the running units read from each process's cgroup
(no per-unit CPU/memory, no inactive units) rather than showing nothing.
Likewise a listening **port** the agent can't map to a PID (no `SYS_PTRACE`, or
a locked-down host) is still named by its **owner** from `/proc/net` — `root`,
or `uid 101` for a host system user (a real name like `systemd-resolve` with the
optional `/etc/passwd` mount above) — just not killable from the dashboard. Some managed
platforms (e.g. TrueNAS SCALE apps) don't let you set `--pid host` /
`--security-opt` / these mounts — there the agent runs with whatever it's given
and degrades the rest. For the fullest picture, run the agent natively
(`agent.sh`).

To build the image yourself: `docker build -t culprit-agent .`

## What's inside

```
agent.sh                 bootstrap venv + save config + run  (python -m culprit.agent)
requirements-agent.txt   psutil — the only runtime dependency
culprit-agent.service    systemd user unit
sync-package.sh          maintainer tool: refresh culprit/ from the repo
culprit/                 a copy of the runnable package (collectors, sampler,
                         db, state, config, linux, util, agent)
```

## Keeping the package copy in sync (maintainers only)

`culprit/` here is a **duplicate** of the host repo's top-level `culprit/`
package, minus the host-only modules (`main.py`, `auth.py`, `nodes.py`,
`__main__.py`) and plus the agent-only `agent.py`. This is the cost of a
one-folder, self-contained bundle: after changing any shared code (a collector,
the sampler, `db`/`state`/`config`/`linux`/`util`) in the host repo, refresh the
copy here. `sync-package.sh` pulls from a sibling `culprit/` checkout (i.e. the
[culprit](https://github.com/olayzen/culprit) repo cloned next to this one):

```bash
./sync-package.sh          # reads ../culprit, preserves agent.py, skips host-only files
```
