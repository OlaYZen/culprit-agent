# culprit-agent

A **self-contained, deployable** monitoring agent for
[culprit](https://github.com/OlaYZen/culprit). Clone (or copy) this repo onto
any Linux server you want to watch; it carries its own copy of the runnable
`culprit` package, so at runtime it needs nothing from the host repo. It samples
the machine and pushes reports to the culprit host; it runs no dashboard and
**opens no listening ports**.

## Deploy

```bash
git clone https://github.com/OlaYZen/culprit-agent.git
cd culprit-agent
./agent.sh <host-url> <token>
#   e.g.  ./agent.sh http://192.168.1.5:8787 web-01.<secret>
#   get <token> from the host dashboard: Nodes > "Generate token"
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
(GitHub Actions builds `ghcr.io/olayzen/culprit-agent`). The agent monitors the
**host** it runs on, so it runs **privileged** in the host's PID and network
namespaces.

Set your host URL and token, then run this. It is the whole installer:

```bash
docker run -d --name culprit-agent --restart unless-stopped --pull always \
  --privileged --pid host --network host \
  -e CULPRIT_HOST=http://192.168.1.1:8787 \
  -e CULPRIT_TOKEN=web-01.your-secret-here \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/os-release:/etc/os-release:ro \
  -v /var/lib/ubuntu-advantage:/var/lib/ubuntu-advantage:ro \
  -v /var/log/journal:/var/log/journal:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  -v /run/systemd:/run/systemd:ro \
  -v /run/dbus:/run/dbus:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/olayzen/culprit-agent:latest
```

Only the two `CULPRIT_HOST` / `CULPRIT_TOKEN` values are required. Add any of
the optional `-e` vars below if you need them:

- `CULPRIT_HOST` **(required):** your host dashboard URL, e.g. `http://192.168.1.1:8787`
- `CULPRIT_TOKEN` **(required):** get it from the dashboard (Nodes > *Generate token*), or `CULPRIT_TOKEN_FILE` to read it from a mounted file / Docker secret
- `CULPRIT_INTERVAL=1`: fast-tier sampling seconds (default `1`)
- `CULPRIT_INSECURE=1`: accept a self-signed host cert (only for an `https://` host with an untrusted cert; irrelevant for plain HTTP)
- `CULPRIT_LOG_LEVEL=info`: set `debug` when troubleshooting

To update later, re-run the exact same command: `--pull always` fetches the
latest image and Docker recreates the container.

### NVIDIA GPU

To surface an NVIDIA GPU (utilisation, VRAM, per-process memory in the Graphics
panel), add `--gpus all` and expose the driver's libraries. This needs the
[NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
installed on the host:

```bash
docker run -d --name culprit-agent --restart unless-stopped --pull always \
  --privileged --pid host --network host \
  --gpus all -e NVIDIA_DRIVER_CAPABILITIES=all \
  -e CULPRIT_HOST=http://192.168.1.1:8787 \
  -e CULPRIT_TOKEN=web-01.your-secret-here \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/os-release:/etc/os-release:ro \
  -v /var/lib/ubuntu-advantage:/var/lib/ubuntu-advantage:ro \
  -v /var/log/journal:/var/log/journal:ro \
  -v /etc/machine-id:/etc/machine-id:ro \
  -v /run/systemd:/run/systemd:ro \
  -v /run/dbus:/run/dbus:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/olayzen/culprit-agent:latest
```

The image already bundles `nvidia-ml-py`, so `--gpus all` is the only extra you
need. Without it the Graphics panel reads "unavailable" and nothing else is
affected. **Intel / AMD GPUs don't use `--gpus`**; they surface through
`/dev/dri`, which `--privileged` already exposes (Intel shows only while a
process is actively using the GPU, e.g. a live transcode).

**Why the flags and mounts:**

| Flag / mount | Unlocks |
|---|---|
| `--privileged` | full host access: all capabilities (`SYS_PTRACE` and the rest) and no AppArmor/seccomp confinement, so listening **ports** attribute to their process and are killable. Without it the Ports view shows every port as "another user's process" |
| `--pid host` | sees the host's processes (and their per-process CPU/IO/FDs). **Mandatory:** even privileged, the agent sees nothing without it |
| `--network host` | reaches the host node, and sees the host's interfaces and sockets |
| `-v /etc/passwd + /etc/group` | resolves host UIDs to real login names (else system users read as `uid 101`) |
| `-v /var/log/journal + /etc/machine-id` | the **journal** (Events view): `journalctl` reads it from files, no daemon needed. Persistent journal assumed; on a volatile-only host mount `/run/log/journal` instead |
| `-v /run/systemd + /run/dbus` | the **Services (systemd units)** view, the unit **descriptions** on Ports, and login **Sessions**: `systemctl`/`loginctl` reach the host's systemd + D-Bus over these sockets |
| `-v /etc/os-release` | the host's OS identity (else the image's Debian base); also gates Ubuntu Pro |
| `-v /var/lib/ubuntu-advantage` | the Ubuntu Pro status row |

With all of the above, everything works: CPU, memory, PSI, disk, network,
**ports** (with the systemd unit behind each), processes, journal events,
sessions, systemd units, OS identity and Ubuntu Pro.

Two honest caveats. The **Ports** view names each listener's systemd unit from
the process's own cgroup, so the unit **name** shows even without the
`/run/systemd` mount (the mount adds the friendlier **description**). And
systemd-over-a-socket from inside a container can be **intermittent**: a
Services tick may occasionally read "unavailable", and the **Services** view
then falls back to listing the running units read from each process's cgroup
(no per-unit CPU/memory, no inactive units) rather than showing nothing.
Some managed platforms (e.g. TrueNAS SCALE apps) don't let you run privileged
or set `--pid host` / these mounts; there the agent runs with whatever it is
given and degrades the rest (an unattributable port still shows its **owner**
from `/proc/net`, just not a kill button). For the fullest picture, run it with
the command above, or natively (`agent.sh`) as root.

To build the image yourself: `docker build -t culprit-agent .`

## What's inside

```
agent.sh                      bootstrap venv + save config + run (python -m culprit.agent)
requirements-agent.txt        psutil, the only runtime dependency
culprit-agent.service         systemd USER unit (unprivileged)
culprit-agent.system.service  systemd SYSTEM unit, runs as root for full attribution
Dockerfile                    builds the ghcr.io/olayzen/culprit-agent image
docker/entrypoint.sh          maps the CULPRIT_* env vars onto the agent CLI
sync-package.sh               maintainer tool: refresh culprit/ from the repo
culprit/                      a copy of the runnable package (collectors, sampler,
                              db, state, config, linux, util, agent)
```

## Keeping the package copy in sync (maintainers only)

`culprit/` here is a **duplicate** of the host repo's top-level `culprit/`
package, minus the host-only modules (`main.py`, `auth.py`, `nodes.py`,
`__main__.py`) and plus the agent-only `agent.py`. This is the cost of a
one-folder, self-contained bundle: after changing any shared code (a collector,
the sampler, `db`/`state`/`config`/`linux`/`util`) in the host repo, refresh the
copy here. `sync-package.sh` pulls from a sibling `culprit/` checkout (i.e. the
[culprit](https://github.com/OlaYZen/culprit) repo cloned next to this one):

```bash
./sync-package.sh          # reads ../culprit, preserves agent.py, skips host-only files
```

## Security

Found a vulnerability? Please report it privately, never in a public issue. See
the security policy in the main repository:
<https://github.com/OlaYZen/culprit/security/policy>.
