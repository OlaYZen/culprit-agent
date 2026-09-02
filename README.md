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
  --env-file .env \
  -v /etc/os-release:/etc/os-release:ro \
  -v /var/lib/ubuntu-advantage:/var/lib/ubuntu-advantage:ro \
  ghcr.io/olayzen/culprit-agent:latest
```

**Configuration is by environment variable** (the entrypoint turns them into the
agent's CLI): `CULPRIT_HOST` and `CULPRIT_TOKEN` are required; `CULPRIT_INTERVAL`,
`CULPRIT_INSECURE=1` (accept a self-signed host cert) and `CULPRIT_LOG_LEVEL` are
optional. The token may also be supplied via `CULPRIT_TOKEN_FILE` (a Docker
secret / mounted file).

**Why the host flags:**

| Flag | Unlocks |
|---|---|
| `--network host` | reaches the host node, and sees the host's interfaces and sockets |
| `--pid host` | sees the host's processes (and their per-process CPU/IO/FDs) |
| `--cap-add SYS_PTRACE` | reads other users' `/proc/<pid>/io`, fd counts, open files |
| `-v /etc/os-release:…:ro` | the host's OS identity (else you see the image's Debian base) — this also gates Ubuntu Pro |
| `-v /var/lib/ubuntu-advantage:…:ro` | the Ubuntu Pro status row |

CPU, memory, PSI, disk, network, sockets and the process table work out of the
box (Docker already exposes the host's `/proc/stat`, `/proc/meminfo`, etc.).
**Userspace files come from the image, not the host** — mount `/etc/os-release`
(above) so the machine shows the host distro and its Ubuntu Pro status rather
than the container's Debian base.
Sources that need the host's **systemd** — systemd units and the journal (so the
Services and Events views) — read as *unavailable* in a container unless you
also mount `/run/systemd` and `/var/log/journal` and add `systemctl`/`journalctl`
to the image; everything degrades honestly rather than breaking. For full
coverage of those, run the agent natively (`agent.sh` above) instead.

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
