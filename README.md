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
