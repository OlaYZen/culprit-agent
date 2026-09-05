"""Self-update: git-pull this checkout and restart, on the host's say-so.

The agent never decides *when* to update -- that's the host's call (a manual
click or its daily schedule), delivered as one more CommandBroker action,
same channel as terminate/priority/throttle. This module only answers two
questions the host needs to make that call, and does the update itself:

    capability()          can this install even be updated this way, and why not
    fetch_remote_version() is there a newer version.json published on GitHub
    perform()              actually git-pull + reinstall + ask for a restart

Deliberately the "quickest dirtiest way": a real git clone with a working
`origin` remote is the whole mechanism, restarted via a clean process exit
that leans on the systemd unit's own `Restart=always` (see agent.sh). No
`systemctl` shell-out, no separate installer, no version-number gate on the
apply step -- fetch_remote_version() only gates *whether it's worth asking*,
never whether git actually finds something to reset to.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.request

from . import config as config_module

log = logging.getLogger("culprit.agent.updater")

_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never hang on a prompt
_REMOTE_VERSION_URL = (
    "https://raw.githubusercontent.com/OlaYZen/culprit-agent/{branch}/version.json")


def _run(argv: list[str], timeout: float) -> str | None:
    """A git/pip subprocess in the checkout, returning stdout or None on any
    failure. Never raises -- mirrors linux.run()'s discipline, but this one
    needs cwd/env, which that shared helper does not take."""
    try:
        completed = subprocess.run(
            argv, cwd=config_module.ROOT, env=_GIT_ENV,
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("%s failed: %s", " ".join(argv), exc)
        return None
    if completed.returncode != 0:
        log.warning("%s exited %d: %s", " ".join(argv), completed.returncode,
                    completed.stderr.strip()[:300])
        return None
    return completed.stdout


def current_branch() -> str:
    """The checkout's branch, or "main" when there is no .git to ask (a
    Docker or cp -r deployment) -- just the default fetch_remote_version()
    compares against, never assumed capable of anything else."""
    if not (config_module.ROOT / ".git").is_dir():
        return "main"
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=10)
    return branch.strip() if branch else "main"


def capability() -> tuple[bool, str | None]:
    """(capable, reason) -- every blocker is named exactly, never silent."""
    if os.environ.get("CULPRIT_AGENT_DOCKER"):
        return False, "running in the Docker image; rebuild/pull the image instead"
    if not config_module.get().allow_remote_update:
        return False, "remote updates disabled on this agent (allow_remote_update is false)"
    if not os.environ.get("INVOCATION_ID"):
        return False, "not running under systemd (started via --run); nothing would bring it back up"
    if not (config_module.ROOT / ".git").is_dir():
        return False, "checkout has no .git (deployed with cp -r, not git clone)"
    if not _run(["git", "remote", "get-url", "origin"], timeout=10):
        return False, "no 'origin' remote configured"
    status = _run(["git", "status", "--porcelain"], timeout=15)
    if status is None:
        return False, "git status failed"
    if status.strip():
        return False, "the checkout has local modifications (git status is not clean)"
    return True, None


def fetch_remote_version(branch: str) -> tuple[str | None, str | None]:
    """(version, reason) from the version.json GitHub publishes for `branch`.
    Independent of capability(): worth showing even on a Docker or cp -r
    install that cannot self-apply an update."""
    url = _REMOTE_VERSION_URL.format(branch=branch)
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read())
        return str(data["version"]), None
    except urllib.error.URLError as exc:
        return None, f"could not reach github: {exc}"
    except (ValueError, KeyError, TypeError):
        return None, f"version.json missing or unparsable on {branch}"


def _cmd_err(cmd_id, status: int, message: str) -> dict:
    return {"id": cmd_id, "ok": False, "status": status, "error": message}


def perform(cmd_id) -> dict:
    """Run the update. Returns the {"id", "ok", ...} shape agent.py's other
    command results use, plus "restart": True when the caller should exit
    once this result has been posted back. Never raises."""
    capable, reason = capability()
    if not capable:
        return _cmd_err(cmd_id, 409, reason or "not capable")

    from_sha = _run(["git", "rev-parse", "HEAD"], timeout=10)
    if from_sha is None:
        return _cmd_err(cmd_id, 500, "git rev-parse HEAD failed")
    from_sha = from_sha.strip()

    if _run(["git", "fetch", "--quiet", "origin"], timeout=60) is None:
        return _cmd_err(cmd_id, 502, "git fetch failed")

    branch = current_branch()
    if _run(["git", "reset", "--hard", "--quiet", f"origin/{branch}"],
           timeout=30) is None:
        return _cmd_err(cmd_id, 500, f"git reset --hard origin/{branch} failed")

    to_sha = _run(["git", "rev-parse", "HEAD"], timeout=10)
    to_sha = to_sha.strip() if to_sha else from_sha

    if to_sha == from_sha:
        return {"id": cmd_id, "ok": True,
                "result": {"updated": False, "sha": to_sha[:12]}}

    pip = _run([sys.executable, "-m", "pip", "install", "--quiet",
               "-r", "requirements-agent.txt"], timeout=180)
    if pip is None:
        # Revert: disk must keep matching what's actually running.
        _run(["git", "reset", "--hard", "--quiet", from_sha], timeout=30)
        return _cmd_err(
            cmd_id, 500,
            f"pip install failed after updating to {to_sha[:12]}; "
            f"reverted to {from_sha[:12]}")

    return {"id": cmd_id, "ok": True,
            "result": {"updated": True, "from_sha": from_sha[:12],
                      "to_sha": to_sha[:12]},
            "restart": True}
