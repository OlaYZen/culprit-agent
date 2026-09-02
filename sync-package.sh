#!/usr/bin/env bash
# Refresh culprit-agent/culprit/ from the shared host package (../culprit), so
# this self-contained bundle stays in sync after edits to shared code
# (collectors, sampler, db, state, config, linux, util). Host-only modules
# (main.py/auth.py/nodes.py) are never copied; the agent-only agent.py is
# preserved. Run from anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
rsync -a --delete \
  --exclude='main.py' --exclude='auth.py' --exclude='nodes.py' --exclude='__main__.py' \
  --exclude='agent.py' \
  --exclude='__pycache__' --exclude='*.pyc' \
  "$repo/culprit/" "$here/culprit/"
echo "synced $repo/culprit -> $here/culprit (agent.py preserved, host-only files skipped)"
