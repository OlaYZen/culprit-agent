#!/usr/bin/env bash
# Deploy/run a culprit agent on this server.
#
# First run (enroll -- get the token on the HOST with `python -m culprit agents add <name>`):
#   ./agent.sh https://hub.example:8787 <name>.<secret>
#   ./agent.sh --insecure https://hub:8787 <token>     # self-signed TLS
#
# After that (config is saved in agent.json):
#   ./agent.sh
#
# The agent has no dashboard and opens no ports: it samples this machine and
# pushes reports to the host. Install it permanently with:
#   mkdir -p ~/.config/systemd/user
#   cp culprit-agent.service ~/.config/systemd/user/
#   systemctl --user enable --now culprit-agent
#   loginctl enable-linger $USER
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# Bring the venv to a known-good state: it exists AND psutil imports. This is
# deliberately not a "does the .venv folder exist" check. A venv can be left
# half-built by an interrupted first run, by `python -m venv` failing on a host
# that lacks python3-venv/ensurepip (it still leaves a bin/python behind, with
# no working pip), or by being copied in from another machine -- and trusting
# the folder then skips setup forever and fails at runtime with
# `ModuleNotFoundError: No module named 'psutil'`. So: try to install the deps;
# if that cannot succeed, rebuild the venv from scratch once; only then give up.
ensure_deps() {
    .venv/bin/python -c 'import psutil' 2>/dev/null && return 0
    echo "installing agent dependencies (psutil)..."
    # `python -m pip` rather than the pip wrapper: it still works when the
    # bin/pip script is missing but the module is present.
    .venv/bin/python -m pip install --quiet --upgrade pip 2>/dev/null || return 1
    .venv/bin/python -m pip install --quiet -r requirements-agent.txt 2>/dev/null || return 1
    .venv/bin/python -c 'import psutil' 2>/dev/null
}

make_venv() {
    echo "creating agent virtual environment (psutil only)..."
    "$PYTHON" -m venv .venv
}

if [ ! -x .venv/bin/python ]; then
    make_venv || {
        echo "error: venv creation failed -- on Debian/Ubuntu: sudo apt install python3-venv" >&2
        exit 1
    }
fi

if ! ensure_deps; then
    # The venv is present but unusable (no pip / broken interpreter). Rebuild it
    # from scratch -- exactly the `rm -rf .venv` a person would do by hand.
    echo "existing .venv is incomplete; rebuilding it from scratch..."
    rm -rf .venv
    make_venv || {
        echo "error: venv creation failed -- on Debian/Ubuntu: sudo apt install python3-venv" >&2
        exit 1
    }
    ensure_deps || {
        echo "error: could not install psutil into the agent venv." >&2
        echo "       Check network access (pip needs to reach PyPI), then rerun." >&2
        echo "       Offline hosts: 'sudo apt install python3-psutil' and recreate" >&2
        echo "       the venv with '$PYTHON -m venv --system-site-packages .venv'." >&2
        exit 1
    }
fi

ARGS=()
INSECURE=""
HOST_URL=""
TOKEN=""
for arg in "$@"; do
    case "$arg" in
        --insecure) INSECURE="--insecure" ;;
        http*://*) HOST_URL="$arg" ;;
        *.*) TOKEN="$arg" ;;
        *) ARGS+=("$arg") ;;
    esac
done

if [ -n "$HOST_URL" ] && [ -n "$TOKEN" ]; then
    exec .venv/bin/python -m culprit.agent --host "$HOST_URL" --token "$TOKEN" \
        $INSECURE "${ARGS[@]+"${ARGS[@]}"}"
fi
exec .venv/bin/python -m culprit.agent $INSECURE "${ARGS[@]+"${ARGS[@]}"}"
