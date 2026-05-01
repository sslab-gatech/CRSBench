#!/usr/bin/env bash
# =============================================================================
# Remote Worker Setup Script
# =============================================================================
# Sets up a remote machine to run as a CRSBench distributed worker.
#
# Usage:
#   export CRSBENCH_REDIS_HOST=orchestrator.example.com:6379
#   export CRSBENCH_BRANCH=ccs-artifacts     # optional; otherwise use the cloned repo's default branch
#   export CRSBENCH_CONFIG_FILE=/path/to/config.yaml  # optional
#   bash setup-remote-worker.sh worker-a
#
# Optional environment:
#   CRSBENCH_REPO_URL        Git URL to clone or pull
#   CRSBENCH_BRANCH          Git branch/ref to check out
#   CRSBENCH_INSTALL_DIR     Checkout path on the remote machine
#   CRSBENCH_REDIS_HOST      Redis/Valkey host:port used for connectivity test
#   CRSBENCH_CONFIG_FILE     Worker config path to verify/show in final instructions
#   CRSBENCH_REMOTE_ENV_FILE Staged `.env` path copied by the orchestrator helper
#   CRSBENCH_BUNDLE_WORKERS  Parallelism for `benchmark bundle-all`
# =============================================================================

set -euo pipefail

MACHINE_NAME="${1:?Usage: $0 <machine-name>}"
REPO_URL="${CRSBENCH_REPO_URL:-git@github.com:artifact-org/CRSBench.git}"
BRANCH="${CRSBENCH_BRANCH:-}"
INSTALL_DIR="${CRSBENCH_INSTALL_DIR:-$HOME/CRSBench}"
CRSBENCH_REDIS_HOST="${CRSBENCH_REDIS_HOST:-}"
REMOTE_ENV_FILE="${CRSBENCH_REMOTE_ENV_FILE:-/tmp/crsbench-worker.env}"
BUNDLE_WORKERS="${CRSBENCH_BUNDLE_WORKERS:-20}"
CONFIG_FILE="${CRSBENCH_CONFIG_FILE:-$INSTALL_DIR/experiment-configs/${MACHINE_NAME}.yaml}"

echo "============================================="
echo " CRSBench Remote Worker Setup: $MACHINE_NAME"
echo "============================================="

echo ""
echo "[1/9] Checking prerequisites..."

if ! command -v git &>/dev/null; then
    echo "ERROR: git not found. Install git first."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found. Install Docker first."
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon not running or current user lacks permission."
    echo "  Try: sudo usermod -aG docker $USER && newgrp docker"
    exit 1
fi

echo "  git:    $(git --version)"
echo "  docker: $(docker --version)"

echo ""
echo "[2/9] Configuring git SSH access for submodules..."

if ! git config --global --get url."git@github.com:artifact-org/".insteadOf &>/dev/null; then
    git config --global --unset url."git@github.com:".insteadOf 2>/dev/null || true
    git config --global url."git@github.com:artifact-org/".insteadOf "https://github.com/artifact-org/"
    echo "  Configured HTTPS→SSH URL rewrite for artifact-org repos"
else
    echo "  HTTPS→SSH URL rewrite already configured"
fi

if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
    echo "  GitHub SSH access: OK"
else
    echo "WARNING: GitHub SSH access may not be configured."
    echo "  Submodule init may fail. To fix:"
    echo "    1. Generate key: ssh-keygen -t ed25519 -C \"$MACHINE_NAME@example.com\""
    echo "    2. Add to GitHub: https://github.com/settings/keys"
    echo "    3. Test: ssh -T git@github.com"
fi

echo ""
echo "[3/9] Setting up CRSBench repo..."

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "  Repo exists at $INSTALL_DIR, updating..."
    cd "$INSTALL_DIR"
    git fetch origin
    if [ -n "$BRANCH" ]; then
        git checkout "$BRANCH"
        git pull --ff-only origin "$BRANCH"
    else
        BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
        if [ -n "$BRANCH" ]; then
            git pull --ff-only origin "$BRANCH"
        else
            BRANCH="$(git rev-parse --short HEAD)"
            echo "  Repo is in detached HEAD state at $BRANCH; leaving checkout unchanged"
        fi
    fi
else
    echo "  Cloning to $INSTALL_DIR..."
    if [ -n "$BRANCH" ]; then
        git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"
    BRANCH="${BRANCH:-$(git symbolic-ref --quiet --short HEAD 2>/dev/null || git rev-parse --short HEAD)}"
fi

echo "  Using CRSBench ref: $BRANCH"

if [ -f "$REMOTE_ENV_FILE" ]; then
    echo "  Installing staged environment file to $INSTALL_DIR/.env..."
    install -m 600 "$REMOTE_ENV_FILE" "$INSTALL_DIR/.env"
    rm -f "$REMOTE_ENV_FILE"
fi

echo ""
echo "[4/9] Initializing submodules..."
git submodule update --init --recursive
echo "  Submodules initialized"

echo ""
echo "[5/9] Installing Python environment..."

if ! command -v uv &>/dev/null; then
    echo "  Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "  uv: $(uv --version)"
echo "  Installing CRSBench dependencies..."
uv sync --all-extras
echo "  Installing CRSBench in editable mode..."
uv pip install -e .

echo ""
echo "[6/9] Bundling benchmarks..."
uv run crsbench benchmark bundle-all --force --workers "$BUNDLE_WORKERS" benchmarks/
echo "  Benchmarks bundled"

echo ""
echo "[7/9] Preparing coverage dependencies..."
./scripts/setup-third-party.sh
uv run crsbench prepare --coverage
echo "  Coverage dependencies prepared"

echo ""
echo "[8/9] Checking experiment config..."

if [ -f "$CONFIG_FILE" ]; then
    echo "  Config found: $CONFIG_FILE"
else
    echo "WARNING: Config file not found: $CONFIG_FILE"
    echo "  Set CRSBENCH_CONFIG_FILE before running this script if the worker should use a different path."
fi

echo ""
echo "[9/9] Testing Redis connectivity..."

if [ -z "$CRSBENCH_REDIS_HOST" ]; then
    echo "WARNING: CRSBENCH_REDIS_HOST is not set; skipping connectivity test."
elif uv run python -c "
import os
import redis

host, _, port = '$CRSBENCH_REDIS_HOST'.partition(':')
port = int(port) if port else 6379
r = redis.Redis(
    host=host,
    port=port,
    password=os.environ.get('CRSBENCH_REDIS_PASSWORD'),
    socket_connect_timeout=5,
)
r.ping()
print('  Redis connection OK: $CRSBENCH_REDIS_HOST')
" 2>/dev/null; then
    :
else
    echo "WARNING: Cannot reach Redis at $CRSBENCH_REDIS_HOST"
    echo "  Make sure Redis/Valkey is running on the orchestrator host and is network-accessible."
    echo "  Check: redis-cli -h $CRSBENCH_REDIS_HOST ping"
fi

echo ""
echo "============================================="
echo " Setup complete for $MACHINE_NAME!"
echo "============================================="
echo ""
echo "To start the worker:"
echo "  cd $INSTALL_DIR"
echo "  uv run crsbench worker \\"
echo "    --experiment-config $CONFIG_FILE"
echo ""
echo "To run in background with tmux:"
echo "  tmux new-session -d -s crsbench-worker \\"
echo "    'cd $INSTALL_DIR && uv run crsbench worker --experiment-config $CONFIG_FILE'"
echo ""
echo "To monitor:"
echo "  tmux attach -t crsbench-worker"
