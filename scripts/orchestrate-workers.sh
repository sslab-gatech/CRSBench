#!/usr/bin/env bash
# =============================================================================
# Worker Orchestration Script
# =============================================================================
# Push code, bootstrap, start, and collect CRSBench workers over SSH.
#
# Usage:
#   scripts/orchestrate-workers.sh <command> [machine-or-host ...]
#
# Commands:
#   push        Push the configured branch to GitHub
#   redis-setup Configure Redis/Valkey on the current machine with password auth
#   setup       Setup workers on remote machines (parallel)
#   start       Start workers on remote machines via tmux
#   stop        Stop workers on remote machines
#   status      Check worker status on remote machines
#   logs        Tail worker logs on a remote machine
#   collect     Rsync experiment results from remote machines
#   all         Push + setup + start (full deployment)
#
# Host selection:
#   - Pass explicit hostnames on the CLI, for example:
#       scripts/orchestrate-workers.sh status worker-a.example.com
#   - Or create `.crsbench-remote-hosts` with `alias=host` lines, for example:
#       worker-a=worker-a.example.com
#       worker-b=worker-b.example.com
#
# Environment:
#   CRSBENCH_BRANCH               Git ref to push/checkout (default: current checkout branch, else `ccs-artifacts`)
#   CRSBENCH_REPO_URL             Repo URL cloned on remote hosts
#   CRSBENCH_INSTALL_DIR          Remote install path (default: `$HOME/CRSBench`)
#   CRSBENCH_REMOTE_CONFIG_PATH   Shared config path for all remote workers
#   CRSBENCH_REMOTE_CONFIG_TEMPLATE
#                                 `printf` template used when each machine has its own config path
#   CRSBENCH_REDIS_HOST           Redis/Valkey host:port for setup/start instructions
#   CRSBENCH_REMOTE_EXPERIMENT_DIR
#                                 Remote experiment root to collect
#   CRSBENCH_LOCAL_COLLECT_DIR    Local directory where `collect` writes per-host shards
#   CRSBENCH_REDIS_PASSWORD       Override Redis password (default: read from `.env`)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BRANCH="${CRSBENCH_BRANCH:-$(git -C "$REPO_DIR" branch --show-current 2>/dev/null || true)}"
BRANCH="${BRANCH:-ccs-artifacts}"
REPO_URL="${CRSBENCH_REPO_URL:-git@github.com:artifact-org/CRSBench.git}"
SETUP_SCRIPT="$SCRIPT_DIR/setup-remote-worker.sh"
INSTALL_DIR="${CRSBENCH_INSTALL_DIR:-$HOME/CRSBench}"
TMUX_SESSION="${CRSBENCH_TMUX_SESSION:-crsbench-worker}"
REMOTE_EXPERIMENT_DIR="${CRSBENCH_REMOTE_EXPERIMENT_DIR:-$HOME/crsbench/experiment-data}"
LOCAL_COLLECT_DIR="${CRSBENCH_LOCAL_COLLECT_DIR:-$REPO_DIR/.run/remote-collect}"
REMOTE_HOSTS_FILE="${CRSBENCH_REMOTE_HOSTS_FILE:-$REPO_DIR/.crsbench-remote-hosts}"
REMOTE_ENV_FILE="${CRSBENCH_REMOTE_ENV_FILE:-/tmp/crsbench-worker.env}"
REMOTE_CONFIG_PATH="${CRSBENCH_REMOTE_CONFIG_PATH:-}"
REMOTE_CONFIG_TEMPLATE="${CRSBENCH_REMOTE_CONFIG_TEMPLATE:-experiment-configs/%s.yaml}"
REDIS_HOST="${CRSBENCH_REDIS_HOST:-}"
BUNDLE_WORKERS="${CRSBENCH_BUNDLE_WORKERS:-20}"
ENV_FILE="$REPO_DIR/.env"

declare -a ALL_MACHINES=()
declare -A HOSTNAMES
REMOTE_HOSTS_LOADED=0

SSH_OPTS="-A -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"

log() { echo "[orchestrate] $*"; }
err() { echo "[orchestrate] ERROR: $*" >&2; }

trim() {
    printf '%s' "$1" | xargs
}

load_env() {
    if [[ -z "${CRSBENCH_REDIS_PASSWORD:-}" ]] && [[ -f "$ENV_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$ENV_FILE"
    fi
}

load_host_config() {
    if [[ $REMOTE_HOSTS_LOADED -eq 1 ]]; then
        return
    fi
    REMOTE_HOSTS_LOADED=1

    if [[ ! -f "$REMOTE_HOSTS_FILE" ]]; then
        return
    fi

    while IFS='=' read -r alias host; do
        alias=$(trim "$alias")
        host=$(trim "$host")

        if [[ -z "$alias" || "$alias" == \#* || -z "$host" ]]; then
            continue
        fi

        ALL_MACHINES+=("$alias")
        HOSTNAMES["$alias"]="$host"
    done < "$REMOTE_HOSTS_FILE"
}

get_redis_password() {
    load_env
    if [[ -n "${CRSBENCH_REDIS_PASSWORD:-}" ]]; then
        echo "$CRSBENCH_REDIS_PASSWORD"
        return
    fi
    err "Redis password not found. Set CRSBENCH_REDIS_PASSWORD or run: scripts/orchestrate-workers.sh redis-setup"
    exit 1
}

get_hostname() {
    local machine="$1"
    load_host_config

    if [[ -n "${HOSTNAMES[$machine]+x}" ]]; then
        echo "${HOSTNAMES[$machine]}"
        return
    fi

    if [[ "$machine" == *@* || "$machine" == *.* ]]; then
        echo "$machine"
        return
    fi

    err "Unknown machine: $machine"
    err "Pass a hostname directly, or add '$machine=<host>' to $REMOTE_HOSTS_FILE"
    exit 1
}

get_machines() {
    if [[ $# -gt 0 ]]; then
        echo "$@"
        return
    fi

    load_host_config
    if [[ ${#ALL_MACHINES[@]} -eq 0 ]]; then
        err "No remote machines configured."
        err "Create $REMOTE_HOSTS_FILE with alias=host lines, or pass hosts on the CLI."
        exit 1
    fi
    echo "${ALL_MACHINES[@]}"
}

remote_config_for_machine() {
    local machine="$1"
    if [[ -n "$REMOTE_CONFIG_PATH" ]]; then
        echo "$REMOTE_CONFIG_PATH"
    else
        printf "$REMOTE_CONFIG_TEMPLATE" "$machine"
    fi
}

remote_setup_env() {
    local -a env_parts=()
    env_parts+=("CRSBENCH_REPO_URL=$(printf '%q' "$REPO_URL")")
    env_parts+=("CRSBENCH_BRANCH=$(printf '%q' "$BRANCH")")
    env_parts+=("CRSBENCH_INSTALL_DIR=$(printf '%q' "$INSTALL_DIR")")
    env_parts+=("CRSBENCH_REMOTE_ENV_FILE=$(printf '%q' "$REMOTE_ENV_FILE")")
    env_parts+=("CRSBENCH_BUNDLE_WORKERS=$(printf '%q' "$BUNDLE_WORKERS")")
    if [[ -n "$REMOTE_CONFIG_PATH" ]]; then
        env_parts+=("CRSBENCH_CONFIG_FILE=$(printf '%q' "$REMOTE_CONFIG_PATH")")
    fi
    if [[ -n "$REDIS_HOST" ]]; then
        env_parts+=("CRSBENCH_REDIS_HOST=$(printf '%q' "$REDIS_HOST")")
    fi
    if [[ -n "${CRSBENCH_REDIS_PASSWORD:-}" ]]; then
        env_parts+=("CRSBENCH_REDIS_PASSWORD=$(printf '%q' "$CRSBENCH_REDIS_PASSWORD")")
    fi
    printf '%s ' "${env_parts[@]}"
}

ssh_cmd() {
    local host="$1"
    shift
    local ssh_flags=()
    while [[ $# -gt 0 && "$1" == -* ]]; do
        ssh_flags+=("$1")
        shift
    done
    ssh $SSH_OPTS "${ssh_flags[@]+"${ssh_flags[@]}"}" "$host" "$@"
}

cmd_redis_setup() {
    log "Setting up Redis via Docker with password authentication..."

    local container_name="redis-crsbench"

    if ! command -v docker &>/dev/null; then
        err "docker not found. Install Docker first."
        exit 1
    fi
    if ! command -v redis-cli &>/dev/null; then
        err "redis-cli not found. Install redis-tools: sudo apt install redis-tools"
        exit 1
    fi

    load_env
    local password="${CRSBENCH_REDIS_PASSWORD:-}"
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 24)
        log "  Generated new Redis password"
    else
        log "  Reusing existing password from .env"
    fi

    if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
        log "  Removing existing $container_name container..."
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    fi

    log "  Starting Redis container ($container_name) on port 6379..."
    docker run -d \
        --name "$container_name" \
        --restart unless-stopped \
        -p 0.0.0.0:6379:6379 \
        redis:latest \
        redis-server --requirepass "$password"

    local retries=10
    while ! redis-cli -a "$password" ping &>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            err "Redis container failed to become ready"
            exit 1
        fi
        sleep 1
    done

    echo "CRSBENCH_REDIS_PASSWORD=$password" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    log "  Container:  $container_name (redis:latest)"
    log "  Listening:  0.0.0.0:6379"
    log "  Password:   saved to $ENV_FILE"
    log ""
    log "  Usage:  uv run crsbench ...  (.env is loaded automatically)"
}

cmd_push() {
    log "Pushing $BRANCH to origin..."
    cd "$REPO_DIR"
    git push origin "$BRANCH"
    log "Push complete"
}

cmd_setup() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    if [[ ! -f "$SETUP_SCRIPT" ]]; then
        err "Setup script not found: $SETUP_SCRIPT"
        exit 1
    fi

    load_env
    log "Setting up workers on: ${machines[*]}"

    local pids=()
    local logdir
    logdir=$(mktemp -d)

    for machine in "${machines[@]}"; do
        local host
        host=$(get_hostname "$machine")
        local logfile="$logdir/$machine.log"
        local setup_env
        setup_env=$(remote_setup_env)

        log "  Starting setup on $machine ($host)..."
        scp -q $SSH_OPTS "$SETUP_SCRIPT" "$host:/tmp/setup-remote-worker.sh"
        if [[ -f "$ENV_FILE" ]]; then
            scp -q $SSH_OPTS "$ENV_FILE" "$host:$REMOTE_ENV_FILE"
        fi
        ssh $SSH_OPTS "$host" "${setup_env}bash /tmp/setup-remote-worker.sh $(printf '%q' "$machine")" \
            > "$logfile" 2>&1 &
        pids+=($!)
    done

    log "  Setup running in parallel. Tailing progress..."
    local all_done=0
    while [[ $all_done -eq 0 ]]; do
        all_done=1
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                all_done=0
                break
            fi
        done
        if [[ $all_done -eq 0 ]]; then
            for machine in "${machines[@]}"; do
                local last_step
                last_step=$(grep -oP '\[\d+/\d+\].*' "$logdir/$machine.log" 2>/dev/null | tail -1 || true)
                if [[ -n "$last_step" ]]; then
                    echo "    $machine: $last_step"
                fi
            done
            sleep 10
        fi
    done

    local failed=0
    for i in "${!machines[@]}"; do
        local machine="${machines[$i]}"
        local pid="${pids[$i]}"
        local logfile="$logdir/$machine.log"

        if wait "$pid"; then
            log "  $machine: setup OK"
        else
            err "  $machine: setup FAILED (see $logfile)"
            failed=1
        fi
    done

    if [[ $failed -eq 1 ]]; then
        log "Log files in: $logdir"
        exit 1
    fi

    rm -rf "$logdir"
    log "All workers set up"
}

cmd_start() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    load_env
    local redis_pass="${CRSBENCH_REDIS_PASSWORD:-}"

    log "Starting workers on: ${machines[*]}"

    for machine in "${machines[@]}"; do
        local host
        host=$(get_hostname "$machine")
        local config
        config=$(remote_config_for_machine "$machine")
        local worker_cmd
        worker_cmd="export PATH=\$HOME/.local/bin:\$PATH"
        if [[ -n "$REDIS_HOST" ]]; then
            worker_cmd+=" && export CRSBENCH_REDIS_HOST=$(printf '%q' "$REDIS_HOST")"
        fi
        if [[ -n "$redis_pass" ]]; then
            worker_cmd+=" && export CRSBENCH_REDIS_PASSWORD=$(printf '%q' "$redis_pass")"
        fi
        worker_cmd+=" && cd $(printf '%q' "$INSTALL_DIR")"
        worker_cmd+=" && uv run crsbench worker --experiment-config $(printf '%q' "$config") 2>&1 | tee worker.log"

        ssh_cmd "$host" "tmux kill-session -t $TMUX_SESSION 2>/dev/null || true"
        ssh_cmd "$host" "tmux new-session -d -s $(printf '%q' "$TMUX_SESSION") $(printf '%q' "$worker_cmd")"

        log "  $machine: worker started (tmux session: $TMUX_SESSION)"
    done

    log "All workers started"
}

cmd_stop() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    log "Stopping workers on: ${machines[*]}"

    for machine in "${machines[@]}"; do
        local host
        host=$(get_hostname "$machine")

        if ssh_cmd "$host" "tmux kill-session -t $TMUX_SESSION 2>/dev/null"; then
            log "  $machine: worker stopped"
        else
            log "  $machine: no worker running"
        fi
    done
}

cmd_status() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"
    local install_parent
    install_parent="$(dirname "$INSTALL_DIR")"

    for machine in "${machines[@]}"; do
        local host
        host=$(get_hostname "$machine")

        echo ""
        echo "=== $machine ($host) ==="

        if ssh_cmd "$host" "tmux has-session -t $TMUX_SESSION 2>/dev/null"; then
            echo "  Worker: RUNNING"
        else
            echo "  Worker: STOPPED"
        fi

        ssh_cmd "$host" "df -h $(printf '%q' "$install_parent") | tail -1 | awk '{print \"  Disk:   \" \$3 \" used / \" \$2 \" (\" \$5 \" full)\"}'" 2>/dev/null || true

        local containers
        containers=$(ssh_cmd "$host" "docker ps -q 2>/dev/null | wc -l" 2>/dev/null || echo "?")
        echo "  Docker: $containers containers running"
    done
    echo ""
}

cmd_logs() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    if [[ ${#machines[@]} -ne 1 ]]; then
        err "logs command requires exactly one machine (got: ${machines[*]})"
        exit 1
    fi

    local machine="${machines[0]}"
    local host
    host=$(get_hostname "$machine")

    log "Attaching to $machine worker logs (Ctrl+C to detach)..."
    ssh_cmd "$host" -t "tmux attach -t $TMUX_SESSION"
}

cmd_collect() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    log "Collecting results from: ${machines[*]}"
    log "  Remote source: $REMOTE_EXPERIMENT_DIR"
    log "  Local dest:    $LOCAL_COLLECT_DIR/<machine>"

    mkdir -p "$LOCAL_COLLECT_DIR"

    for machine in "${machines[@]}"; do
        local host
        host=$(get_hostname "$machine")
        local local_dest="$LOCAL_COLLECT_DIR/$machine"

        log "  Syncing $machine..."
        mkdir -p "$local_dest"

        rsync -az --progress \
            --exclude='crs-build/' \
            --exclude='.oss-crs-workdir/' \
            -e "ssh $SSH_OPTS" \
            "$host:$REMOTE_EXPERIMENT_DIR/" \
            "$local_dest/"

        log "  $machine: sync complete"
    done

    log "Collection complete. Per-machine shards saved under $LOCAL_COLLECT_DIR"
}

cmd_all() {
    local machines
    read -ra machines <<< "$(get_machines "$@")"

    cmd_push
    echo ""
    cmd_setup "${machines[@]}"
    echo ""
    cmd_start "${machines[@]}"
    echo ""
    cmd_status "${machines[@]}"
}

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    push)        cmd_push ;;
    redis-setup) cmd_redis_setup ;;
    setup)       cmd_setup "$@" ;;
    start)       cmd_start "$@" ;;
    stop)        cmd_stop "$@" ;;
    status)      cmd_status "$@" ;;
    logs)        cmd_logs "$@" ;;
    collect)     cmd_collect "$@" ;;
    all)         cmd_all "$@" ;;
    *)
        cat <<EOF
Usage: $0 {push|redis-setup|setup|start|stop|status|logs|collect|all} [machine-or-host ...]

Remote host configuration:
  - pass hostnames directly on the CLI, or
  - create $REMOTE_HOSTS_FILE with 'alias=host' lines.

Selected environment:
  CRSBENCH_BRANCH=$BRANCH
  CRSBENCH_REPO_URL=$REPO_URL
  CRSBENCH_INSTALL_DIR=$INSTALL_DIR
  CRSBENCH_REDIS_HOST=${REDIS_HOST:-<unset>}
  CRSBENCH_REMOTE_CONFIG_PATH=${REMOTE_CONFIG_PATH:-<unset>}
  CRSBENCH_REMOTE_CONFIG_TEMPLATE=$REMOTE_CONFIG_TEMPLATE
  CRSBENCH_REMOTE_EXPERIMENT_DIR=$REMOTE_EXPERIMENT_DIR
  CRSBENCH_LOCAL_COLLECT_DIR=$LOCAL_COLLECT_DIR
EOF
        exit 1
        ;;
esac
