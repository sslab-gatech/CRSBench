"""Valkey preparation and tmux lifecycle management."""

from __future__ import annotations

import logging  # noqa: TID251 - standalone wrapper uses stdlib logging
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from framework.errors import FrameworkError

if TYPE_CHECKING:
    from framework.config import RunnerConfig

log = logging.getLogger(__name__)

UNSET_PROXY_ARGS = [
    "-u",
    "http_proxy",
    "-u",
    "https_proxy",
    "-u",
    "HTTP_PROXY",
    "-u",
    "HTTPS_PROXY",
]


def _run(
    command: list[str], *, cwd: Path, check: bool = True
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command, cwd=cwd, text=True, capture_output=True, check=check
        )
    except FileNotFoundError as exc:
        raise FrameworkError(
            f"required command is not installed: {command[0]}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise FrameworkError(
            f"command failed ({shlex.join(command)}): {detail}"
        ) from exc


def require_tmux() -> None:
    if shutil.which("tmux") is None:
        raise FrameworkError("tmux is not installed or not on PATH")
    if shutil.which("uv") is None:
        raise FrameworkError("uv is not installed or not on PATH")


def require_local_services() -> None:
    """Require tools used to manage the repository-owned local Valkey."""
    require_tmux()
    if shutil.which("docker") is None:
        raise FrameworkError("docker is not installed or not on PATH")


def _redis_endpoint(redis_host: object) -> tuple[str, int]:
    if not isinstance(redis_host, str) or not redis_host.strip():
        raise FrameworkError("runtime.redis_host must identify local Valkey")
    value = redis_host.strip()
    parsed = urlparse(value if "://" in value else f"redis://{value}")
    try:
        port = parsed.port or 6379
    except ValueError as exc:
        raise FrameworkError(f"invalid runtime.redis_host: {value}") from exc
    return (parsed.hostname or ""), port


def require_owned_local_valkey(redis_host: object) -> str:
    """Reject destructive management of anything except our local service."""
    host, port = _redis_endpoint(redis_host)
    if host not in {"localhost", "127.0.0.1"} or port != 6379:
        raise FrameworkError(
            "automatic Valkey restart/flush is restricted to the repository-owned "
            f"local service at localhost:6379 (configured: {redis_host!r})"
        )
    return f"{host}:{port}"


def _valkey_helper(repo_root: Path, *args: str) -> None:
    helper = repo_root / "scripts" / "valkey-helper.py"
    _run([sys.executable, str(helper), *args], cwd=repo_root)


def _require_valkey_pong(repo_root: Path) -> None:
    result = _run(
        ["docker", "exec", "crsbench-valkey", "valkey-cli", "ping"],
        cwd=repo_root,
    )
    if result.stdout.strip() != "PONG":
        raise FrameworkError(
            "repository-owned local Valkey did not return PONG after restart"
        )


def prepare_local_valkey(repo_root: Path, redis_host: object) -> None:
    """Restart, flush, and probe the explicitly local wrapper-owned service."""
    require_owned_local_valkey(redis_host)
    log.info("restarting repository-owned local Valkey")
    # Use explicit stop/start rather than helper ``restart``: restart preserves
    # password mode from .env, which binds on all interfaces. Framework runs own
    # a loopback-only service.
    _valkey_helper(repo_root, "stop")
    _valkey_helper(repo_root, "start")
    log.info("flushing local Valkey before fresh experiment")
    _valkey_helper(repo_root, "clean-all", "--force")
    _valkey_helper(repo_root, "status")
    _require_valkey_pong(repo_root)


def check_valkey_connection(redis_host: object) -> None:
    """Perform a non-destructive Redis/Valkey readiness check."""
    if not isinstance(redis_host, str) or not redis_host.strip():
        raise FrameworkError("runtime.redis_host is missing")
    from crsbench.distributed.queue import check_redis_available

    if not check_redis_available(redis_host.strip()):
        raise FrameworkError(f"Valkey is not reachable at {redis_host}")


def _cli(
    cfg: RunnerConfig,
    subcommand: str,
    experiment_yaml: Path,
    *,
    retry: bool = False,
    queue_model: str | None = None,
) -> list[str]:
    command = [
        "env",
        *UNSET_PROXY_ARGS,
    ]
    if queue_model is not None:
        command.append(f"CRSBENCH_QUEUE_MODEL={queue_model}")
    command.extend(
        [
            f"CRSBENCH_LLM_UPSTREAM_BASE_URL={cfg.llm_host}",
            "uv",
            "run",
            "crsbench",
            subcommand,
            "--experiment-config",
            str(experiment_yaml),
        ]
    )
    if subcommand == "run":
        command.append("--distributed")
        if retry:
            command.extend(["--queue-mode", "continue", "--retry-failed"])
    return command


def _tmux_shell(
    command: list[str], log_path: Path, exit_path: Path | None = None
) -> str:
    command_text = shlex.join(command)
    if exit_path is not None:
        marker = shlex.quote(str(exit_path))
        command_text += (
            f"; status=$?; printf '%s\\n' \"$status\" > {marker}; exit $status"
        )
    log_file = shlex.quote(str(log_path))
    return f"set -o pipefail; {{ {command_text}; }} 2>&1 | tee -a {log_file}"


def _local_processes() -> dict[int, tuple[int, str]]:
    """Return local process IDs mapped to parent IDs and command lines."""
    try:
        result = subprocess.run(
            ["ps", "-u", str(os.getuid()), "-o", "pid=,ppid=,args="],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FrameworkError(f"could not inspect existing workers: {exc}") from exc
    if result.returncode != 0:
        raise FrameworkError("could not inspect existing workers with ps")

    processes: dict[int, tuple[int, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            processes[int(parts[0])] = (int(parts[1]), parts[2])
        except ValueError:
            continue
    return processes


def _is_worker_launcher(command: str) -> bool:
    """Return whether a command line launches a CRSBench trial worker pool."""
    try:
        arguments = shlex.split(command)
    except ValueError:
        arguments = command.split()
    for index, argument in enumerate(arguments[:-1]):
        executable = Path(argument).name
        if executable in {"crsbench", "crsbench_cli.py"}:
            if arguments[index + 1] == "worker":
                return True
    return False


def _worker_tree_roots(processes: dict[int, tuple[int, str]]) -> set[int]:
    """Find worker launchers plus orphaned visible CRSBench RQ processes."""
    launchers = {
        pid
        for pid, (_parent, command) in processes.items()
        if _is_worker_launcher(command)
    }
    roots: set[int] = set()
    for launcher_pid in launchers:
        root = launcher_pid
        current = launcher_pid
        visited: set[int] = set()
        while current in processes and current not in visited:
            visited.add(current)
            parent = processes[current][0]
            if parent in launchers:
                root = parent
            current = parent
        roots.add(root)

    for worker_pid, (_parent, command) in processes.items():
        if "rq:worker:" not in command or "crsbench" not in command:
            continue

        current = worker_pid
        visited: set[int] = set()
        has_launcher_ancestor = False
        while current in processes and current not in visited:
            visited.add(current)
            if current in launchers:
                has_launcher_ancestor = True
                break
            current = processes[current][0]

        if not has_launcher_ancestor:
            roots.add(worker_pid)

    return roots


def clear_existing_workers() -> None:
    """Terminate all local CRSBench RQ workers before launching a new pool."""
    processes = _local_processes()
    roots = _worker_tree_roots(processes)
    if roots:
        from crsbench.distributed.worker import _terminate_process_tree

        log.info("stopping %d existing local CRSBench worker pool(s)", len(roots))
        for pid in roots:
            _terminate_process_tree(pid)
        remaining_processes = _local_processes()
        survivors = _worker_tree_roots(remaining_processes)
        if survivors:
            raise FrameworkError(
                f"could not stop existing CRSBench worker pools: {sorted(survivors)}"
            )


def launch_tmux(
    cfg: RunnerConfig,
    repo_root: Path,
    experiment_yaml: Path,
    *,
    logs_dir: Path | None = None,
    exit_path: Path | None = None,
    retry: bool = False,
    queue_model: str | None = None,
) -> None:
    existing = _run(
        ["tmux", "has-session", "-t", cfg.tmux_session],
        cwd=repo_root,
        check=False,
    )
    if existing.returncode == 0:
        raise FrameworkError(f"tmux session already exists: {cfg.tmux_session}")
    logs_dir = cfg.logs_dir if logs_dir is None else logs_dir
    exit_path = cfg.run_dir / "runner.exit" if exit_path is None else exit_path
    logs_dir.mkdir(parents=True, exist_ok=True)
    specs = [
        (
            "evaluator",
            _cli(cfg, "evaluator", experiment_yaml, queue_model=queue_model),
            None,
        ),
        (
            "worker",
            _cli(cfg, "worker", experiment_yaml, queue_model=queue_model),
            None,
        ),
        (
            "run",
            _cli(
                cfg,
                "run",
                experiment_yaml,
                retry=retry,
                queue_model=queue_model,
            ),
            exit_path,
        ),
    ]
    try:
        for index, (name, command, marker) in enumerate(specs):
            shell_command = _tmux_shell(command, logs_dir / f"{name}.log", marker)
            if index == 0:
                tmux = [
                    "tmux",
                    "new-session",
                    "-d",
                    "-s",
                    cfg.tmux_session,
                    "-n",
                    name,
                    "bash",
                    "-lc",
                    shell_command,
                ]
            else:
                tmux = [
                    "tmux",
                    "new-window",
                    "-t",
                    cfg.tmux_session,
                    "-n",
                    name,
                    "bash",
                    "-lc",
                    shell_command,
                ]
            _run(tmux, cwd=repo_root)
    except FrameworkError:
        stop_session(cfg)
        raise


def log_monitoring_commands(cfg: RunnerConfig, *, logs_dir: Path | None = None) -> None:
    """Print copy-and-paste commands for observing a running experiment."""
    log.info("Run started in tmux.")
    log.info("Attach to the session:")
    log.info("  tmux attach -t %s", shlex.quote(cfg.tmux_session))
    log.info("Follow logs:")
    logs_dir = cfg.logs_dir if logs_dir is None else logs_dir
    for name in ("run", "worker", "evaluator"):
        log.info("  tail -f %s", shlex.quote(str(logs_dir / f"{name}.log")))
    log.info("Waiting for runner to finish...")


def wait_for_runner(cfg: RunnerConfig, *, exit_path: Path | None = None) -> int:
    exit_path = cfg.run_dir / "runner.exit" if exit_path is None else exit_path
    while not exit_path.exists():
        alive = (
            subprocess.run(
                ["tmux", "has-session", "-t", cfg.tmux_session],
                capture_output=True,
            ).returncode
            == 0
        )
        if not alive:
            raise FrameworkError(
                "tmux session ended before the runner recorded an exit code"
            )
        time.sleep(cfg.poll_seconds)
    try:
        return int(exit_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        raise FrameworkError(f"invalid runner exit marker: {exit_path}") from exc


def stop_session(cfg: RunnerConfig) -> None:
    """Stop pane process trees before removing the tmux session."""
    panes = subprocess.run(
        [
            "tmux",
            "list-panes",
            "-s",
            "-t",
            cfg.tmux_session,
            "-F",
            "#{pane_pid}",
        ],
        capture_output=True,
        text=True,
    )
    if panes.returncode == 0:
        from crsbench.distributed.worker import _terminate_process_tree

        for value in panes.stdout.splitlines():
            try:
                _terminate_process_tree(int(value))
            except Exception as exc:
                log.warning("could not stop tmux pane process %r: %s", value, exc)
    subprocess.run(
        ["tmux", "kill-session", "-t", cfg.tmux_session],
        capture_output=True,
    )
