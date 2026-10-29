"""Tests for framework service process discovery."""

from pathlib import Path

from framework.config import RunnerConfig
from framework.services import (
    _cli,
    _is_worker_launcher,
    _tmux_shell,
    _worker_tree_roots,
)


def test_worker_launcher_detection() -> None:
    assert _is_worker_launcher(
        "uv run python framework/crsbench_cli.py worker --experiment-config run.yaml"
    )
    assert _is_worker_launcher("uv run crsbench worker --experiment-name example")
    assert not _is_worker_launcher("uv run crsbench evaluator --ci")
    assert not _is_worker_launcher("python unrelated_worker.py")


def test_idle_workers_are_owned_by_launcher() -> None:
    processes = {
        100: (
            1,
            "uv run python framework/crsbench_cli.py worker --experiment-config x",
        ),
        101: (100, "python framework/crsbench_cli.py worker --experiment-config x"),
        110: (101, "rq:worker:abc: Idle"),
        120: (101, "rq:worker:def: Processing crsbench.distributed.jobs.run_crs_trial"),
    }

    assert _worker_tree_roots(processes) == {100}


def test_unrelated_rq_worker_is_not_selected() -> None:
    processes = {
        200: (1, "python unrelated_service.py"),
        201: (200, "rq:worker:other: Idle"),
    }

    assert _worker_tree_roots(processes) == set()


def test_orphaned_busy_crsbench_worker_is_selected() -> None:
    command = "rq:worker:abc: Processing crsbench.distributed.jobs.run_crs_trial"
    processes = {300: (1, command)}

    assert _worker_tree_roots(processes) == {300}


def test_framework_commands_use_native_crsbench_cli() -> None:
    cfg = RunnerConfig(
        run_id="run-example",
        llm_host="http://llm.example",
        llm_models=("model",),
        crs_names=("discver-model",),
        benchmark_names=("benchmark",),
        benchmarks_dir=Path("benchmarks"),
        suites_dir=Path("benchmark-suites"),
        registry_dir=Path("oss-crs/registry"),
        results_dir=Path("results"),
        crs_env_file=Path("framework/cfg_crs_env.yaml"),
        experiment_template=Path("framework/experiment-template.yaml"),
        tmux_session="run-example",
        poll_seconds=1,
    )

    command = _cli(cfg, "worker", Path("experiment.yaml"))
    assert "crsbench" in command
    assert not any(item.startswith("CRSBENCH_QUEUE_MODEL=") for item in command)

    retry_command = _cli(cfg, "run", Path("experiment.yaml"), retry=True)
    assert retry_command[-4:] == [
        "--distributed",
        "--queue-mode",
        "continue",
        "--retry-failed",
    ]

    legacy_command = _cli(
        cfg,
        "worker",
        Path("experiment.yaml"),
        queue_model="per-experiment",
    )
    assert "CRSBENCH_QUEUE_MODEL=per-experiment" in legacy_command

    flat_command = _cli(
        cfg,
        "worker",
        Path("experiment.yaml"),
        queue_model="flat",
    )
    assert "CRSBENCH_QUEUE_MODEL=flat" in flat_command


def test_tmux_shell_preserves_runner_exit_code_with_tee() -> None:
    shell = _tmux_shell(["false"], Path("run.log"), Path("runner.exit"))
    assert "set -o pipefail" in shell
    assert "status=$?" in shell
    assert "exit $status" in shell
