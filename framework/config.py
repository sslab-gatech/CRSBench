"""Load and validate the self-contained framework configuration."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from framework.errors import FrameworkError

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise FrameworkError("cfg 'llm_host' must be a string")
    host = value.strip().rstrip("/")
    if host.endswith("/v1"):
        host = host[:-3]
    if not host.startswith(("http://", "https://")):
        raise FrameworkError("LLM host must begin with http:// or https://")
    return host


@dataclass(frozen=True)
class RunnerConfig:
    run_id: str
    llm_host: str
    llm_models: tuple[str, ...]
    crs_names: tuple[str, ...]
    benchmark_names: tuple[str, ...]
    benchmarks_dir: Path
    suites_dir: Path
    registry_dir: Path
    results_dir: Path
    crs_env_file: Path
    tmux_session: str
    poll_seconds: float
    experiment: dict[str, Any]
    runtime: dict[str, Any]
    storage: dict[str, Any]
    worker: dict[str, Any]
    evaluator: dict[str, Any]

    @property
    def run_dir(self) -> Path:
        return self.results_dir / "framework-runs" / self.run_id.removeprefix("run-")

    @property
    def logs_dir(self) -> Path:
        return self.run_dir / "logs"


def _path(value: str, repo_root: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError("configured paths must be non-empty strings")
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def _configured_path(
    paths: dict[str, Any], key: str, default: str, repo_root: Path
) -> Path:
    value = paths.get(key, default)
    if not isinstance(value, str):
        raise FrameworkError(f"cfg path '{key}' must be a string")
    return _path(value, repo_root)


def _string_list(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
    ):
        raise FrameworkError(f"cfg '{key}' must be a non-empty list")
    result = tuple(item.strip() for item in value)
    if any(not item or not SAFE_NAME.fullmatch(item) for item in result):
        raise FrameworkError(f"cfg '{key}' contains an unsafe or empty name")
    if len(result) != len(set(result)):
        raise FrameworkError(f"cfg '{key}' contains duplicates")
    return result


def _model_list(data: dict[str, Any]) -> tuple[str, ...]:
    value = data.get("llms")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
    ):
        raise FrameworkError("cfg 'llms' must be a non-empty list of strings")
    result = tuple(item.strip() for item in value)
    if any(not item or any(char.isspace() for char in item) for item in result):
        raise FrameworkError("cfg 'llms' contains an empty model or whitespace")
    if len(result) != len(set(result)):
        raise FrameworkError("cfg 'llms' contains duplicates")
    return result


def _required_mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise FrameworkError(f"cfg '{key}' must be an object")
    return value


def load_config(path: Path) -> RunnerConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"config does not exist: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise FrameworkError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FrameworkError("cfg root must be a JSON object")

    repo_root = Path(__file__).resolve().parent.parent
    configured_run_id = data.get("run_id")
    if configured_run_id is not None and not isinstance(configured_run_id, str):
        raise FrameworkError("cfg 'run_id' must be a string")
    run_id = configured_run_id or datetime.now().strftime("run-%Y%m%d-%H%M%S")
    if not SAFE_NAME.fullmatch(run_id):
        raise FrameworkError("cfg 'run_id' contains unsafe characters")
    if not run_id.startswith("run-"):
        run_id = f"run-{run_id}"
    try:
        poll_seconds = float(data.get("poll_seconds", 5))
    except (TypeError, ValueError) as exc:
        raise FrameworkError("cfg 'poll_seconds' must be a number") from exc
    if poll_seconds <= 0:
        raise FrameworkError("cfg 'poll_seconds' must be positive")

    paths = _required_mapping(data, "paths")
    experiment = _required_mapping(data, "experiment")
    runtime = _required_mapping(data, "runtime")
    storage = _required_mapping(data, "storage")
    worker = _required_mapping(data, "worker")
    evaluator = _required_mapping(data, "evaluator")
    tmux_session = data.get("tmux_session") or run_id
    if not isinstance(tmux_session, str):
        raise FrameworkError("cfg 'tmux_session' must be a string")
    cfg = RunnerConfig(
        run_id=run_id,
        llm_host=normalize_host(data.get("llm_host", "")),
        llm_models=_model_list(data),
        crs_names=_string_list(data, "crses"),
        benchmark_names=_string_list(data, "benchmarks"),
        benchmarks_dir=_configured_path(
            paths, "benchmarks", "benchmarks", repo_root
        ),
        suites_dir=_configured_path(
            paths, "benchmark_suites", "benchmark-suites", repo_root
        ),
        registry_dir=_configured_path(
            paths, "crs_registry", "oss-crs/registry", repo_root
        ),
        results_dir=_configured_path(paths, "results", "results", repo_root),
        crs_env_file=_configured_path(
            paths, "crs_env", "framework/cfg_crs_env.yaml", repo_root
        ),
        tmux_session=tmux_session,
        poll_seconds=poll_seconds,
        experiment=experiment,
        runtime=runtime,
        storage=storage,
        worker=worker,
        evaluator=evaluator,
    )
    if not SAFE_NAME.fullmatch(cfg.tmux_session):
        raise FrameworkError("cfg 'tmux_session' contains unsafe characters")
    for label, required in (
        ("benchmarks", cfg.benchmarks_dir),
        ("benchmark suites", cfg.suites_dir),
        ("CRS registry", cfg.registry_dir),
        ("CRS environment config", cfg.crs_env_file),
    ):
        if not required.exists():
            raise FrameworkError(f"{label} path does not exist: {required}")
    return cfg


def load_crs_env(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise FrameworkError(
            f"cannot read CRS environment config {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise FrameworkError("CRS environment config must contain a mapping")
    entries = data.get("crses", data)
    if not isinstance(entries, dict):
        raise FrameworkError("CRS environment config must contain a 'crses' mapping")
    return entries
