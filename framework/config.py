"""Load and validate the minimal framework configuration."""

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
CONFIG_KEYS = {"llm_host", "models", "crses", "benchmarks", "storage"}


def normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise FrameworkError("cfg 'llm_host' must be a string")
    host = value.strip().rstrip("/")
    if host.endswith("/v1"):
        host = host[:-3]
    if not host.startswith(("http://", "https://")):
        raise FrameworkError("LLM host must begin with http:// or https://")
    return host


def _path(value: object, repo_root: Path, key: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"cfg '{key}' must be a non-empty path")
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def _name_list(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
    ):
        raise FrameworkError(f"cfg '{key}' must be a non-empty list of strings")
    result = tuple(item.strip() for item in value)
    if any(not item or not SAFE_NAME.fullmatch(item) for item in result):
        raise FrameworkError(f"cfg '{key}' contains an unsafe or empty name")
    if len(result) != len(set(result)):
        raise FrameworkError(f"cfg '{key}' contains duplicates")
    return result


def _model_list(data: dict[str, Any]) -> tuple[str, ...]:
    value = data.get("models")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
    ):
        raise FrameworkError("cfg 'models' must be a non-empty list of strings")
    result = tuple(item.strip() for item in value)
    if any(not item or any(char.isspace() for char in item) for item in result):
        raise FrameworkError("cfg 'models' contains an empty model or whitespace")
    if len(result) != len(set(result)):
        raise FrameworkError("cfg 'models' contains duplicates")
    return result


@dataclass(frozen=True)
class RunnerConfig:
    run_id: str
    llm_host: str
    llm_models: tuple[str, ...]
    crs_names: tuple[str, ...]
    benchmark_names: tuple[str, ...]
    results_dir: Path
    benchmarks_dir: Path
    suites_dir: Path
    registry_dir: Path
    crs_env_file: Path
    experiment_template: Path
    tmux_session: str
    poll_seconds: float = 5.0

    @property
    def run_dir(self) -> Path:
        return self.results_dir / "framework-runs" / self.run_id.removeprefix("run-")

    @property
    def logs_dir(self) -> Path:
        return self.run_dir / "logs"

    @property
    def experiment_data_dir(self) -> Path:
        return self.results_dir / "experiment-data"

    @property
    def report_data_dir(self) -> Path:
        return self.results_dir / "report-data"


def load_config(path: Path) -> RunnerConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"config does not exist: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise FrameworkError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FrameworkError("cfg root must be a JSON object")
    unknown = sorted(set(data) - CONFIG_KEYS)
    if unknown:
        raise FrameworkError(f"cfg contains unknown fields: {', '.join(unknown)}")

    repo_root = Path(__file__).resolve().parent.parent
    run_id = datetime.now().strftime("run-%Y%m%d-%H%M%S-%f")
    cfg = RunnerConfig(
        run_id=run_id,
        llm_host=normalize_host(data.get("llm_host", "")),
        llm_models=_model_list(data),
        crs_names=_name_list(data, "crses"),
        benchmark_names=_name_list(data, "benchmarks"),
        results_dir=_path(data.get("storage"), repo_root, "storage"),
        benchmarks_dir=(repo_root / "benchmarks").resolve(),
        suites_dir=(repo_root / "benchmark-suites").resolve(),
        registry_dir=(repo_root / "oss-crs" / "registry").resolve(),
        crs_env_file=(repo_root / "framework" / "cfg_crs_env.yaml").resolve(),
        experiment_template=(
            repo_root / "framework" / "experiment-template.yaml"
        ).resolve(),
        tmux_session=run_id,
    )
    for label, required in (
        ("benchmarks", cfg.benchmarks_dir),
        ("benchmark suites", cfg.suites_dir),
        ("CRS registry", cfg.registry_dir),
        ("CRS environment config", cfg.crs_env_file),
        ("experiment template", cfg.experiment_template),
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
    if not isinstance(data, dict) or set(data) != {"crses"}:
        raise FrameworkError(
            "CRS environment config must contain only a 'crses' mapping"
        )
    entries = data["crses"]
    if not isinstance(entries, dict):
        raise FrameworkError("CRS environment config 'crses' must be a mapping")
    return entries
