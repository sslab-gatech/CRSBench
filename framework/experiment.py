"""Render and archive experiments from the framework template."""

from __future__ import annotations

import copy
import json
import logging  # noqa: TID251 - standalone wrapper uses stdlib logging
import shutil
from typing import TYPE_CHECKING, Any

import yaml

from framework.errors import FrameworkError

if TYPE_CHECKING:
    from pathlib import Path

    from framework.cleanup import Manifest
    from framework.config import RunnerConfig
    from framework.crs import CRSVariant

log = logging.getLogger(__name__)
SERVICE_DEFAULTS_KEY = "_generated_service_defaults"
DISCVER_MIN_RESERVE = 3600


def _load_yaml(path: Path, description: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise FrameworkError(f"{description} does not exist: {path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise FrameworkError(f"cannot read {description} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FrameworkError(f"{description} must contain a mapping")
    return data


def _validate_rendered(rendered: str, description: str) -> None:
    try:
        from crsbench.validation.format_validator import (
            validate_experiment_config_from_string,
        )

        validation = validate_experiment_config_from_string(rendered)
    except Exception as exc:
        raise FrameworkError(f"{description} validation could not run: {exc}") from exc
    if not validation.is_valid:
        messages = "; ".join(str(error) for error in validation.errors)
        raise FrameworkError(f"{description} is invalid: {messages}")


def _positive_int(value: object, label: str) -> int:
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise FrameworkError(f"{label} must be a positive integer") from exc
    if result <= 0 or isinstance(value, bool):
        raise FrameworkError(f"{label} must be a positive integer")
    return result


def validate_discver_timeout(data: dict[str, Any], variants: list[CRSVariant]) -> None:
    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        raise FrameworkError("experiment template is missing runtime")
    run_timeout = _positive_int(runtime.get("run_timeout"), "runtime.run_timeout")
    for variant in variants:
        if variant.base_name != "discver":
            continue
        raw = variant.additional_env.get("FUZZ_TIMEOUT")
        if raw is None:
            raise FrameworkError(f"{variant.name} requires FUZZ_TIMEOUT")
        fuzz_timeout = _positive_int(raw, f"{variant.name} FUZZ_TIMEOUT")
        reserve = run_timeout - fuzz_timeout
        if reserve < DISCVER_MIN_RESERVE:
            raise FrameworkError(
                f"{variant.name} FUZZ_TIMEOUT leaves {reserve}s before run_timeout; "
                f"at least {DISCVER_MIN_RESERVE}s is required"
            )
        log.info(
            "DiscVer timeout budget for %s: run=%ds fuzz=%ds gross reserve=%ds",
            variant.name,
            run_timeout,
            fuzz_timeout,
            reserve,
        )


def render_experiment(
    cfg: RunnerConfig, suite: str, variants: list[CRSVariant]
) -> tuple[dict[str, Any], str]:
    data = copy.deepcopy(_load_yaml(cfg.experiment_template, "experiment template"))
    experiment = data.get("experiment")
    runtime = data.get("runtime")
    storage = data.get("storage")
    compose = data.get("crs_compose")
    if not all(
        isinstance(section, dict) for section in (experiment, runtime, storage, compose)
    ):
        raise FrameworkError(
            "experiment template requires experiment, runtime, storage, and crs_compose mappings"
        )

    experiment["name"] = cfg.run_id
    experiment["benchmark_suite"] = suite
    experiment.pop("benchmarks", None)
    storage["experiment_filestore"] = str(cfg.experiment_data_dir)
    storage["report_filestore"] = str(cfg.report_data_dir)

    service_defaults = compose.pop(SERVICE_DEFAULTS_KEY, None)
    if not isinstance(service_defaults, dict):
        raise FrameworkError(
            f"experiment template crs_compose.{SERVICE_DEFAULTS_KEY} must be a mapping"
        )
    for variant in variants:
        service = copy.deepcopy(service_defaults)
        if variant.additional_env:
            service["additional_env"] = variant.additional_env
        else:
            service.pop("additional_env", None)
        compose[variant.name] = service

    validate_discver_timeout(data, variants)
    rendered = yaml.safe_dump(data, sort_keys=False)
    _validate_rendered(rendered, "generated experiment")
    return data, rendered


def write_experiment(
    cfg: RunnerConfig,
    repo_root: Path,
    suite: str,
    variants: list[CRSVariant],
    manifest: Manifest,
) -> Path:
    _data, rendered = render_experiment(cfg, suite, variants)
    generated = repo_root / f"experiment-{cfg.run_id}.yaml"
    if generated.exists():
        raise FrameworkError(f"refusing to overwrite experiment file: {generated}")
    generated.write_text(rendered, encoding="utf-8")
    manifest.add(generated)
    return generated


def archive_experiment(
    cfg: RunnerConfig,
    experiment_yaml: Path,
    suite: str,
    variants: list[CRSVariant],
) -> Path:
    if cfg.run_dir.exists():
        raise FrameworkError(f"run output directory already exists: {cfg.run_dir}")
    cfg.run_dir.mkdir(parents=True, exist_ok=False)
    archived = cfg.run_dir / "experiment.yaml"
    try:
        shutil.copy2(experiment_yaml, archived)
        support_dir = cfg.run_dir / "support"
        registry_archive = support_dir / "registry"
        registry_archive.mkdir(parents=True)
        shutil.copy2(
            cfg.suites_dir / f"{suite}.yaml", support_dir / "benchmark-suite.yaml"
        )
        for variant in variants:
            shutil.copy2(
                cfg.registry_dir / f"{variant.name}.yaml",
                registry_archive / f"{variant.name}.yaml",
            )
        (support_dir / "framework.json").write_text(
            json.dumps(
                {"llm_host": cfg.llm_host, "models": list(cfg.llm_models)}, indent=2
            )
            + "\n",
            encoding="utf-8",
        )
        (support_dir / "queue-model.txt").write_text("flat\n", encoding="utf-8")
    except OSError:
        shutil.rmtree(cfg.run_dir, ignore_errors=True)
        raise
    return archived


def load_experiment(path: Path) -> dict[str, Any]:
    data = _load_yaml(path, "retry experiment")
    _validate_rendered(path.read_text(encoding="utf-8"), "retry experiment")
    return data
