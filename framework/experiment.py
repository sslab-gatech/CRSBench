"""Render a validated experiment directly from framework configuration."""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import yaml

from framework.cleanup import Manifest
from framework.config import RunnerConfig
from framework.crs import CRSVariant
from framework.errors import FrameworkError


def get_run_timeout(runtime: dict[str, object]) -> int:
    """Return runtime.run_timeout for CRS settings coupled to the trial budget."""
    run_timeout = runtime.get("run_timeout")
    if not isinstance(run_timeout, int) or isinstance(run_timeout, bool):
        raise FrameworkError("cfg 'runtime.run_timeout' must be an integer")
    if run_timeout <= 0:
        raise FrameworkError("cfg 'runtime.run_timeout' must be positive")
    return run_timeout


def write_experiment(
    cfg: RunnerConfig,
    repo_root: Path,
    suite: str,
    variants: list[CRSVariant],
    manifest: Manifest,
    *,
    archive: bool = True,
) -> Path:
    # Start from the complete user configuration and inject only values that are
    # generated for this invocation. This avoids an external template dependency.
    data = {
        "experiment": copy.deepcopy(cfg.experiment),
        "runtime": copy.deepcopy(cfg.runtime),
        "storage": copy.deepcopy(cfg.storage),
        "worker": copy.deepcopy(cfg.worker),
        "evaluator": copy.deepcopy(cfg.evaluator),
    }
    experiment = data["experiment"]
    storage = data["storage"]
    experiment["name"] = cfg.run_id
    experiment["benchmark_suite"] = suite
    experiment.pop("benchmarks", None)
    storage["experiment_filestore"] = str(
        cfg.results_dir / "experiment-data"
    )
    storage["report_filestore"] = str(cfg.results_dir / "report-data")

    data["crs_compose"] = {
        variant.name: variant.compose for variant in variants
    }

    rendered = yaml.safe_dump(data, sort_keys=False)
    try:
        from crsbench.validation.format_validator import (
            validate_experiment_config_from_string,
        )

        validation = validate_experiment_config_from_string(rendered)
    except Exception as exc:
        raise FrameworkError(f"experiment validation could not run: {exc}") from exc
    if not validation.is_valid:
        messages = "; ".join(str(error) for error in validation.errors)
        raise FrameworkError(f"generated experiment is invalid: {messages}")

    if archive and cfg.run_dir.exists():
        raise FrameworkError(f"run output directory already exists: {cfg.run_dir}")

    generated = repo_root / f"experiment-{cfg.run_id}.yaml"
    if generated.exists():
        raise FrameworkError(f"refusing to overwrite experiment file: {generated}")
    generated.write_text(rendered, encoding="utf-8")
    manifest.add(generated)

    if archive:
        cfg.run_dir.mkdir(parents=True, exist_ok=False)
        archived = cfg.run_dir / "experiment.yaml"
        try:
            shutil.copy2(generated, archived)
            support_dir = cfg.run_dir / "support"
            registry_archive = support_dir / "registry"
            registry_archive.mkdir(parents=True)
            suite_path = cfg.suites_dir / f"{suite}.yaml"
            shutil.copy2(suite_path, support_dir / "benchmark-suite.yaml")
            for variant in variants:
                source = cfg.registry_dir / f"{variant.name}.yaml"
                destination = registry_archive / f"{variant.name}.yaml"
                shutil.copy2(source, destination)
        except OSError:
            shutil.rmtree(cfg.run_dir, ignore_errors=True)
            raise
    return generated


def load_experiment(path: Path) -> dict:
    """Load and schema-validate an existing experiment YAML for retry."""
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
    except FileNotFoundError as exc:
        raise FrameworkError(f"retry experiment does not exist: {path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise FrameworkError(f"cannot read retry experiment {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FrameworkError("retry experiment YAML must contain a mapping")
    try:
        from crsbench.validation.format_validator import (
            validate_experiment_config_from_string,
        )

        validation = validate_experiment_config_from_string(text)
    except Exception as exc:
        raise FrameworkError(
            f"retry experiment validation could not run: {exc}"
        ) from exc
    if not validation.is_valid:
        messages = "; ".join(str(error) for error in validation.errors)
        raise FrameworkError(f"retry experiment is invalid: {messages}")
    return data
