"""Tests for generic CRS expansion and experiment template rendering."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from framework.cleanup import Manifest
from framework.config import RunnerConfig
from framework.crs import CRSVariant, _render, prepare_variants
from framework.errors import FrameworkError
from framework.experiment import render_experiment, validate_discver_timeout


def _runner(tmp_path: Path, *, models: tuple[str, ...] = ("model-a",)) -> RunnerConfig:
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "discver.yaml").write_text(
        "name: discver\ntype: [bug-finding]\n", encoding="utf-8"
    )
    env_file = tmp_path / "crs.yaml"
    env_file.write_text(
        "crses:\n  discver:\n    additional_env:\n"
        "      DISCVER_LLM_MODEL: '{model}'\n"
        "      DISCVER_LLM_URL: '{llm_host}/v1'\n"
        "      FUZZ_TIMEOUT: '7000'\n",
        encoding="utf-8",
    )
    return RunnerConfig(
        run_id="run-test",
        llm_host="http://llm.test",
        llm_models=models,
        crs_names=("discver",),
        benchmark_names=("benchmark",),
        results_dir=tmp_path / "results",
        benchmarks_dir=tmp_path / "benchmarks",
        suites_dir=tmp_path / "suites",
        registry_dir=registry,
        crs_env_file=env_file,
        experiment_template=Path("framework/experiment-template.yaml").resolve(),
        tmux_session="run-test",
    )


def test_crs_variants_expand_models(tmp_path: Path) -> None:
    cfg = _runner(tmp_path, models=("model-a", "model-b"))
    variants = prepare_variants(cfg, Path("/repo"), Manifest())
    assert [variant.name for variant in variants] == [
        "discver-model-a",
        "discver-model-b",
    ]
    assert variants[0].additional_env["DISCVER_LLM_URL"] == "http://llm.test/v1"


def test_identical_existing_registry_variant_is_reused(tmp_path: Path) -> None:
    cfg = _runner(tmp_path)
    existing = cfg.registry_dir / "discver-model-a.yaml"
    existing.write_text(
        "name: discver-model-a\ntype: [bug-finding]\n", encoding="utf-8"
    )
    manifest = Manifest()
    prepare_variants(cfg, Path("/repo"), manifest)
    assert existing.resolve() not in manifest.paths


def test_unknown_environment_placeholder_is_rejected() -> None:
    with pytest.raises(FrameworkError, match="unknown CRS environment placeholder"):
        _render("{timeout}", model="m", host="http://host", repo_root=Path("/repo"))


def test_template_rendering_injects_generated_values(tmp_path: Path) -> None:
    cfg = _runner(tmp_path)
    variants = prepare_variants(cfg, Path("/repo"), Manifest())
    data, rendered = render_experiment(cfg, "custom/run-test", variants)
    assert data["experiment"]["name"] == "run-test"
    assert data["storage"]["experiment_filestore"] == str(cfg.experiment_data_dir)
    assert data["crs_compose"]["discver-model-a"]["num_cores"] == 8
    assert "_generated_service_defaults" not in rendered
    assert (
        yaml.safe_load(cfg.experiment_template.read_text())["experiment"]["name"]
        == "generated"
    )


def test_discver_requires_completion_reserve() -> None:
    data = {"runtime": {"run_timeout": 10000}}
    variants = [CRSVariant("discver-model", "discver", {"FUZZ_TIMEOUT": "7000"})]
    with pytest.raises(FrameworkError, match="at least 3600s"):
        validate_discver_timeout(data, variants)


def test_discver_requires_fuzz_timeout() -> None:
    data = {"runtime": {"run_timeout": 12800}}
    variants = [CRSVariant("discver-model", "discver", {})]
    with pytest.raises(FrameworkError, match="requires FUZZ_TIMEOUT"):
        validate_discver_timeout(data, variants)


def test_non_discver_has_no_timeout_requirement() -> None:
    data = {"runtime": {"run_timeout": 10}}
    variants = [CRSVariant("claude-model", "crs-bug-finding-claude-code", {})]
    validate_discver_timeout(data, variants)


def test_generic_claude_environment_is_rendered(tmp_path: Path) -> None:
    cfg = _runner(tmp_path)
    (cfg.registry_dir / "claude.yaml").write_text(
        "name: claude\ntype: [bug-finding]\n", encoding="utf-8"
    )
    cfg.crs_env_file.write_text(
        "crses:\n  claude:\n    additional_env:\n"
        "      ANTHROPIC_MODEL: '{model}'\n"
        "      CRS_AGENT: claude_code\n",
        encoding="utf-8",
    )
    cfg = replace(cfg, crs_names=("claude",))
    variants = prepare_variants(cfg, Path("/repo"), Manifest())
    assert variants[0].additional_env == {
        "ANTHROPIC_MODEL": "model-a",
        "CRS_AGENT": "claude_code",
    }
