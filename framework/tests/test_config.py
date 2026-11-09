"""Tests for the minimal framework configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from framework.config import load_config
from framework.errors import FrameworkError

if TYPE_CHECKING:
    from pathlib import Path


def _config(tmp_path: Path, **updates: object) -> Path:
    data: dict[str, object] = {
        "llm_host": "http://localhost:4000",
        "models": ["model-a"],
        "crses": ["discver"],
        "benchmarks": ["benchmark-a"],
        "storage": str(tmp_path / "results"),
    }
    data.update(updates)
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_minimal_config(tmp_path: Path) -> None:
    cfg = load_config(_config(tmp_path))
    assert cfg.llm_models == ("model-a",)
    assert cfg.crs_names == ("discver",)
    assert cfg.results_dir == (tmp_path / "results").resolve()
    assert cfg.experiment_template.name == "experiment-template.yaml"


def test_unknown_config_field_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FrameworkError, match="unknown fields: runtime"):
        load_config(_config(tmp_path, runtime={}))


def test_duplicate_models_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(FrameworkError, match="models.*duplicates"):
        load_config(_config(tmp_path, models=["model-a", "model-a"]))
