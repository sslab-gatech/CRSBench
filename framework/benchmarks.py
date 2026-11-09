"""Benchmark checks and per-run suite creation."""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING

import yaml

from framework.errors import FrameworkError

if TYPE_CHECKING:
    from pathlib import Path

    from framework.cleanup import Manifest
    from framework.config import RunnerConfig


def check_benchmarks(cfg: RunnerConfig, repo_root: Path) -> None:
    del repo_root
    errors: list[str] = []
    for name in cfg.benchmark_names:
        root = cfg.benchmarks_dir / name
        if not root.is_dir():
            errors.append(f"missing benchmark directory: {root}")
        elif not (root / ".aixcc" / "meta.yaml").is_file():
            errors.append(f"missing benchmark metadata: {root / '.aixcc/meta.yaml'}")
        elif not (root / "project.yaml").is_file():
            errors.append(f"missing benchmark project file: {root / 'project.yaml'}")
    if errors:
        raise FrameworkError("; ".join(errors))


def write_suite(cfg: RunnerConfig, repo_root: Path, manifest: Manifest) -> str:
    del repo_root
    custom_dir = cfg.suites_dir / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    suite_path = custom_dir / f"{cfg.run_id}.yaml"
    if suite_path.exists():
        raise FrameworkError(f"refusing to overwrite benchmark suite: {suite_path}")
    payload = {
        "Name": cfg.run_id,
        "Description": f"Generated benchmark suite for {cfg.run_id}",
        # BenchmarkSuiteConfig requires a non-empty MM.DD.YYYY release date.
        "Release date": date.today().strftime("%m.%d.%Y"),
        "benchmark_list": list(cfg.benchmark_names),
    }
    suite_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    manifest.add(suite_path)
    return f"custom/{cfg.run_id}"
