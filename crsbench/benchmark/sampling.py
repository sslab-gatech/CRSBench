"""Outcome-independent, balanced sampling of benchmark IDs by language and mode."""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from crsbench.utils.logger import get_logger
from crsbench.validation.schemas import (
    BenchmarkConfig,
    BenchmarkSuiteConfig,
    ProjectConfig,
)

if TYPE_CHECKING:
    import argparse

STRATA = ("c/delta", "c/full", "jvm/delta", "jvm/full")
logger = get_logger(__name__)


def sample_benchmarks(
    source_suite: Path, benchmarks_root: Path, *, seed: int, per_stratum: int
) -> tuple[list[str], dict]:
    """Sample whole benchmarks; read metadata only, never experiment outcomes.

    Mode matches experiment.mode=auto: prefer delta when supported, else full.
    Missing or incompatible metadata is an error, never a silent exclusion.
    """
    if per_stratum < 1:
        raise ValueError("per_stratum must be positive")
    suite_bytes = source_suite.read_bytes()
    suite = BenchmarkSuiteConfig.model_validate(yaml.safe_load(suite_bytes))
    if any(not isinstance(item, str) for item in suite.benchmark_list):
        raise ValueError("Source suite must contain whole benchmark IDs, not selectors")

    population: dict[str, list[str]] = {stratum: [] for stratum in STRATA}
    fingerprints = []
    for name in sorted(suite.get_benchmark_names()):
        if Path(name).name != name or name in (".", ".."):
            raise ValueError(f"Invalid benchmark ID: {name}")
        root = benchmarks_root / name
        project_bytes = (root / "project.yaml").read_bytes()
        meta_bytes = (root / ".aixcc" / "meta.yaml").read_bytes()
        project = ProjectConfig.model_validate(yaml.safe_load(project_bytes))
        meta = BenchmarkConfig.model_validate(yaml.safe_load(meta_bytes))
        language = {"c": "c", "c++": "c", "jvm": "jvm", "java": "jvm"}.get(
            project.language
        )
        if language is None:
            raise ValueError(f"{name}: unsupported language {project.language!r}")
        if not any(harness.vulns for harness in meta.harness_files):
            raise ValueError(
                f"{name}: no ground-truth CPVs; cannot sample for evaluation"
            )
        mode = "delta" if meta.delta_mode else "full"
        population[f"{language}/{mode}"].append(name)
        fingerprints.append(
            [
                name,
                hashlib.sha256(project_bytes).hexdigest(),
                hashlib.sha256(meta_bytes).hexdigest(),
            ]
        )

    rng = random.Random(seed)
    strata = {}
    selected = []
    for stratum in STRATA:
        members = population[stratum]
        if len(members) < per_stratum:
            raise ValueError(
                f"{stratum}: requested {per_stratum}, but population has {len(members)}"
            )
        draw = sorted(rng.sample(members, per_stratum))
        selected.extend(draw)
        strata[stratum] = {
            "population_size": len(members),
            "sample_size": len(draw),
            "population": members,
            "selected": draw,
        }

    manifest = {
        "schema_version": 1,
        "method": "balanced stratified random sampling without replacement",
        "sampling_unit": "benchmark ID (all ground-truth harnesses and CPVs)",
        "algorithm": "Python random.Random(seed).sample on sorted IDs in STRATA order",
        "seed": seed,
        "per_stratum": per_stratum,
        "mode_policy": "auto: delta if supported, otherwise full",
        "source_suite_name": suite.Name,
        "source_suite_sha256": hashlib.sha256(suite_bytes).hexdigest(),
        "metadata_sha256": hashlib.sha256(
            json.dumps(fingerprints, separators=(",", ":")).encode()
        ).hexdigest(),
        "population_size": sum(len(members) for members in population.values()),
        "sample_size": len(selected),
        "exclusions": [],
        "strata": strata,
    }
    return selected, manifest


def add_sample_subparser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "sample", help="Sample whole benchmarks independently of CRS outcomes"
    )
    parser.add_argument(
        "--source-suite", type=Path, default=Path("benchmark-suites/crsbench/all.yaml")
    )
    parser.add_argument("--benchmarks-root", type=Path, default=Path("benchmarks"))
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--per-stratum", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Output suite YAML")
    parser.add_argument(
        "--manifest", type=Path, required=True, help="Output audit JSON"
    )
    parser.add_argument("--name", required=True, help="Generated suite name")
    parser.add_argument(
        "--release-date", required=True, help="Suite release date (MM.DD.YYYY)"
    )
    parser.add_argument("--force", action="store_true", help="Replace existing outputs")
    parser.set_defaults(func=run_sample)


def run_sample(args: argparse.Namespace) -> int:
    try:
        datetime.strptime(args.release_date, "%m.%d.%Y")
        if args.output.resolve() == args.manifest.resolve():
            raise ValueError("Suite and manifest must use different output paths")
        if args.source_suite.resolve() in {
            args.output.resolve(),
            args.manifest.resolve(),
        }:
            raise ValueError("Outputs must not overwrite the source population suite")
        if not args.force:
            for output in (args.output, args.manifest):
                if output.exists():
                    raise ValueError(f"Output already exists: {output}; use --force")
        selected, manifest = sample_benchmarks(
            args.source_suite,
            args.benchmarks_root,
            seed=args.seed,
            per_stratum=args.per_stratum,
        )
        suite = BenchmarkSuiteConfig.model_validate(
            {
                "Name": args.name,
                "Description": (
                    f"Balanced random sample: {args.per_stratum} benchmarks per "
                    f"language/mode stratum; seed {args.seed}; independent of CRS outcomes."
                ),
                "Release date": args.release_date,
                "benchmark_list": selected,
            }
        )
        manifest["output_suite_name"] = args.name
        manifest["release_date"] = args.release_date
        for output in (args.output, args.manifest):
            output.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if args.force else "x"
        with args.output.open(mode, encoding="utf-8") as stream:
            yaml.safe_dump(suite.model_dump(by_alias=True), stream, sort_keys=False)
        with args.manifest.open(mode, encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.error("Sampling failed: {}", exc)
        return 1
    logger.info(
        "Sampled {} of {} benchmarks", len(selected), manifest["population_size"]
    )
    for stratum, details in manifest["strata"].items():
        logger.info(
            "  {}: {} / {}", stratum, details["sample_size"], details["population_size"]
        )
    logger.info("Suite: {}\nManifest: {}", args.output, args.manifest)
    return 0
