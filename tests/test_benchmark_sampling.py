"""Sampling reproducibility and the ICSE cloud experiment contracts."""

import argparse
import json
from collections import Counter
from pathlib import Path

import pytest
import yaml
from crsbench.benchmark.sampling import (
    STRATA,
    add_sample_subparser,
    run_sample,
    sample_benchmarks,
)
from crsbench.cloud.models import build_cloud_launch_plan
from crsbench.run_experiment import generate_trial_matrix, resolve_benchmark_harnesses
from crsbench.validation.schemas import BenchmarkSuiteConfig, ExperimentConfig

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def population(tmp_path):
    root = tmp_path / "benchmarks"
    names = []
    for language in ("c++", "jvm"):
        for mode in ("delta", "full"):
            for index in range(3):
                name = f"{language}-{mode}-{index}"
                names.append(name)
                path = root / name
                (path / ".aixcc").mkdir(parents=True)
                (path / "project.yaml").write_text(
                    yaml.safe_dump({"language": language})
                )
                meta = {
                    "full_mode": {"base_commit": "a" * 40},
                    "harness_files": [
                        {
                            "name": "fuzz",
                            "path": "$PROJECT/fuzz",
                            "vulns": [
                                {
                                    "vuln_keyword": "cpv_0",
                                    "povs": [{"id": "pov_0", "sanitizer": "address"}],
                                }
                            ],
                        }
                    ],
                }
                if mode == "delta":
                    meta["delta_mode"] = {
                        "base_commit": "a" * 40,
                        "ref_commit": "b" * 40,
                    }
                (path / ".aixcc/meta.yaml").write_text(yaml.safe_dump(meta))
    source = tmp_path / "all.yaml"
    source.write_text(
        yaml.safe_dump(
            {
                "Name": "all",
                "Description": "Complete fixture population",
                "Release date": "11.04.2026",
                "benchmark_list": names,
            }
        )
    )
    return source, root


def test_balanced_sample_includes_whole_benchmarks_and_is_reproducible(population):
    source, root = population
    first, audit = sample_benchmarks(source, root, seed=42, per_stratum=2)
    assert len(first) == len(set(first)) == 8
    assert audit["population_size"] == 12
    assert audit["exclusions"] == []
    assert list(audit["strata"]) == list(STRATA)
    for stratum in audit["strata"].values():
        assert stratum["population_size"] == 3
        assert len(stratum["selected"]) == 2
        assert set(stratum["selected"]) <= set(stratum["population"])

    # Results files, unrelated directories and source-suite ordering cannot
    # influence the draw. This also tests dual-mode metadata with auto mode.
    for path in root.iterdir():
        (path / "standalone-results.json").write_text('{"success": false}')
    (root / "not-in-the-population").mkdir()
    data = yaml.safe_load(source.read_text())
    data["benchmark_list"].reverse()
    source.write_text(yaml.safe_dump(data))
    again, other_audit = sample_benchmarks(source, root, seed=42, per_stratum=2)
    assert again == first
    assert other_audit["strata"] == audit["strata"]
    assert other_audit["metadata_sha256"] == audit["metadata_sha256"]
    different, _ = sample_benchmarks(source, root, seed=43, per_stratum=2)
    assert different != first


def test_sample_entire_stratum_and_reject_insufficient_size(population):
    source, root = population
    selected, _ = sample_benchmarks(source, root, seed=1, per_stratum=3)
    assert set(selected) == set(yaml.safe_load(source.read_text())["benchmark_list"])
    with pytest.raises(ValueError, match="population has 3"):
        sample_benchmarks(source, root, seed=1, per_stratum=4)
    with pytest.raises(ValueError, match="positive"):
        sample_benchmarks(source, root, seed=1, per_stratum=0)


def test_missing_metadata_aborts_instead_of_changing_population(population):
    source, root = population
    next(root.glob("*/project.yaml")).unlink()
    with pytest.raises(FileNotFoundError):
        sample_benchmarks(source, root, seed=42, per_stratum=1)


def test_source_cannot_filter_harnesses_or_cpvs(population):
    source, root = population
    data = yaml.safe_load(source.read_text())
    data["benchmark_list"][0] = {data["benchmark_list"][0]: ["fuzz"]}
    source.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="whole benchmark IDs"):
        sample_benchmarks(source, root, seed=1, per_stratum=1)


def test_sample_command_writes_valid_suite_and_protects_existing_draw(
    population, tmp_path
):
    source, root = population
    parser = argparse.ArgumentParser()
    add_sample_subparser(parser.add_subparsers())
    output = tmp_path / "sample.yaml"
    manifest = tmp_path / "audit.json"
    args = parser.parse_args(
        [
            "sample",
            "--source-suite",
            str(source),
            "--benchmarks-root",
            str(root),
            "--seed",
            "42",
            "--per-stratum",
            "1",
            "--output",
            str(output),
            "--manifest",
            str(manifest),
            "--name",
            "sample",
            "--release-date",
            "11.04.2026",
        ]
    )
    assert args.func(args) == 0
    suite = BenchmarkSuiteConfig.model_validate(yaml.safe_load(output.read_text()))
    assert len(suite.get_benchmark_names()) == 4
    original = manifest.read_bytes()
    args.seed = 2
    assert run_sample(args) == 1
    assert manifest.read_bytes() == original
    args.force = True
    assert run_sample(args) == 0
    assert json.loads(manifest.read_text())["seed"] == 2


def test_frozen_icse_sample_reproduces_from_complete_population():
    selected, manifest = sample_benchmarks(
        REPO / "benchmark-suites/crsbench/all.yaml",
        REPO / "benchmarks",
        seed=20261104,
        per_stratum=7,
    )
    suite = yaml.safe_load(
        (REPO / "benchmark-suites/icse/hybrid-random.yaml").read_text()
    )
    assert suite["benchmark_list"] == selected
    manifest["output_suite_name"] = suite["Name"]
    manifest["release_date"] = suite["Release date"]
    assert manifest == json.loads(
        (REPO / "experiment-configs/icse/hybrid-random-sampling.json").read_text()
    )


@pytest.mark.parametrize("kind,expected_jobs", [("finding", 171), ("smoke", 4)])
def test_icse_configs_expand_to_hybrid_only_cloud_jobs(
    kind, expected_jobs, monkeypatch
):
    monkeypatch.chdir(REPO)
    config = ExperimentConfig.model_validate(
        yaml.safe_load(
            (
                REPO / f"experiment-configs/icse/gce-sample-hybrid-random-{kind}.yaml"
            ).read_text()
        )
    )
    entries = config.get_benchmark_entries()
    harnesses = resolve_benchmark_harnesses(entries, config.benchmarks_root)
    trials = generate_trial_matrix(
        harnesses, config.get_crs_registry_ids(), config, config.registry_dir
    )
    assert len(trials) == expected_jobs
    assert {trial.crs for trial in trials} == {"crs-sample-hybrid"}
    assert config.litellm_mode == "external"
    assert config.cloud.env["CRSBENCH_TAILSCALE_AUTH_KEY"] == (
        "os.environ/CRSBENCH_TAILSCALE_AUTH_KEY"
    )
    assert config.cloud.env["CRSBENCH_LLM_UPSTREAM_BASE_URL"] == (
        "os.environ/CRSBENCH_LLM_UPSTREAM_BASE_URL"
    )
    plan = build_cloud_launch_plan(config)
    assert plan.orchestrator.provider.value == "gce"
    if kind == "smoke":
        assert len(entries) == 4
        assert Counter(t.mode for t in trials) == {"delta": 2, "full": 2}
        assert config.trials == 1
        assert config.run_timeout == 600
        assert len(plan.worker_placements) == len(plan.evaluator_placements) == 1
    else:
        assert len(entries) == 28
        assert config.trials == 3
        assert config.run_timeout == 28800
        assert sum(t.sanitizer == "memory" for t in trials) == 3
