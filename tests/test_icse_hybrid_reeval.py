"""Collection-to-re-evaluation isolation, completeness and timeline regressions."""

import json
import os
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from crsbench.evaluation.reeval.cli import _reeval_bug_finding, _resolve_experiment_dir
from crsbench.evaluation.verification.models import (
    PovVerificationResult,
    PovVerificationStatus,
)
from scripts.icse_hybrid_reeval import (
    audit,
    finalize,
    prepare,
    sha256,
    verify,
    write_json,
)


@pytest.fixture
def collection(tmp_path):
    matrix = {
        "crs": "hybrid",
        "benchmark": "project",
        "harness": "fuzz",
        "mode": "delta",
        "sanitizer": "address",
        "trial_num": 1,
    }
    record = {
        "key": "hybrid:project:fuzz:delta:address:1:-",
        "matrix": matrix,
        "relative_path": "hybrid/project/fuzz/delta/address/trial-1",
    }
    plan = {
        "experiment": "study",
        "total_trials": 1,
        "batches": {
            "first": {"experiment": "study-first", "trials": [record]},
            "remaining": {"experiment": "study-remaining", "trials": []},
        },
    }
    root = tmp_path / "raw" / "study-first" / "study-first"
    path = root / record["relative_path"]
    (path / "output/povs").mkdir(parents=True)
    (path / ".success").touch()
    (path / ".verification-undrained.json").write_text("{}")
    metadata = {
        **matrix,
        "mode": "bug_finding",
        "build_mode": "delta",
        "timestamp": "2026-06-30T00:00:00+00:00",
        "run_time": 100,
        "experiment_name": "study-first",
        "source": {"path": "/remote/benchmarks/project"},
    }
    write_json(path / "metadata.json", metadata)
    (path / "worker.log").write_text(
        "POV store crs_run_start_time updated: 1782777600.0\n"
    )
    (path / "povs").mkdir()
    write_json(
        path / "povs/pov_store.json",
        {
            "crs_run_start_time": 1782777600.0,
            "povs": {"stale": {"cpv_matched": ["old"]}},
            "cpv_to_first_pov": {"old": {}},
        },
    )
    for n in range(10):
        p = path / "output/povs" / f"pov-{n:02}"
        p.write_bytes(bytes([n]))
        os.utime(p, ns=(1782777600000000000 + n * 10**9,) * 2)
    remaining = tmp_path / "remaining"
    remaining.mkdir()
    return plan, {"first": [tmp_path / "raw"], "remaining": [remaining]}, path


def test_prepare_and_actual_local_reeval_preserve_originals_and_first_match(
    collection, tmp_path
):
    plan, inputs, source = collection
    original = (source / "povs/pov_store.json").read_bytes()
    report = audit(plan, inputs)
    assert report["counts"]["selected"] == 1
    assert report["counts"]["undrained"] == 1
    prepared = prepare(report, tmp_path / "prepared", 4)
    manifest = json.loads((prepared / "sample-manifest.json").read_text())
    trial = manifest["trials"][0]
    tree = prepared / "experiment-data" / manifest["experiment"]
    dest = tree / trial["relative_path"]
    assert len(trial["samples"]) == 4
    assert verify(prepared)["problems"]  # fresh store cannot pass before verification
    assert not (dest / ".verification-undrained.json").exists()
    assert (dest / "metadata.json").read_bytes() == (
        source / "metadata.json"
    ).read_bytes()
    assert (
        _resolve_experiment_dir(
            {
                "experiment": manifest["experiment"],
                "experiment_filestore": str(prepared / "experiment-data"),
            }
        )
        == tree
    )
    # Reverse result order to exercise first-match normalization after verification.
    results = [
        PovVerificationResult(
            status=PovVerificationStatus.CPV,
            benchmark="project",
            cpv_matched=["cpv_0"],
            pov_id=p["name"],
        )
        for p in reversed(trial["samples"])
    ]
    with patch("crsbench.evaluation.verification.VerificationEngine") as engine:
        engine.return_value.verify_benchmark.return_value = SimpleNamespace(
            results=results
        )
        assert (
            _reeval_bug_finding(
                dest,
                tmp_path,
                tmp_path,
                "fuzz",
                dest,
                "pkgs",
                1,
                1,
                force_rebuild=False,
                use_inc_build=False,
            )
            == 4
        )
    assert not verify(prepared)["problems"]
    finalize(prepared)
    store = json.loads((dest / "povs/pov_store.json").read_text())
    first = min(p["mtime_ns"] for p in trial["samples"]) / 1e9
    assert store["cpv_to_first_pov"]["cpv_0"]["discovery_ts"] == first
    assert "old" not in store["cpv_to_first_pov"]
    assert (source / "povs/pov_store.json").read_bytes() == original
    with pytest.raises(ValueError, match="existing preparation"):
        prepare(report, prepared, 4)


def test_sampling_survives_preparation_path_changes_and_zero_povs(collection, tmp_path):
    plan, inputs, source = collection
    report = audit(plan, inputs)
    a, b = (prepare(report, tmp_path / name, 3) for name in ("a", "b"))
    assert (a / "sample-manifest.json").read_bytes() == (
        b / "sample-manifest.json"
    ).read_bytes()
    for p in (source / "output/povs").iterdir():
        p.unlink()
    empty = prepare(audit(plan, inputs), tmp_path / "empty", 3)
    assert not verify(empty)["problems"]
    finalize(empty)


@pytest.mark.parametrize(
    "problem", ["seed", "partial", "unfinished", "metadata", "snapshot", "duplicate"]
)
def test_audit_rejects_invalid_executions_and_corrupt_or_duplicate_collections(
    collection, tmp_path, problem
):
    plan, inputs, source = collection
    if problem == "seed":
        (source / "worker.log").write_text("Seed corpus input enabled but unavailable")
    elif problem == "partial":
        (source / ".operator-excluded.json").write_text("{}")
    elif problem == "unfinished":
        (source / ".success").unlink()
    elif problem == "metadata":
        metadata = json.loads((source / "metadata.json").read_text())
        metadata["harness"] = "wrong"
        write_json(source / "metadata.json", metadata)
    elif problem == "snapshot":
        (source / "snapshot-0001.complete").touch()
    else:
        root = tmp_path / "duplicate"
        shutil.copytree(inputs["first"][0], root)
        inputs["first"].append(root)
    report = audit(plan, inputs)
    assert report["counts"]["selected"] == 0
    with pytest.raises(ValueError):
        prepare(report, tmp_path / "rejected", 3)
    assert not (tmp_path / "rejected").exists()


def test_finalize_refuses_missing_error_and_mutated_sample(collection, tmp_path):
    plan, inputs, _ = collection
    prepared = prepare(audit(plan, inputs), tmp_path / "prepared", 1)
    trial = json.loads((prepared / "sample-manifest.json").read_text())["trials"][0]
    dest = next((prepared / "experiment-data").iterdir()) / trial["relative_path"]
    pov = dest / "output/povs" / trial["samples"][0]["name"]
    store_path = dest / "povs/pov_store.json"
    store = json.loads(store_path.read_text())
    store["povs"] = {sha256(pov)[:16]: {"status": "error"}}
    write_json(store_path, store)
    with pytest.raises(ValueError, match="not complete"):
        finalize(prepared)
    store["povs"][sha256(pov)[:16]]["status"] = "not_vulnerable"
    write_json(store_path, store)
    assert not verify(prepared)["problems"]
    pov.write_bytes(b"changed")
    assert verify(prepared)["problems"]
