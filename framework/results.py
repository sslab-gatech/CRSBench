"""Produce precision/recall CSVs from CRSBench trial artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

import yaml

from framework.errors import FrameworkError

if TYPE_CHECKING:
    from framework.config import RunnerConfig

TRIAL_COLUMNS = [
    "experiment_name",
    "crs_name",
    "benchmark_name",
    "harness_name",
    "run_mode",
    "sanitizer",
    "trial_number",
    "trial_status",
    "build_duration_seconds",
    "run_duration_seconds",
    "snapshot_count",
    "total_povs_discovered",
    "total_known_vulnerabilities",
    "unique_known_vulnerabilities_found",
    "unique_vulnerability_precision",
    "known_pov_count",
    "unintended_crash_pov_count",
    "candidate_unknown_crash_sites",
    "not_vulnerable_pov_count",
    "verification_error_count",
    "verified_non_error_pov_count",
    "known_pov_precision",
    "potential_max_pov_precision",
    "time_to_first_known_vulnerability_seconds",
    "time_to_first_unintended_crash_seconds",
]
SUMMARY_COLUMNS = [
    "benchmark_name",
    "total_known_vulnerabilities",
    "unique_known_vulnerabilities_found",
    "known_vulnerability_recall",
    "total_known_povs",
    "total_unintended_crash_povs",
    "distinct_candidate_unknown_crash_sites",
    "total_not_vulnerable_povs",
    "total_verification_errors",
    "pooled_known_pov_precision",
    "pooled_useful_finding_precision",
    "mean_trial_known_pov_precision",
]


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _expected_cpvs(benchmarks_dir: Path, benchmark: str, harness: str) -> set[str]:
    path = benchmarks_dir / benchmark / ".aixcc" / "meta.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return set()
    if not isinstance(data, dict):
        return set()
    harnesses = data.get("harness_files") or []
    if not isinstance(harnesses, list):
        return set()
    for item in harnesses:
        if not isinstance(item, dict):
            continue
        if item.get("name") == harness:
            vulnerabilities = item.get("vulns") or []
            if not isinstance(vulnerabilities, list):
                return set()
            return {
                str(v["vuln_keyword"])
                for v in vulnerabilities
                if isinstance(v, dict) and v.get("vuln_keyword")
            }
    return set()


def _status(trial_dir: Path, metadata: dict[str, Any]) -> str:
    if (trial_dir / ".fail").exists():
        return "failed"
    if not (trial_dir / ".success").exists():
        return "incomplete"
    run_time = metadata.get("run_time")
    experiment_config = metadata.get("experiment_config") or {}
    timeout = (
        experiment_config.get("run_timeout")
        if isinstance(experiment_config, dict)
        else None
    )
    if (
        isinstance(run_time, (int, float))
        and isinstance(timeout, (int, float))
        and run_time >= timeout
    ):
        return "timed_out"
    return "completed"


def _ratio(numerator: int, denominator: int) -> float | str:
    return numerator / denominator if denominator else "NA"


def _value_or_na(value: Any) -> Any:
    return "NA" if value is None else value


def _snapshot_count(history: dict[str, Any], trial_dir: Path) -> int:
    value = history.get("snapshot_count", 0)
    try:
        count = int(value)
    except (TypeError, ValueError):
        count = 0
    has_final_snapshot = (trial_dir / "povs/snapshots/snapshot--01.json").exists()
    return max(0, count - int(has_final_snapshot))


def _first_time(entries: Iterable[dict[str, Any]], start: Any) -> float | str:
    if not isinstance(start, (int, float)):
        return "NA"
    timestamps = []
    for entry in entries:
        value = entry.get("file_mtime", entry.get("first_seen_ts"))
        if isinstance(value, (int, float)):
            timestamps.append(value)
    return min(timestamps) - start if timestamps else "NA"


def parse_trial(
    trial_dir: Path, benchmarks_dir: Path, experiment_name: str
) -> tuple[dict[str, Any], set[str], set[str]]:
    metadata = _json(trial_dir / "metadata.json")
    if not metadata:
        raise FrameworkError(f"trial has no readable metadata: {trial_dir}")
    store = _json(trial_dir / "povs" / "pov_store.json")
    history = _json(trial_dir / "povs" / "snapshot_history.json")
    raw_povs = store.get("povs") or {}
    if not isinstance(raw_povs, dict):
        raw_povs = {}
    entries = [entry for entry in raw_povs.values() if isinstance(entry, dict)]
    cpv_entries = [entry for entry in entries if entry.get("status") == "cpv"]
    unintended = [
        entry for entry in entries if entry.get("status") == "unintended_crash"
    ]
    not_vulnerable = [
        entry for entry in entries if entry.get("status") == "not_vulnerable"
    ]
    errors = [entry for entry in entries if entry.get("status") in {"error", "timeout"}]
    found_cpvs = {
        str(cpv) for entry in cpv_entries for cpv in (entry.get("cpv_matched") or [])
    }
    benchmark = str(metadata.get("benchmark", ""))
    harness = str(metadata.get("harness", ""))
    expected = _expected_cpvs(benchmarks_dir, benchmark, harness)
    non_error = len(entries) - len(errors)
    known_precision = _ratio(len(cpv_entries), non_error)
    useful = len(cpv_entries) + len(unintended)
    row = {
        "experiment_name": metadata.get("experiment_name", experiment_name),
        "crs_name": metadata.get("crs", ""),
        "benchmark_name": benchmark,
        "harness_name": harness,
        "run_mode": metadata.get("build_mode", ""),
        "sanitizer": metadata.get("sanitizer", ""),
        "trial_number": metadata.get("trial_num", ""),
        "trial_status": _status(trial_dir, metadata),
        "build_duration_seconds": _value_or_na(metadata.get("build_time")),
        "run_duration_seconds": _value_or_na(metadata.get("run_time")),
        "snapshot_count": _snapshot_count(history, trial_dir),
        "total_povs_discovered": len(entries),
        "total_known_vulnerabilities": len(expected),
        "unique_known_vulnerabilities_found": len(found_cpvs & expected),
        "unique_vulnerability_precision": _ratio(
            len(found_cpvs & expected), len(expected)
        ),
        "known_pov_count": len(cpv_entries),
        "unintended_crash_pov_count": len(unintended),
        "candidate_unknown_crash_sites": len(
            {
                entry.get("crash_signature")
                for entry in unintended
                if entry.get("crash_signature")
            }
        ),
        "not_vulnerable_pov_count": len(not_vulnerable),
        "verification_error_count": len(errors),
        "verified_non_error_pov_count": non_error,
        "known_pov_precision": known_precision,
        "potential_max_pov_precision": _ratio(useful, non_error),
        "time_to_first_known_vulnerability_seconds": _first_time(
            cpv_entries, store.get("crs_run_start_time")
        ),
        "time_to_first_unintended_crash_seconds": _first_time(
            unintended, store.get("crs_run_start_time")
        ),
    }
    signatures = {
        f"{harness}/{entry['crash_signature']}"
        for entry in unintended
        if entry.get("crash_signature")
    }
    found_identities = {f"{harness}/{cpv}" for cpv in found_cpvs & expected}
    return row, found_identities, signatures


def _write(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def parse_experiment(
    experiment_dir: Path, benchmarks_dir: Path, output_dir: Path
) -> tuple[Path, Path]:
    if not experiment_dir.is_dir():
        raise FrameworkError(f"experiment directory does not exist: {experiment_dir}")
    if not benchmarks_dir.is_dir():
        raise FrameworkError(f"benchmarks directory does not exist: {benchmarks_dir}")
    experiment_name = experiment_dir.name
    trial_rows: list[dict[str, Any]] = []
    found_by_trial: dict[int, set[str]] = {}
    signatures_by_trial: dict[int, set[str]] = {}
    trial_dirs = sorted(
        path for path in experiment_dir.rglob("trial-*") if path.is_dir()
    )
    for trial_dir in trial_dirs:
        if not (trial_dir / "metadata.json").is_file():
            continue
        row, found, signatures = parse_trial(trial_dir, benchmarks_dir, experiment_name)
        found_by_trial[id(row)] = found
        signatures_by_trial[id(row)] = signatures
        trial_rows.append(row)
    if not trial_rows:
        raise FrameworkError(
            f"no completed or partial trials found in {experiment_dir}"
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in trial_rows:
        grouped[str(row["benchmark_name"])].append(row)
    summary_rows: list[dict[str, Any]] = []
    for benchmark, rows in sorted(grouped.items()):
        harness_totals: dict[str, int] = {}
        for row in rows:
            harness_totals[str(row["harness_name"])] = int(
                row["total_known_vulnerabilities"]
            )
        known_total = sum(harness_totals.values())
        found_union = set().union(*(found_by_trial[id(row)] for row in rows))
        signature_union = set().union(*(signatures_by_trial[id(row)] for row in rows))
        known = sum(int(row["known_pov_count"]) for row in rows)
        unintended_count = sum(int(row["unintended_crash_pov_count"]) for row in rows)
        not_vuln = sum(int(row["not_vulnerable_pov_count"]) for row in rows)
        errors = sum(int(row["verification_error_count"]) for row in rows)
        verified = sum(int(row["verified_non_error_pov_count"]) for row in rows)
        trial_precisions = [
            float(row["known_pov_precision"])
            for row in rows
            if row["known_pov_precision"] != "NA"
        ]
        summary_rows.append(
            {
                "benchmark_name": benchmark,
                "total_known_vulnerabilities": known_total,
                "unique_known_vulnerabilities_found": len(found_union),
                "known_vulnerability_recall": _ratio(len(found_union), known_total),
                "total_known_povs": known,
                "total_unintended_crash_povs": unintended_count,
                "distinct_candidate_unknown_crash_sites": len(signature_union),
                "total_not_vulnerable_povs": not_vuln,
                "total_verification_errors": errors,
                "pooled_known_pov_precision": _ratio(known, verified),
                "pooled_useful_finding_precision": _ratio(
                    known + unintended_count, verified
                ),
                "mean_trial_known_pov_precision": (
                    statistics.mean(trial_precisions) if trial_precisions else "NA"
                ),
            }
        )
    trial_path = output_dir / f"{experiment_name}_trial_metrics.csv"
    summary_path = output_dir / f"{experiment_name}_benchmark_summary.csv"
    _write(trial_path, TRIAL_COLUMNS, trial_rows)
    _write(summary_path, SUMMARY_COLUMNS, summary_rows)
    return trial_path, summary_path


def parse_results(cfg: RunnerConfig, repo_root: Path) -> tuple[Path, Path]:
    del repo_root
    return parse_experiment(
        cfg.results_dir / "experiment-data" / cfg.run_id,
        cfg.benchmarks_dir,
        cfg.run_dir / "csv",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment_dir", type=Path)
    parser.add_argument("--benchmarks-dir", type=Path, default=Path("benchmarks"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    parse_experiment(args.experiment_dir, args.benchmarks_dir, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
