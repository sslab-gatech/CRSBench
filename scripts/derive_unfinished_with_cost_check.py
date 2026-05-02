#!/usr/bin/env python3
"""Derive unfinished trial keys from a collected CRSBench experiment, treating
trials with `.success` but `llm-usage.json` reporting `total_cost_usd <= 0`
(or missing/unreadable) as failed.

This extends `crsbench cloud derive-unfinished-trial-keys` with one extra
check: a `.success` marker is not sufficient — the trial must also have
positive recorded LLM cost. Trials that recorded a `.success` with $0 cost
are considered failed (no real LLM work happened) and are added to the
rerun set, alongside trials with `.fail` markers (with --rerun-failed-trials)
and trials that were never executed at all.

The output trial-keys file is consumed by:
    crsbench cloud launch --config <CONFIG> --only-trial-keys-file <FILE>

Usage:
    scripts/derive_unfinished_with_cost_check.py \
        --config <CONFIG.yaml> \
        --from <COLLECTED_ROOT> \
        --output <FILE> \
        [--rerun-failed-trials] \
        [--dry-run]

With --dry-run, no file is written and a per-CRS / per-benchmark / per-CPV
breakdown of what would be re-run is printed to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

from crsbench.experiment.trial_selection import (
    _build_trial_matrix_from_config,
    _resolve_wrapped_collected_root,
    _trial_key_from_collected_trial_dir,
    trial_key_for_trial,
)
from crsbench.run_experiment import load_experiment_config


def _llm_cost_status(trial_dir: Path) -> tuple[Optional[float], Optional[str]]:
    """Return (cost_or_None, problem_reason_or_None)."""
    path = trial_dir / "llm-usage.json"
    if not path.exists():
        return None, "llm-usage.json missing"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"llm-usage.json unreadable ({exc})"
    cost = data.get("total_cost_usd")
    if not isinstance(cost, (int, float)):
        return None, "total_cost_usd missing or non-numeric"
    if cost <= 0:
        return float(cost), "total_cost_usd <= 0"
    return float(cost), None


def _parse_trial_key(key: str) -> dict[str, str]:
    """Split canonical trial key into named parts.

    Uses ``maxsplit=6`` so a cpv_id containing literal ':' stays in the last
    field rather than overflowing into extra parts.
    """
    parts = key.split(":", 6)
    if len(parts) != 7:
        return {"raw": key}
    crs, benchmark, harness, mode, sanitizer, trial_num, cpv_id = parts
    return {
        "crs": crs,
        "benchmark": benchmark,
        "harness": harness,
        "mode": mode,
        "sanitizer": sanitizer,
        "trial_num": trial_num,
        "cpv_id": cpv_id,
    }


def _print_breakdown(
    rerun_keys: list[str],
    reason_by_key: dict[str, str],
    *,
    stream,
) -> None:
    """Print per-CRS, per-(CRS,benchmark,cpv) breakdown of the rerun set."""
    by_crs: dict[str, int] = defaultdict(int)
    by_crs_bench: dict[tuple[str, str], int] = defaultdict(int)
    by_crs_bench_cpv: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    by_reason: dict[str, int] = defaultdict(int)

    for key in rerun_keys:
        parts = _parse_trial_key(key)
        crs = parts.get("crs", "?")
        bench = parts.get("benchmark", "?")
        cpv = parts.get("cpv_id", "-")
        trial_num = parts.get("trial_num", "?")
        sanitizer = parts.get("sanitizer", "?")
        by_crs[crs] += 1
        by_crs_bench[(crs, bench)] += 1
        by_crs_bench_cpv[(crs, bench, cpv)].append(f"trial-{trial_num}/{sanitizer}")
        by_reason[reason_by_key.get(key, "unknown")] += 1

    print("Rerun reasons:", file=stream)
    for reason, n in sorted(by_reason.items(), key=lambda kv: -kv[1]):
        print(f"  {reason}: {n}", file=stream)
    print(file=stream)

    print("Rerun by CRS:", file=stream)
    for crs, n in sorted(by_crs.items()):
        print(f"  {crs}: {n}", file=stream)
    print(file=stream)

    print("Rerun by (CRS, benchmark):", file=stream)
    for (crs, bench), n in sorted(by_crs_bench.items()):
        print(f"  {crs} / {bench}: {n}", file=stream)
    print(file=stream)

    print("Rerun by (CRS, benchmark, CPV) — trial-num/sanitizer cells:", file=stream)
    for (crs, bench, cpv), cells in sorted(by_crs_bench_cpv.items()):
        cells_text = ", ".join(sorted(cells))
        print(f"  {crs} / {bench} / {cpv}: {len(cells)}  [{cells_text}]", file=stream)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Experiment config YAML used to build the trial matrix",
    )
    parser.add_argument(
        "--from",
        dest="collected_root",
        type=Path,
        required=True,
        help="Collected experiment root to scan for trial-* leaves",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output trial-keys file (newline-delimited). Omit to print to stdout.",
    )
    parser.add_argument(
        "--rerun-failed-trials",
        action="store_true",
        help="Also include trials whose collected directory has a .fail marker",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't write a file; print breakdown of what would be re-run",
    )
    args = parser.parse_args()

    config = load_experiment_config(args.config)
    matrix = _build_trial_matrix_from_config(config)
    matrix_keys_ordered = [trial_key_for_trial(t) for t in matrix]
    matrix_key_set = set(matrix_keys_ordered)

    root = _resolve_wrapped_collected_root(
        args.collected_root,
        getattr(config, "experiment", None),
    )
    if not root.exists() or not root.is_dir():
        sys.exit(f"error: collected root is not a directory: {root}")

    success_full_keys: set[str] = set()
    success_zero_cost: dict[str, str] = {}
    fail_keys: set[str] = set()

    for dirpath, _, filenames in os.walk(root):
        has_success = ".success" in filenames
        has_fail = ".fail" in filenames
        if not has_success and not has_fail:
            continue
        trial_dir = Path(dirpath)
        key = _trial_key_from_collected_trial_dir(trial_dir, root)
        if key is None:
            continue

        if has_success:
            _, problem = _llm_cost_status(trial_dir)
            if problem is None:
                success_full_keys.add(key)
            else:
                success_zero_cost[key] = problem
        if has_fail and not has_success:
            fail_keys.add(key)

    seen_keys = success_full_keys | set(success_zero_cost) | fail_keys
    unknown = seen_keys - matrix_key_set
    if unknown:
        sample = ", ".join(sorted(unknown)[:5])
        sys.exit(
            "error: collected results contain trial keys that are NOT in the "
            f"matrix built from {args.config}. The rerun config's matrix must "
            "match the original. Sample unknown keys: "
            f"{sample}{' ...' if len(unknown) > 5 else ''}"
        )

    rerun_keys: list[str] = []
    reason_by_key: dict[str, str] = {}
    incomplete_count = 0
    fail_skipped_count = 0
    for key in matrix_keys_ordered:
        if key in success_full_keys:
            continue
        if key in success_zero_cost:
            rerun_keys.append(key)
            reason_by_key[key] = ".success but " + success_zero_cost[key]
            continue
        if key in fail_keys:
            if args.rerun_failed_trials:
                rerun_keys.append(key)
                reason_by_key[key] = ".fail marker (with --rerun-failed-trials)"
            else:
                fail_skipped_count += 1
            continue
        rerun_keys.append(key)
        reason_by_key[key] = "never executed (no marker)"
        incomplete_count += 1

    err = sys.stderr
    print(f"Trial matrix size:                 {len(matrix_keys_ordered)}", file=err)
    print(f"  .success with cost > 0 (skip):   {len(success_full_keys)}", file=err)
    print(
        f"  .success with cost <= 0 (rerun): {len(success_zero_cost)}",
        file=err,
    )
    if args.rerun_failed_trials:
        print(f"  .fail (rerun):                   {len(fail_keys)}", file=err)
    else:
        print(
            f"  .fail (kept as terminal):        {len(fail_keys)}  "
            "(use --rerun-failed-trials to rerun)",
            file=err,
        )
    print(f"  never executed (rerun):          {incomplete_count}", file=err)
    print(f"Total rerun set:                   {len(rerun_keys)}", file=err)
    print(file=err)

    if rerun_keys:
        _print_breakdown(rerun_keys, reason_by_key, stream=err)
        print(file=err)

    if args.dry_run:
        print("(dry-run: no file written)", file=err)
        return 0

    if args.output is None:
        for key in rerun_keys:
            print(key)
        return 0

    payload = "\n".join(rerun_keys)
    if rerun_keys:
        payload += "\n"
    args.output.write_text(payload, encoding="utf-8")
    print(f"Wrote {len(rerun_keys)} trial keys to {args.output}", file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
