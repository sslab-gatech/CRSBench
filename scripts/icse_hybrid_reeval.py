#!/usr/bin/env python3
"""Audit collected hybrid trials and freeze an isolated local POV re-evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from crsbench.evaluation.reeval.cli import _stratified_sample_pov_files
from crsbench.experiment.trial_selection import _resolve_wrapped_collected_root
from crsbench.reporting.metrics import resolve_trial_anchor
from crsbench.reporting.models import TrialMetadataFile


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect_trial(path: Path, record: dict, experiment: str) -> dict:
    """Separate collection integrity, CRS execution, and verification readiness."""
    problems, invalid = [], []
    success, failed = (path / ".success").exists(), (path / ".fail").exists()
    if success and failed:
        problems.append("conflicting terminal markers")
    metadata = {}
    try:
        metadata = json.loads((path / "metadata.json").read_text())
        TrialMetadataFile.model_validate(metadata)
        expected = {**record["matrix"], "experiment_name": experiment}
        expected["build_mode"] = expected.pop("mode")
        if metadata.get("mode") != "bug_finding":
            problems.append("metadata task is not bug_finding")
        for field in (
            "crs",
            "benchmark",
            "harness",
            "trial_num",
            "sanitizer",
            "build_mode",
            "experiment_name",
            "target_cpv_id",
        ):
            if metadata.get(field) != expected.get(field):
                problems.append(f"metadata identity mismatch: {field}")
    except (OSError, ValueError, TypeError) as exc:
        problems.append(f"unreadable/invalid metadata: {exc}")
        metadata = {}
    log_path = path / "worker.log"
    log = log_path.read_text(errors="replace") if log_path.is_file() else ""
    if not log:
        problems.append("missing worker log")
    if "Seed corpus input enabled but unavailable" in log:
        invalid.append("seed corpus unavailable; CRS rerun required")
    elif "Failed to evaluate harness" in log:
        invalid.append("harness evaluation failed; CRS rerun required")
    if (path / ".operator-excluded.json").exists():
        invalid.append("operator-excluded partial execution")
    if success and not (metadata.get("run_time") or 0) > 0:
        invalid.append("no completed CRS run recorded")
    for marker in path.glob("snapshot-*.complete"):
        if not marker.with_suffix(".tar.gz").is_file():
            problems.append(f"missing complete snapshot: {marker.name}")
    pov_dir = path / "output/povs"
    if success and not invalid and not pov_dir.is_dir():
        problems.append("missing output/povs directory in completed execution")
    povs = sorted(p for p in pov_dir.glob("*") if not p.name.startswith("."))
    if any(not p.is_file() for p in povs):
        problems.append("non-file or broken symlink in output/povs")
    store = path / "povs/pov_store.json"
    if store.exists():
        try:
            data = json.loads(store.read_text())
            if not isinstance(data.get("povs"), dict):
                problems.append("invalid POV store")
            elif (
                success
                and not invalid
                and data["povs"]
                and not any(p.is_file() for p in povs)
            ):
                problems.append("empty output/povs contradicts recorded POVs")
        except (OSError, ValueError, AttributeError):
            problems.append("unreadable POV store")
    return {
        "source": str(path.resolve()),
        "status": "success" if success else "fail" if failed else "unfinished",
        "collection_problems": problems,
        "invalid_reasons": invalid,
        "verification_undrained": (path / ".verification-undrained.json").exists(),
        "pov_count": sum(p.is_file() for p in povs),
        "eligible": success and not failed and not problems and not invalid,
    }


def audit(plan: dict, inputs: dict[str, list[Path]]) -> dict:
    rows, blockers, roots = [], [], {}
    for name, batch in plan["batches"].items():
        records = {r["relative_path"]: r for r in batch["trials"]}
        attempts = defaultdict(list)
        roots[name] = []
        for supplied in inputs[name]:
            root = _resolve_wrapped_collected_root(
                supplied.resolve(), batch["experiment"]
            )
            if not root.is_dir():
                raise ValueError(f"Missing collection: {supplied}")
            roots[name].append(str(root))
            for path in sorted(root.glob("*/*/*/*/*/trial-*")):
                if not path.is_dir():
                    continue
                rel = str(path.relative_to(root))
                if rel not in records:
                    blockers.append(f"unplanned trial: {path}")
                    continue
                attempt = inspect_trial(path, records[rel], batch["experiment"])
                if any(a["source"] == attempt["source"] for a in attempts[rel]):
                    raise ValueError(f"Collection supplied more than once: {path}")
                attempts[rel].append(attempt)
        for rel, record in records.items():
            candidates = [a for a in attempts[rel] if a["eligible"]]
            if len(candidates) > 1:
                blockers.append(f"duplicate eligible executions: {record['key']}")
            for attempt in attempts[rel]:
                if attempt["status"] == "success" and attempt["collection_problems"]:
                    blockers.append(
                        f"damaged completed collection: {attempt['source']}"
                    )
            rows.append(
                {
                    **record,
                    "batch": name,
                    "attempts": attempts[rel],
                    "selected_source": candidates[0]["source"]
                    if len(candidates) == 1
                    else None,
                }
            )
    if len(rows) != plan["total_trials"] or len({r["key"] for r in rows}) != len(rows):
        raise ValueError("Plan does not contain the declared number of unique trials")
    counts = Counter()
    for row in rows:
        counts["planned"] += 1
        counts["selected"] += row["selected_source"] is not None
        counts["pending"] += row["selected_source"] is None
        for a in row["attempts"]:
            counts["attempts"] += 1
            counts[f"attempt_{a['status']}"] += 1
            counts["undrained"] += a["verification_undrained"]
            counts["invalid_executions"] += bool(a["invalid_reasons"])
            counts["collection_problems"] += bool(a["collection_problems"])
            counts["pov_files"] += a["pov_count"]
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "experiment": plan["experiment"],
        "counts": dict(counts),
        "roots": roots,
        "blockers": blockers,
        "trials": rows,
    }


def prepare(report: dict, output: Path, sample_size: int) -> Path:
    """Copy a frozen sample; fresh verdicts never inherit the undrained live store."""
    if sample_size < 0:
        raise ValueError("sample size must be nonnegative (0 means all)")
    if report["blockers"]:
        raise ValueError(f"Resolve collection blockers first: {report['blockers']}")
    if output.exists():
        raise ValueError(f"Refusing to replace an existing preparation: {output}")
    selected = [r for r in report["trials"] if r["selected_source"]]
    if not selected:
        raise ValueError("No eligible completed trials")
    output = output.resolve()
    for row in selected:
        source = Path(row["selected_source"])
        if output.is_relative_to(source) or source.is_relative_to(output):
            raise ValueError("Preparation and source trees must not overlap")
    output.parent.mkdir(parents=True, exist_ok=True)
    experiment = report["experiment"] + "-local-reeval"
    with tempfile.TemporaryDirectory(
        prefix=".reeval-prepare-", dir=output.parent
    ) as tmp:
        staging = Path(tmp) / "prepared"
        tree = staging / "experiment-data" / experiment
        tree.mkdir(parents=True)
        samples = []
        for row in selected:
            source = Path(row["selected_source"])
            dest = tree / row["relative_path"]
            dest.mkdir(parents=True)
            # Raw originals, including all old verdicts, remain in the collections.
            # Copy snapshots/accounting/logs with mtimes, but no old verification state.
            for p in source.iterdir():
                if p.is_file() and p.name not in (
                    ".verification-undrained.json",
                    "pov_verification_results.json",
                ):
                    shutil.copy2(p, dest / p.name)
            metadata = json.loads((source / "metadata.json").read_text())
            metadata_epoch = datetime.fromisoformat(metadata["timestamp"]).timestamp()
            anchor, provenance = resolve_trial_anchor(
                source, metadata_epoch=metadata_epoch
            )
            if anchor is None:
                raise ValueError(f"Missing original trial-start anchor: {source}")
            (dest / "povs").mkdir()
            write_json(
                dest / "povs/pov_store.json",
                {"crs_run_start_time": anchor, "povs": {}, "cpv_to_first_pov": {}},
            )
            files = [
                p
                for p in (source / "output/povs").glob("*")
                if p.is_file() and not p.name.startswith(".")
            ]
            chosen = _stratified_sample_pov_files(files, sample_size, seed=row["key"])
            (dest / "output/povs").mkdir(parents=True)
            entries = []
            for p in chosen:
                copied = dest / "output/povs" / p.name
                shutil.copy2(p, copied)
                entries.append(
                    {
                        "name": p.name,
                        "sha256": sha256(copied),
                        "mtime_ns": copied.stat().st_mtime_ns,
                    }
                )
            samples.append(
                {
                    "key": row["key"],
                    "relative_path": row["relative_path"],
                    "source": str(source),
                    "total_povs": len(files),
                    "samples": entries,
                    "anchor": anchor,
                    "anchor_source": provenance,
                }
            )
        write_json(staging / "collection-audit.json", report)
        write_json(
            staging / "sample-manifest.json",
            {
                "schema_version": 1,
                "experiment": experiment,
                "sample_size": sample_size,
                "sampling": "mtime strata; one per equal-count bucket; seed=canonical trial key",
                "trials": samples,
            },
        )
        config = {
            "experiment": {"name": experiment, "task": "bugfinding"},
            "runtime": {
                "source_mode": "pkgs",
                "inc_build_enabled": False,
                "per_pov_verify_timeout": 300,
            },
            "storage": {"experiment_filestore": str(output / "experiment-data")},
        }
        (staging / "reeval.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
        repo = Path(__file__).resolve().parents[1]
        run_script = f"""#!/usr/bin/env bash
set -euo pipefail
cd {shlex.quote(str(repo))}
PREPARED={shlex.quote(str(output))}
# The subset is already frozen; a second sampling pass must be disabled.
CRSBENCH_REEVAL_POV_SAMPLE_SIZE=0 uv run crsbench re-eval \\
  -c "$PREPARED/reeval.yaml" --local \\
  --jobs "${{REEVAL_JOBS:-4}}" --cores-per-job "${{REEVAL_CORES_PER_JOB:-16}}" \\
  -v 2>&1 | tee -a "$PREPARED/reeval.log"
uv run python scripts/icse_hybrid_reeval.py finalize "$PREPARED"
uv run crsbench report \\
  --experiment-dir "$PREPARED/experiment-data/{experiment}" \\
  --format csv --output "$PREPARED/reports"
"""
        (staging / "run-local.sh").write_text(run_script)
        staging.rename(output)
    return output


def verify(prepared: Path) -> dict:
    """Gate reporting on every sampled content hash receiving a usable verdict."""
    manifest = json.loads((prepared / "sample-manifest.json").read_text())
    tree = prepared / "experiment-data" / manifest["experiment"]
    problems = []
    for trial in manifest["trials"]:
        path = tree / trial["relative_path"]
        expected = set()
        names = {item["name"] for item in trial["samples"]}
        if {
            p.name
            for p in (path / "output/povs").iterdir()
            if not p.name.startswith(".")
        } != names:
            problems.append(f"sample inventory changed: {trial['key']}")
        for item in trial["samples"]:
            p = path / "output/povs" / item["name"]
            if (
                not p.is_file()
                or sha256(p) != item["sha256"]
                or p.stat().st_mtime_ns != item["mtime_ns"]
            ):
                problems.append(f"sample changed: {p}")
            expected.add(item["sha256"][:16])
        data = json.loads((path / "povs/pov_store.json").read_text())
        entries = data.get("povs") or {}
        if set(entries) != expected:
            problems.append(f"incomplete/unexpected verdict hashes: {trial['key']}")
        if data.get("crs_run_start_time") != trial["anchor"]:
            problems.append(f"trial-start anchor changed: {trial['key']}")
        for entry in entries.values():
            if entry.get("status") not in ("cpv", "not_vulnerable", "unintended_crash"):
                problems.append(f"unusable verdict: {trial['key']}")
    return {"trials": len(manifest["trials"]), "problems": problems}


def finalize(prepared: Path) -> dict:
    """Rebuild first-match times from the frozen sample before CSV aggregation."""
    result = verify(prepared)
    if result["problems"]:
        raise ValueError(f"Re-evaluation is not complete: {result['problems']}")
    manifest = json.loads((prepared / "sample-manifest.json").read_text())
    for trial in manifest["trials"]:
        store = (
            prepared
            / "experiment-data"
            / manifest["experiment"]
            / trial["relative_path"]
            / "povs/pov_store.json"
        )
        data = json.loads(store.read_text())
        times = {}
        for item in trial["samples"]:
            key = item["sha256"][:16]
            ts = item["mtime_ns"] / 1e9
            times[key] = min(times.get(key, ts), ts)
        first = {}
        for key, entry in data["povs"].items():
            entry["file_mtime"] = times[key]
            for cpv in entry.get("cpv_matched") or []:
                if cpv not in first or times[key] < first[cpv]["discovery_ts"]:
                    first[cpv] = {
                        "pov_hash": key,
                        "discovery_ts": times[key],
                        "relative_time": times[key] - trial["anchor"],
                    }
        data["cpv_to_first_pov"] = first
        write_json(store, data)
    write_json(prepared / "verification-audit.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("audit", "prepare"):
        p = sub.add_parser(command)
        p.add_argument("--plan", type=Path, required=True)
        p.add_argument("--first", type=Path, nargs="+", required=True)
        p.add_argument("--remaining", type=Path, nargs="+", required=True)
        p.add_argument("--output", type=Path, required=True)
        if command == "prepare":
            p.add_argument("--sample-size", type=int, default=100)
    for command in ("verify", "finalize"):
        p = sub.add_parser(command)
        p.add_argument("prepared", type=Path)
    args = parser.parse_args()
    try:
        if args.command in ("verify", "finalize"):
            result = (
                verify(args.prepared)
                if args.command == "verify"
                else finalize(args.prepared)
            )
            print(json.dumps(result, indent=2))
            return int(bool(result["problems"]))
        plan = json.loads(args.plan.read_text())
        report = audit(plan, {"first": args.first, "remaining": args.remaining})
        if args.command == "audit":
            with args.output.open("x") as stream:
                stream.write(json.dumps(report, indent=2) + "\n")
        else:
            prepare(report, args.output, args.sample_size)
        print(
            json.dumps(
                {
                    "counts": report["counts"],
                    "blockers": report["blockers"],
                    "output": str(args.output),
                },
                indent=2,
            )
        )
        return int(bool(report["blockers"]))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"Re-evaluation preparation failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
