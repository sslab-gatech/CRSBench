"""Inventory every local benchmark in the compact historical 10-column format."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any

import yaml

COLUMNS = [
    "benchmark_name",
    "supported_modes",
    "total_harnesses",
    "vulnerable_harnesses",
    "total_known_vulnerabilities",
    "vulnerabilities_with_patches",
    "build_variants",
    "main_repo",
    "language",
    "homepage",
]


def _load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return value if isinstance(value, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def collect(benchmarks_dir: Path) -> list[dict[str, Any]]:
    if not benchmarks_dir.is_dir():
        raise FileNotFoundError(
            f"benchmarks directory does not exist: {benchmarks_dir}"
        )
    rows: list[dict[str, Any]] = []
    for root in sorted(path for path in benchmarks_dir.iterdir() if path.is_dir()):
        meta = _load(root / ".aixcc" / "meta.yaml")
        project = _load(root / "project.yaml")
        if not meta:
            continue
        has_delta = bool(meta.get("delta_mode"))
        has_full = bool(meta.get("full_mode"))
        if has_delta and has_full:
            modes = "Both"
        elif has_delta:
            modes = "Delta"
        elif has_full:
            modes = "Full"
        else:
            modes = "N/A"
        harnesses = meta.get("harness_files") or []
        if not isinstance(harnesses, list):
            harnesses = []
        harnesses = [item for item in harnesses if isinstance(item, dict)]
        vulnerable = [item for item in harnesses if item.get("vulns")]
        vulns = [
            vuln
            for item in vulnerable
            if isinstance(item.get("vulns"), list)
            for vuln in item["vulns"]
            if isinstance(vuln, dict)
        ]
        with_patches = 0
        for item in vulnerable:
            item_vulns = item.get("vulns") or []
            if not isinstance(item_vulns, list):
                continue
            for vuln in item_vulns:
                if not isinstance(vuln, dict):
                    continue
                cpv = str(vuln.get("vuln_keyword", ""))
                patches = root / ".aixcc" / str(item.get("name")) / cpv / "patches"
                if cpv and any(patches.glob("*.diff")):
                    with_patches += 1
        rows.append(
            {
                "benchmark_name": root.name,
                "supported_modes": modes,
                "total_harnesses": len(harnesses),
                "vulnerable_harnesses": len(vulnerable),
                "total_known_vulnerabilities": len(vulns),
                "vulnerabilities_with_patches": with_patches,
                "build_variants": with_patches + (1 if has_delta else 0),
                "main_repo": project.get("main_repo") or "N/A",
                "language": project.get("language") or "N/A",
                "homepage": project.get("homepage") or "N/A",
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            -int(row["total_known_vulnerabilities"]),
            str(row["benchmark_name"]),
        ),
    )


def write(rows: list[dict[str, Any]], output: Path | None, delimiter: str) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
    handle = output.open("w", newline="", encoding="utf-8") if output else sys.stdout
    try:
        writer = csv.DictWriter(
            handle, fieldnames=COLUMNS, delimiter=delimiter, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if output:
            handle.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmarks-dir", type=Path, default=Path("benchmarks"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("tsv", "csv"), default="tsv")
    args = parser.parse_args()
    delimiter = "\t" if args.format == "tsv" else ","
    write(collect(args.benchmarks_dir), args.output, delimiter)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
