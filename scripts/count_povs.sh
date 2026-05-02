#!/usr/bin/env bash
# Count PoV (bug-triggering input) blobs across benchmarks.
# PoVs live at: benchmarks/<bench>/.aixcc/<harness>/cpv_*/blobs/pov_*.blob
#
# Usage:
#   count_povs.sh [--csv|--csv-detail] [benchmarks_dir]
#     (no flag)   pretty per-benchmark summary + totals
#     --csv       CSV per benchmark: benchmark,cpvs,povs
#     --csv-detail CSV per CPV:      benchmark,harness,cpv,povs

set -euo pipefail

mode="pretty"
BENCH_DIR=""
for arg in "$@"; do
    case "${arg}" in
        --csv) mode="csv" ;;
        --csv-detail) mode="csv-detail" ;;
        -h|--help)
            sed -n '2,11p' "$0"
            exit 0
            ;;
        *) BENCH_DIR="${arg}" ;;
    esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${BENCH_DIR:-${ROOT_DIR}/benchmarks}"

if [[ ! -d "${BENCH_DIR}" ]]; then
    echo "error: benchmarks directory not found: ${BENCH_DIR}" >&2
    exit 1
fi

total=0
bench_count=0
cpv_count=0

if [[ "${mode}" == "csv" ]]; then
    echo "benchmark,cpvs,povs"
elif [[ "${mode}" == "csv-detail" ]]; then
    echo "benchmark,harness,cpv,povs"
fi

while IFS= read -r bench; do
    bench_name="$(basename "${bench}")"
    # sanity benchmarks are toy/test fixtures, exclude from counts
    [[ "${bench_name}" == sanity-* ]] && continue
    bench_povs=0
    bench_cpvs=0
    while IFS= read -r cpv_dir; do
        povs=$(find "${cpv_dir}/blobs" -maxdepth 1 -type f -name 'pov_*.blob' 2>/dev/null | wc -l)
        bench_povs=$((bench_povs + povs))
        bench_cpvs=$((bench_cpvs + 1))
        if [[ "${mode}" == "csv-detail" ]]; then
            cpv_name="$(basename "${cpv_dir}")"
            harness_name="$(basename "$(dirname "${cpv_dir}")")"
            echo "${bench_name},${harness_name},${cpv_name},${povs}"
        fi
    done < <(find "${bench}/.aixcc" -mindepth 2 -maxdepth 2 -type d -name 'cpv_*' 2>/dev/null | sort)

    if (( bench_cpvs > 0 )); then
        case "${mode}" in
            pretty) printf '%-60s cpvs=%-4d povs=%d\n' "${bench_name}" "${bench_cpvs}" "${bench_povs}" ;;
            csv)    echo "${bench_name},${bench_cpvs},${bench_povs}" ;;
        esac
        bench_count=$((bench_count + 1))
        cpv_count=$((cpv_count + bench_cpvs))
        total=$((total + bench_povs))
    fi
done < <(find "${BENCH_DIR}" -mindepth 1 -maxdepth 1 -type d | sort)

case "${mode}" in
    pretty)
        echo "----"
        echo "benchmarks: ${bench_count}"
        echo "cpvs:       ${cpv_count}"
        echo "povs:       ${total}"
        ;;
    csv)        echo "TOTAL,${cpv_count},${total}" ;;
    csv-detail) echo "TOTAL,,,${total}" ;;
esac
