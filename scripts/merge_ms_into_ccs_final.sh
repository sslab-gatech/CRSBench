#!/usr/bin/env bash
# Merge the three missing-success (ms) re-eval result trees into the
# corresponding aggregated trees under /data/crsbench/ccs-final/.
#
# - Per-trial replace at <bench>/<harness>/<mode>/<sanitizer>/trial-N
# - Preserves mtime/perm/links via `cp -a --preserve=all`
# - Default DRY=1 (no disk mutation). Pass DRY=0 to apply.
# - Pass BACKUP=1 (with DRY=0) to hardlink-snapshot the destination roots
#   into `<dst>.pre-ms-merge-<UTC>` before mutating.
# - mosquitto trials are intentionally NOT covered by any ms tree; this
#   script will not touch them.
#
# Usage:
#   scripts/merge_ms_into_ccs_final.sh                # dry-run
#   DRY=0 BACKUP=1 scripts/merge_ms_into_ccs_final.sh # backup then apply
#   DRY=0 scripts/merge_ms_into_ccs_final.sh          # apply, no backup

set -euo pipefail

DRY="${DRY:-1}"
BACKUP="${BACKUP:-0}"

CCS_FINAL=/data/crsbench/ccs-final
MISSING=/data/crsbench/missing

DST_NOCORPUS="$CCS_FINAL/finding_all_cc-finding-original/crs-bug-finding-claude-code"
DST_CORPUS="$CCS_FINAL/finding_all_cc-finding-original-w-corpus/crs-bug-finding-claude-code"

SRC_WIRESHARK="$MISSING/afc-cc-finding-original-wireshark-rerun/afc-cc-finding-original-wireshark-rerun/crs-bug-finding-claude-code"
SRC_XAFC_FINAL="$MISSING/cc-finding-original-except-afc-final-missing-success/cc-xafc-final-ms/crs-bug-finding-claude-code"
SRC_XAFC_CORPUS="$MISSING/cc-finding-original-except-afc-final-corpus-rerun-missing-success/cc-xafc-corpus-rerun-ms/crs-bug-finding-claude-code"

merge_ms_to_final() {
  local SRC="$1" DST="$2" LABEL="$3"
  echo "===================================================================="
  echo "[$LABEL] DRY=$DRY"
  echo "  SRC=$SRC"
  echo "  DST=$DST"
  echo "===================================================================="

  [ -d "$SRC" ] || { echo "ERROR: missing SRC: $SRC"; return 1; }
  [ -d "$DST" ] || { echo "ERROR: missing DST: $DST"; return 1; }

  local replaced=0 added=0
  while IFS= read -r rel; do
    if [ -d "$DST/$rel" ]; then
      replaced=$((replaced+1))
      if [ "$DRY" = "1" ]; then
        echo "[dry] replace: $DST/$rel"
      else
        rm -rf -- "$DST/$rel"
        cp -a --preserve=all "$SRC/$rel" "$DST/$rel"
      fi
    else
      added=$((added+1))
      if [ "$DRY" = "1" ]; then
        echo "[dry] add:     $DST/$rel"
      else
        mkdir -p -- "$(dirname "$DST/$rel")"
        cp -a --preserve=all "$SRC/$rel" "$DST/$rel"
      fi
    fi
  done < <(cd "$SRC" && find . -mindepth 5 -maxdepth 5 -type d -name 'trial-*' -printf '%P\n' | sort)

  echo
  echo "[$LABEL] trial replace=$replaced  add=$added"
  echo
}

snapshot_dst() {
  local DST_ROOT="$1"
  local TS
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  local SNAP="$DST_ROOT.pre-ms-merge-$TS"
  echo "==> snapshot: $DST_ROOT  ->  $SNAP"
  if [ "$DRY" = "1" ]; then
    echo "[dry] cp -al $DST_ROOT $SNAP"
  else
    cp -al "$DST_ROOT" "$SNAP"
  fi
}

if [ "$BACKUP" = "1" ]; then
  snapshot_dst "$CCS_FINAL/finding_all_cc-finding-original"
  snapshot_dst "$CCS_FINAL/finding_all_cc-finding-original-w-corpus"
  echo
fi

merge_ms_to_final "$SRC_WIRESHARK"   "$DST_NOCORPUS" "1/3 wireshark-rerun"
merge_ms_to_final "$SRC_XAFC_FINAL"  "$DST_NOCORPUS" "2/3 xafc-final-ms"
merge_ms_to_final "$SRC_XAFC_CORPUS" "$DST_CORPUS"   "3/3 xafc-corpus-rerun-ms"

echo "===================================================================="
echo "Done (DRY=$DRY). Expected: 1/3 replace=36, 2/3 replace=3, 3/3 replace=3."
echo "Note: atlanta-mosquitto-delta-01 (9 zero-cost trials per tree)"
echo "      is intentionally NOT covered by any ms tree."
echo "===================================================================="
