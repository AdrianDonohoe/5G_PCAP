#!/usr/bin/env bash
# Regenerate the Golden baseline from the sandbox golden triple (N2 + N4 + SBI
# of one healthy run). 5gcap's merged export is deterministic, so the kpis
# section reproduces byte-for-byte; the committed golden_kpis.json must never
# be edited by hand.
#
# Usage: ./regenerate.sh [out.json]   (default: golden_kpis.json next to this script)
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$(dirname "$0")/golden_kpis.json}"
tmp="$(mktemp --suffix=.json)"

uv run --project "$repo/5gcap" 5gcap analyze \
    "$repo/5gcap/tests/fixtures/sandbox_n2.pcap" \
    --json "$tmp" \
    --sbi "$repo/5gcap/tests/fixtures/sandbox_sbi.pcap" \
    --n4 "$repo/5gcap/tests/fixtures/sandbox_n4.pcap" \
    >/dev/null

uv run --project "$repo/5gcap" python - "$tmp" "$out" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    merged = json.load(f)
with open(sys.argv[2], "w") as f:
    json.dump(merged["kpis"], f, indent=2)
    f.write("\n")
PY

rm "$tmp"
echo "Golden baseline written to $out"
