#!/usr/bin/env bash
# Single command to reproduce the OrbitLink grid: bash experiments/run.sh [seeds=3] [--quick]
set -euo pipefail
SEEDS="${1:-3}"; shift || true
OUT="${OUT:-results/$(date -u +%Y%m%dT%H%M%SZ)}"  # set OUT=<existing dir> to resume
mkdir -p "$OUT"
cargo build --release -q --bin orbitlink-sim
[ -f "$OUT/environment.txt" ] || {
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "seeds: $SEEDS $*"
  echo "kernel: $(uname -srm)"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
  echo "rustc: $(rustc --version)"
  echo "crates:"; grep -A1 -E '^name = "(bp7|ml-kem|hkdf|sha2|aes-gcm|aes-kw|hmac)"$' Cargo.lock | grep -v -- '--' | paste - - | sed 's/^/  /'
  echo "network metrics: SIMULATED; protect/accept times: MEASURED; energy: ESTIMATED (1e-7 J/bit assumption)"
} > "$OUT/environment.txt"
"${CARGO_TARGET_DIR:-target}/release/orbitlink-sim" "$SEEDS" "$OUT/raw.csv" "$@" 2>> "$OUT/progress.log"
"${PYTHON:-python3}" experiments/analyze.py "$OUT/raw.csv" "$OUT" || echo "analysis failed; raw data kept"
echo "results in $OUT"
