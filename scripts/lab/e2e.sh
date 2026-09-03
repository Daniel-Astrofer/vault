#!/usr/bin/env bash
# Lab E2E / §13.4 suite entrypoint (F6).
# Usage: from repo root or this directory:
#   ./scripts/lab_e2e.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
echo "== kerosene-vault lab E2E (§13.4) =="
cargo test --test lab_e2e_suite -- --nocapture
echo "== full crate tests =="
cargo test
echo "OK: lab suite green"
