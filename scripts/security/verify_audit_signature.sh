#!/usr/bin/env bash
# Sign / verify mesh audit payloads with F8 audit keys (≠ release ≠ settlement).
#
# Sign:
#   ./scripts/verify_mesh_audit_sig.sh sign \
#     --key ceremony-certs/audit/operators/audit-ops-1.key \
#     --message event.json --sig event.sig
#
# Verify (allowlist required):
#   ./scripts/verify_mesh_audit_sig.sh verify \
#     --allowlist ceremony-certs/audit/allowlist.txt \
#     --pub ceremony-certs/audit/operators/audit-ops-1.pub \
#     --message event.json --sig event.sig
set -euo pipefail

usage() {
  sed -n '2,16p' "$0" | sed 's/^# //;s/^#//'
  exit 2
}

CMD="${1:-}"
[[ -n "$CMD" ]] || usage
shift || true

KEY=""
PUB=""
ALLOWLIST=""
MESSAGE=""
SIG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;
    --pub) PUB="${2:-}"; shift 2 ;;
    --allowlist) ALLOWLIST="${2:-}"; shift 2 ;;
    --message) MESSAGE="${2:-}"; shift 2 ;;
    --sig) SIG="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$MESSAGE" && -f "$MESSAGE" ]] || { echo "error: --message file required" >&2; exit 1; }
[[ -n "$SIG" ]] || { echo "error: --sig path required" >&2; exit 1; }

pubkey_hex_from_pem() {
  local pem="$1"
  local hex
  hex="$(openssl pkey -pubin -in "$pem" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32 || true)"
  if [[ -n "$hex" && "${#hex}" -eq 64 ]]; then
    echo "$hex"
    return
  fi
  openssl pkey -pubin -in "$pem" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}'
}

allowlist_contains() {
  local list="$1" hex="$2"
  [[ -f "$list" ]] || return 1
  awk -v h="$hex" 'NF>=2 && $2==h { found=1 } END { exit !found }' "$list"
}

case "$CMD" in
  sign)
    [[ -n "$KEY" && -f "$KEY" ]] || { echo "error: --key required" >&2; exit 1; }
    openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$MESSAGE" -out "$SIG"
    chmod 0644 "$SIG"
    echo "signed $MESSAGE → $SIG"
    ;;
  verify)
    [[ -n "$PUB" && -f "$PUB" ]] || { echo "error: --pub required" >&2; exit 1; }
    [[ -n "$ALLOWLIST" && -f "$ALLOWLIST" ]] || {
      echo "error: --allowlist required (F8: refuse verify without audit allowlist)" >&2
      exit 1
    }
    hex="$(pubkey_hex_from_pem "$PUB")"
    if ! allowlist_contains "$ALLOWLIST" "$hex"; then
      echo "error: pubkey not on mesh audit allowlist (refusing — key may be release/settlement)" >&2
      exit 1
    fi
    openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$MESSAGE" -sigfile "$SIG"
    echo "verify OK (allowlisted audit key ${hex})"
    ;;
  *)
    usage
    ;;
esac
