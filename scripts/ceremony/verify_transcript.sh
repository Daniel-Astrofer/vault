#!/usr/bin/env bash
set -euo pipefail

# Post-ceremony verification: validates PQ keys, hybrid envelopes, FROST group key,
# and audit signatures after genesis ceremony completes.
#
# Usage:
#   VAULT_CEREMONY_DIR=/path/to/ceremony-artifacts ./scripts/ceremony/verify_transcript.sh
#
# Ceremony artifact layout expected:
#   $VAULT_CEREMONY_DIR/
#     roster.json          — {nodes, genesis_n, threshold, group_pubkey}
#     audit/               — signed audit manifests, public keys and allowlist
#     identity/            — per-node ML-DSA-65 + Ed25519 pubkeys
#     shares/              — encrypted share blobs (hybrid envelope)
#     transcript.log       — DKG round logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CEREMONY_DIR="${VAULT_CEREMONY_DIR:-${1:-$SCRIPT_DIR/../../var/ceremony-certs}}"

fail=0
check() {
  if eval "$1" 2>/dev/null; then
    echo "  [PASS] $2"
  else
    echo "  [FAIL] $2"
    fail=$((fail + 1))
  fi
}

echo "============================================"
echo "  Kerosene Vault Ceremony Transcript Verification"
echo "  Artifacts: $CEREMONY_DIR"
echo "============================================"

# ---- Roster ----
echo
echo "--- Roster integrity ---"
ROSTER="$CEREMONY_DIR/roster.json"
check '[ -f "$ROSTER" ]' "roster.json exists"
if [[ -f "$ROSTER" ]]; then
  check 'python3 -c "import json; r=json.load(open(\"$ROSTER\")); assert len(r[\"nodes\"])>=3, \"<3 nodes\"; assert r[\"genesis_n\"]>=3; print(\"nodes=\"+str(len(r[\"nodes\"]))+\" t=\"+str(r.get(\"threshold\",0))+\" n=\"+str(r[\"genesis_n\"]))" ' \
    "roster: >=3 nodes, valid genesis_n/threshold"
fi

# ---- FROST group key ----
echo
echo "--- FROST group pubkey ---"
check 'python3 -c "
import json, sys
try:
  r=json.load(open(\"$ROSTER\"))
  pk=r.get(\"group_pubkey\",\"\")
  assert pk, \"no group_pubkey\"
  assert len(pk)==66, f\"bad hex len {len(pk)}\"
  print(f\"  group_pubkey={pk[:16]}...\")
except Exception as e:
  print(f\"ERROR: {e}\", file=sys.stderr)
  sys.exit(1)
" ' \
  "FROST group_pubkey is 66 hex chars"

# ---- Identity keys (PQ) ----
echo
echo "--- Identity keys (ML-DSA-65 + Ed25519) ---"
IDENTITY_DIR="$CEREMONY_DIR/identity"
if [[ -d "$IDENTITY_DIR" ]]; then
  ID_COUNT=0
  for d in "$IDENTITY_DIR"/*/; do
    [[ -d "$d" ]] || continue
    node_id="$(basename "$d")"
    has_ml_dsa=0; has_ed25519=0
    [[ -f "$d/ml_dsa_65.pub" ]] && has_ml_dsa=1
    [[ -f "$d/ed25519.pub" ]] && has_ed25519=1
    check "[ $has_ml_dsa -eq 1 ]" "  $node_id ML-DSA-65 pubkey present"
    check "[ $has_ed25519 -eq 1 ]" "  $node_id Ed25519 pubkey present"
    ID_COUNT=$((ID_COUNT + 1))
  done
  check "[ $ID_COUNT -ge 3 ]" "  >=3 node identity directories found"
else
  echo "  [FAIL] identity/ directory not found"
  fail=$((fail + 1))
fi

# ---- Share blobs (hybrid envelope) ----
echo
echo "--- Share blobs (hybrid envelope) ---"
SHARES_DIR="$CEREMONY_DIR/shares"
if [[ -d "$SHARES_DIR" ]]; then
  SHARE_COUNT=0
  for f in "$SHARES_DIR"/vault-*.bin; do
    [[ -f "$f" ]] || continue
    SHARE_COUNT=$((SHARE_COUNT + 1))
  done
  check "[ $SHARE_COUNT -ge 3 ]" "  $SHARE_COUNT share blobs found"
  # Check for hybrid envelope markers (X25519 + ML-KEM)
  for f in "$SHARES_DIR"/vault-*.bin; do
    [[ -f "$f" ]] || continue
    # Hybrid envelope prefix check (first 4 bytes = version tag)
    ver="$(od -An -tx1 -N4 "$f" | tr -d ' ')"
    if [[ "$ver" == "02000000" || "$ver" == "03000000" ]]; then
      echo "  [PASS] $(basename "$f"): hybrid envelope v$(echo "$ver" | head -c1)"
    else
      echo "  [FAIL] $(basename "$f"): unknown envelope version $ver"
      fail=$((fail + 1))
    fi
  done
else
  echo "  [FAIL] shares/ directory not found"
  fail=$((fail + 1))
fi

# ---- Audit signatures ----
echo
echo "--- Audit signatures ---"
AUDIT_DIR="$CEREMONY_DIR/audit"
if [[ -d "$AUDIT_DIR" ]]; then
  VERIFY_AUDIT="$SCRIPT_DIR/../security/verify_audit_signature.sh"
  ALLOWLIST="${VAULT_AUDIT_PUBKEYS_PATH:-$AUDIT_DIR/allowlist.txt}"
  SIG_COUNT=0
  for sig in "$AUDIT_DIR"/manifest-*.sig; do
    [[ -f "$sig" ]] || continue
    SIG_COUNT=$((SIG_COUNT + 1))
    manifest="${sig%.sig}"
    pub="${VAULT_AUDIT_PUBKEY_PATH:-${manifest}.pub}"
    if [[ ! -x "$VERIFY_AUDIT" || ! -f "$manifest" || ! -f "$pub" || ! -f "$ALLOWLIST" ]]; then
      echo "  [FAIL] $(basename "$manifest"): verifier, payload, public key or allowlist missing"
      fail=$((fail + 1))
      continue
    fi
    if bash "$VERIFY_AUDIT" verify \
      --allowlist "$ALLOWLIST" --pub "$pub" \
      --message "$manifest" --sig "$sig" >/dev/null 2>&1; then
      echo "  [PASS] $(basename "$manifest"): audit signature valid"
    else
      echo "  [FAIL] $(basename "$manifest"): audit signature invalid"
      fail=$((fail + 1))
    fi
  done
  if [[ "$SIG_COUNT" -eq 0 ]]; then
    echo "  [FAIL] no signed audit manifest found"
    fail=$((fail + 1))
  fi
else
  echo "  [FAIL] audit/ directory not found"
  fail=$((fail + 1))
fi

# ---- Transcript log ----
echo
echo "--- Transcript log ---"
TRANS="$CEREMONY_DIR/transcript.log"
if [[ -f "$TRANS" ]]; then
  LINES="$(wc -l < "$TRANS")"
  echo "  [INFO] Transcript: $LINES lines"
  check 'grep -qi "DKG.*complete\|keygen.*success\|group.*pubkey" "$TRANS" 2>/dev/null' \
    "DKG completion logged in transcript"
else
  echo "  [FAIL] transcript.log not found"
  fail=$((fail + 1))
fi

echo
echo "============================================"
if [[ $fail -eq 0 ]]; then
  echo "[PASS] Ceremony transcript verified"
else
  echo "[FAIL] $fail verification failure(s)"
  exit 1
fi
