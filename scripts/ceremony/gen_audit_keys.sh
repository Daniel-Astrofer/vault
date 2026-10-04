#!/usr/bin/env bash
# Generate mesh **audit** Ed25519 key material — separate from release cosign and
# settlement/FROST shares (F8 requirement: audit keys ≠ release ≠ settlement).
#
# Outputs under ceremony-certs/audit/ (or VAULT_AUDIT_KEYS_OUT):
#   audit-ca.pub / operators/*.key + *.pub + allowlist.txt
#
# Usage:
#   ./scripts/ceremony/gen_audit_keys.sh
#   VAULT_AUDIT_OPERATORS=ops-1,ops-2,monitor ./scripts/ceremony/gen_audit_keys.sh
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VAULT_ROOT="$REPO_ROOT"

OUT_DIR="${VAULT_AUDIT_KEYS_OUT:-${VAULT_CEREMONY_MTLS_OUT:-$VAULT_ROOT/var/ceremony-certs}/audit}"
OPERATORS_CSV="${VAULT_AUDIT_OPERATORS:-audit-ops-1,audit-ops-2,audit-monitor}"
PURPOSE="mesh-audit"

mkdir -p "$OUT_DIR/operators"
cd "$OUT_DIR"

# Marker file documents purpose separation (do not reuse for release/settlement).
cat > PURPOSE.txt <<EOF
purpose=${PURPOSE}
forbidden_reuse=release_cosign,frost_settlement,mtls_svid
f8_requirement=audit keys must be disjoint from release allowlist and settlement shares
docs=vault/docs/security/AUDIT_KEYS.md
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

ALLOWLIST="$OUT_DIR/allowlist.txt"
: > "$ALLOWLIST"

IFS=',' read -r -a OPS <<< "${OPERATORS_CSV}"
echo "[audit] generating Ed25519 operators → $OUT_DIR/operators"
for op in "${OPS[@]}"; do
  op="$(echo "$op" | tr -d '[:space:]')"
  [[ -n "$op" ]] || continue
  key="$OUT_DIR/operators/${op}.key"
  pub="$OUT_DIR/operators/${op}.pub"
  openssl genpkey -algorithm ED25519 -out "$key"
  openssl pkey -in "$key" -pubout -out "$pub"
  chmod 0600 "$key"
  # Raw 32-byte pubkey hex for runtime allowlist (SPKI DER → last 32 bytes).
  pub_hex="$(openssl pkey -pubin -in "$pub" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32)"
  if [[ -z "$pub_hex" || "${#pub_hex}" -ne 64 ]]; then
    # Fallback: fingerprint of PEM for allowlist membership checks.
    pub_hex="$(openssl pkey -pubin -in "$pub" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"
  fi
  echo "${op} ${pub_hex}" >> "$ALLOWLIST"
  echo "  ${op} pubkey_hex=${pub_hex}"
done

chmod 0644 "$ALLOWLIST" PURPOSE.txt
chmod 0750 operators

# Env snippet for vault / verify hooks.
ENV_HINT="$OUT_DIR/env.hint"
{
  echo "# F8: mesh audit pubkey allowlist (comma-separated hex)."
  echo "# Do NOT point release cosign or FROST paths at these keys."
  csv=""
  while read -r _name hex; do
    [[ -n "${hex:-}" ]] || continue
    if [[ -z "$csv" ]]; then csv="$hex"; else csv="${csv},${hex}"; fi
  done < "$ALLOWLIST"
  echo "VAULT_AUDIT_PUBKEY_ALLOWLIST=${csv}"
  echo "VAULT_AUDIT_PUBKEYS_PATH=${ALLOWLIST}"
} > "$ENV_HINT"

echo "[audit] wrote allowlist → $ALLOWLIST"
echo "[audit] source $ENV_HINT before ceremony checklist / vault boot"
echo "[audit] verify: ./scripts/security/verify_audit_signature.sh --help"
