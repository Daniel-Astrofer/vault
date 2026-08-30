#!/usr/bin/env bash
# Rotate short-lived ceremony leaves (reuses ceremony CA). Unique SPIFFE preserved.
#
# Usage:
#   ./scripts/gen_ceremony_mtls_certs.sh          # once (creates CA + leaves)
#   VAULT_CEREMONY_MTLS_TTL_HOURS=24 ./scripts/rotate_ceremony_mtls_certs.sh
#
# Optional reload hook:
#   VAULT_MTLS_ROTATE_HOOK=/path/to/hook.sh ./scripts/rotate_ceremony_mtls_certs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=mtls_cert_lib.sh
source "$SCRIPT_DIR/mtls_cert_lib.sh"

OUT_DIR="${VAULT_CEREMONY_MTLS_OUT:-${VAULT_LAB_MTLS_OUT:-$VAULT_ROOT/ceremony-certs}}"
TTL_HOURS="${VAULT_CEREMONY_MTLS_TTL_HOURS:-${VAULT_LAB_MTLS_TTL_HOURS:-24}}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.ceremony}"
P12_PASS="${VAULT_LAB_MTLS_P12_PASSWORD:-changeit}"
SPIFFE_KFE="${VAULT_MTLS_SPIFFE_KFE:-spiffe://${TRUST_DOMAIN}/kfe}"
HOOK="${VAULT_MTLS_ROTATE_HOOK:-}"
ORG="Kerosene Ceremony"
NODE_IDS_CSV="$(mtls_default_node_ids)"

if [[ ! -f "$OUT_DIR/ca.crt" || ! -f "$OUT_DIR/ca.key" ]]; then
  echo "error: ceremony CA missing under $OUT_DIR — run gen_ceremony_mtls_certs.sh first" >&2
  exit 1
fi

DAYS=$(( (TTL_HOURS + 23) / 24 ))
if [[ "$DAYS" -lt 1 ]]; then
  DAYS=1
fi

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/kerosene-ceremony-mtls-rotate.XXXXXX")"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

cp -f "$OUT_DIR/ca.crt" "$OUT_DIR/ca.key" "$STAGING/"
cd "$STAGING"

IFS=',' read -r -a NODE_IDS <<< "${NODE_IDS_CSV}"
SPIFFE_PAIRS=()

echo "[rotate] ceremony leaves TTL≈${TTL_HOURS}h → $OUT_DIR"
for node_id in "${NODE_IDS[@]}"; do
  node_id="$(echo "$node_id" | tr -d '[:space:]')"
  [[ -n "$node_id" ]] || continue
  spiffe_id="spiffe://${TRUST_DOMAIN}/vault/${node_id}"
  mkdir -p "nodes/${node_id}"
  EXTRA_SAN="DNS:localhost,DNS:${node_id},DNS:vault-1,DNS:vault-2,DNS:vault-3,IP:127.0.0.1"
  EXTRA_SAN="$(mtls_onion_extra_san "$EXTRA_SAN" "${VAULT_LAB_MTLS_ONION_SANS:-}")"
  (
    cd "nodes/${node_id}"
    cp -f ../../ca.crt ../../ca.key .
    mtls_issue_leaf "server" "${node_id}" "serverAuth" "$spiffe_id" "$DAYS" "$EXTRA_SAN" "$ORG"
    mtls_issue_leaf "client" "${node_id}-client" "clientAuth" "$spiffe_id" "$DAYS" \
      "DNS:localhost,DNS:${node_id}" "$ORG"
    rm -f ca.key
  )
  SPIFFE_PAIRS+=("${node_id}=${spiffe_id}")
done

mkdir -p kfe
(
  cd kfe
  cp -f ../ca.crt ../ca.key .
  mtls_issue_leaf "client" "kerosene-kfe" "clientAuth" "$SPIFFE_KFE" "$DAYS" \
    "DNS:localhost,DNS:kerosene-kfe" "$ORG"
  rm -f ca.key
)
cp -f kfe/client.crt vault-client.crt
cp -f kfe/client.key vault-client.key

FIRST="${NODE_IDS[0]// /}"
if [[ -n "$FIRST" && -d "nodes/${FIRST}" ]]; then
  cp -f "nodes/${FIRST}/server.crt" vault-server.crt
  cp -f "nodes/${FIRST}/server.key" vault-server.key
  cp -f "nodes/${FIRST}/client.crt" vault-peer-client.crt
  cp -f "nodes/${FIRST}/client.key" vault-peer-client.key
fi

mtls_write_java_materials "$STAGING" "$P12_PASS" \
  "$STAGING/vault-client.key" "$STAGING/vault-client.crt" \
  "$STAGING/vault-client.pkcs8.key" "$STAGING/kfe-client.p12" "$STAGING/truststore.p12"
mtls_sync_spiffe_tree "$STAGING" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"
mtls_write_rotation_json "$STAGING" "$TTL_HOURS" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"

# Publish leaves; never overwrite CA from staging.
mkdir -p "$OUT_DIR/nodes" "$OUT_DIR/kfe"
rm -rf "$OUT_DIR/nodes" "$OUT_DIR/spiffe"
cp -a nodes "$OUT_DIR/nodes"
cp -a spiffe "$OUT_DIR/spiffe"
cp -a kfe/. "$OUT_DIR/kfe/"
install -m 0644 vault-server.crt vault-client.crt vault-peer-client.crt "$OUT_DIR/" 2>/dev/null || \
  install -m 0644 vault-client.crt "$OUT_DIR/"
install -m 0600 vault-server.key vault-client.key vault-peer-client.key \
  vault-client.pkcs8.key "$OUT_DIR/" 2>/dev/null || \
  install -m 0600 vault-client.key vault-client.pkcs8.key "$OUT_DIR/"
install -m 0600 kfe-client.p12 truststore.p12 "$OUT_DIR/"
mtls_write_rotation_json "$OUT_DIR" "$TTL_HOURS" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"

export VAULT_CEREMONY_MTLS_OUT="$OUT_DIR"
export VAULT_LAB_MTLS_OUT="$OUT_DIR"
export VAULT_TLS_CERT_PATH="$OUT_DIR/vault-server.crt"
export VAULT_TLS_KEY_PATH="$OUT_DIR/vault-server.key"
export VAULT_TLS_CLIENT_CA_PATH="$OUT_DIR/ca.crt"
export KFE_CLIENT_P12="$OUT_DIR/kfe-client.p12"
export ROTATION_JSON="$OUT_DIR/rotation.json"

echo "[rotate] published ceremony leaves + SPIFFE tree under $OUT_DIR"
cat "$OUT_DIR/rotation.json"

if [[ -n "$HOOK" ]]; then
  if [[ ! -x "$HOOK" ]]; then
    echo "error: VAULT_MTLS_ROTATE_HOOK is not executable: $HOOK" >&2
    exit 1
  fi
  echo "[rotate] invoking hook $HOOK"
  "$HOOK"
fi

echo "[rotate] done — restart/reload vault + kfe TLS materials"
