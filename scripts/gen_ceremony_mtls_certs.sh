#!/usr/bin/env bash
# Ceremony / Gate CA: unique SPIFFE ID per vault node + kfe, short-lived leaves.
# Lab/openssl CA is accepted for Gate visualize; production checklist requires
# SPIRE-like identities (unique URI SANs + rotation). Drop-in SPIRE later uses
# the same spiffe:// paths under ceremony-certs/spiffe/.
#
# Usage:
#   ./scripts/gen_ceremony_mtls_certs.sh
#   VAULT_MTLS_NODE_IDS=vault-1,vault-2,vault-3 \
#   VAULT_MTLS_TRUST_DOMAIN=kerosene.ceremony \
#   VAULT_CEREMONY_MTLS_TTL_HOURS=24 \
#     ./scripts/gen_ceremony_mtls_certs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=mtls_cert_lib.sh
source "$SCRIPT_DIR/mtls_cert_lib.sh"

OUT_DIR="${VAULT_CEREMONY_MTLS_OUT:-${VAULT_LAB_MTLS_OUT:-$VAULT_ROOT/ceremony-certs}}"
TTL_HOURS="${VAULT_CEREMONY_MTLS_TTL_HOURS:-${VAULT_LAB_MTLS_TTL_HOURS:-24}}"
CA_DAYS="${VAULT_CEREMONY_MTLS_CA_DAYS:-825}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.ceremony}"
P12_PASS="${VAULT_LAB_MTLS_P12_PASSWORD:-changeit}"
SPIFFE_KFE="${VAULT_MTLS_SPIFFE_KFE:-spiffe://${TRUST_DOMAIN}/kfe}"
ORG="Kerosene Ceremony"
NODE_IDS_CSV="$(mtls_default_node_ids)"

# OpenSSL -days is day-granularity; ceil hours → days (min 1).
DAYS=$(( (TTL_HOURS + 23) / 24 ))
if [[ "$DAYS" -lt 1 ]]; then
  DAYS=1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "[1/5] Ceremony CA (SPIRE-equivalent trust anchor) → $OUT_DIR/ca.crt"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$CA_DAYS" -out ca.crt \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=${ORG}/OU=Vault Mesh Ceremony/CN=Kerosene Ceremony Vault CA"

IFS=',' read -r -a NODE_IDS <<< "${NODE_IDS_CSV}"
SPIFFE_PAIRS=()

echo "[2/5] Unique vault leaves (TTL≈${TTL_HOURS}h, openssl days=${DAYS})"
for node_id in "${NODE_IDS[@]}"; do
  node_id="$(echo "$node_id" | tr -d '[:space:]')"
  [[ -n "$node_id" ]] || continue
  spiffe_id="spiffe://${TRUST_DOMAIN}/vault/${node_id}"
  mkdir -p "nodes/${node_id}"
  EXTRA_SAN="DNS:localhost,DNS:${node_id},DNS:vault-1,DNS:vault-2,DNS:vault-3,IP:127.0.0.1"
  EXTRA_SAN="$(mtls_onion_extra_san "$EXTRA_SAN" "${VAULT_LAB_MTLS_ONION_SANS:-}")"

  # Server leaf (listen) + client leaf (outbound peer) share the same SPIFFE ID.
  (
    cd "nodes/${node_id}"
    cp -f ../../ca.crt ../../ca.key .
    mtls_issue_leaf "server" "${node_id}" "serverAuth" "$spiffe_id" "$DAYS" "$EXTRA_SAN" "$ORG"
    mtls_issue_leaf "client" "${node_id}-client" "clientAuth" "$spiffe_id" "$DAYS" \
      "DNS:localhost,DNS:${node_id}" "$ORG"
    rm -f ca.key
    chmod 0600 server.key client.key
  )
  SPIFFE_PAIRS+=("${node_id}=${spiffe_id}")
  echo "  ${node_id} → ${spiffe_id}"
done

# Flat convenience aliases for first node (compose default mount paths).
FIRST="${NODE_IDS[0]// /}"
if [[ -n "$FIRST" && -d "nodes/${FIRST}" ]]; then
  cp -f "nodes/${FIRST}/server.crt" vault-server.crt
  cp -f "nodes/${FIRST}/server.key" vault-server.key
  cp -f "nodes/${FIRST}/client.crt" vault-peer-client.crt
  cp -f "nodes/${FIRST}/client.key" vault-peer-client.key
  chmod 0600 vault-server.key vault-peer-client.key
fi

echo "[3/5] kfe client leaf (SPIFFE=$SPIFFE_KFE)"
mkdir -p kfe
(
  cd kfe
  cp -f ../ca.crt ../ca.key .
  mtls_issue_leaf "client" "kerosene-kfe" "clientAuth" "$SPIFFE_KFE" "$DAYS" \
    "DNS:localhost,DNS:kerosene-kfe" "$ORG"
  rm -f ca.key
  chmod 0600 client.key
)
cp -f kfe/client.crt vault-client.crt
cp -f kfe/client.key vault-client.key
chmod 0600 vault-client.key

echo "[4/5] Java materials + SPIFFE tree"
mtls_write_java_materials "$OUT_DIR" "$P12_PASS" \
  "$OUT_DIR/vault-client.key" "$OUT_DIR/vault-client.crt" \
  "$OUT_DIR/vault-client.pkcs8.key" "$OUT_DIR/kfe-client.p12" "$OUT_DIR/truststore.p12"
mtls_sync_spiffe_tree "$OUT_DIR" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"
mtls_write_rotation_json "$OUT_DIR" "$TTL_HOURS" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"

chmod 0600 ca.key 2>/dev/null || true
chmod 0600 kfe-client.p12 truststore.p12 2>/dev/null || true

# Peer SPIFFE allowlist hint for vault runtime (comma-separated).
ALLOWLIST=""
for pair in "${SPIFFE_PAIRS[@]}"; do
  sid="${pair#*=}"
  if [[ -z "$ALLOWLIST" ]]; then
    ALLOWLIST="$sid"
  else
    ALLOWLIST="${ALLOWLIST},${sid}"
  fi
done

echo "[5/5] Ceremony env hint (unique SPIFFE; do not enable mainnet here):"
cat <<EOF
  VAULT_AUTH_MODE=mtls
  VAULT_MTLS_TRUST_DOMAIN=${TRUST_DOMAIN}
  VAULT_TLS_PEER_SPIFFE_ID=${ALLOWLIST}
  VAULT_TLS_VERIFY_MODE=onion_or_spiffe   # Tor ceremony
  # Per-node mount example (vault-2):
  #   VAULT_TLS_CERT_PATH=$OUT_DIR/nodes/vault-2/server.crt
  #   VAULT_TLS_KEY_PATH=$OUT_DIR/nodes/vault-2/server.key
  #   VAULT_TLS_CLIENT_CERT_PATH=$OUT_DIR/nodes/vault-2/client.crt
  #   VAULT_TLS_CLIENT_KEY_PATH=$OUT_DIR/nodes/vault-2/client.key
  #   VAULT_TLS_CLIENT_CA_PATH=$OUT_DIR/ca.crt
  # kfe:
  #   kfe.vaultmesh.tls.cert-path=$OUT_DIR/vault-client.crt
  #   kfe.vaultmesh.tls.key-path=$OUT_DIR/vault-client.pkcs8.key
  #   kfe.vaultmesh.tls.ca-path=$OUT_DIR/ca.crt
  # Rotate leaves:
  #   VAULT_CEREMONY_MTLS_TTL_HOURS=24 ./scripts/rotate_ceremony_mtls_certs.sh
  # SPIFFE tree: $OUT_DIR/spiffe/
Ceremony mTLS materials written to $OUT_DIR (testnet/ceremony Gate — not mainnet).
EOF
