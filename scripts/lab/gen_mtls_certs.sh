#!/usr/bin/env bash
# Generate lab-only CA + vault server/client certs for VAULT_AUTH_MODE=mtls.
# Emits flat paths (compose) + SPIFFE-like SVID tree. Lab ≠ go-live.
#
# Unique per-vault SPIFFE (recommended Gate path):
#   VAULT_MTLS_NODE_IDS=vault-1,vault-2,vault-3 ./scripts/gen_lab_mtls_certs.sh
# Shared lab alias (legacy visualize): omit VAULT_MTLS_NODE_IDS_UNIQUE=1
# Ceremony profile: prefer ./scripts/gen_ceremony_mtls_certs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VAULT_ROOT="$REPO_ROOT"
# shellcheck source=../lib/mtls_cert_lib.sh
source "$SCRIPT_DIR/../lib/mtls_cert_lib.sh"

OUT_DIR="${VAULT_LAB_MTLS_OUT:-$VAULT_ROOT/var/lab-certs}"
DAYS="${VAULT_LAB_MTLS_DAYS:-825}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.lab}"
CN_SERVER="${VAULT_LAB_MTLS_SERVER_CN:-kerosene-vault-lab}"
CN_CLIENT="${VAULT_LAB_MTLS_CLIENT_CN:-kerosene-kfe-lab}"
P12_PASS="${VAULT_LAB_MTLS_P12_PASSWORD:-changeit}"
SPIFFE_KFE="${VAULT_MTLS_SPIFFE_KFE:-spiffe://${TRUST_DOMAIN}/kfe}"
# Default: unique per-node SPIFFE. Set VAULT_MTLS_SHARED_SPIFFE=1 for legacy vault/server alias.
UNIQUE="${VAULT_MTLS_SHARED_SPIFFE:-0}"
NODE_IDS_CSV="$(mtls_default_node_ids)"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "[1/5] Lab root CA → $OUT_DIR/ca.crt"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" -out ca.crt \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Mesh/CN=Kerosene Lab Vault CA"

SPIFFE_PAIRS=()
EXTRA_BASE="DNS:localhost,DNS:vault-1,DNS:vault-2,DNS:vault-3,DNS:$CN_SERVER,IP:127.0.0.1"
EXTRA_BASE="$(mtls_onion_extra_san "$EXTRA_BASE" "${VAULT_LAB_MTLS_ONION_SANS:-}")"

if [[ "$UNIQUE" == "1" ]]; then
  SPIFFE_VAULT="${VAULT_MTLS_SPIFFE_VAULT:-spiffe://${TRUST_DOMAIN}/vault/server}"
  echo "[2/5] Shared vault server cert (legacy SPIFFE=$SPIFFE_VAULT)"
  mtls_issue_leaf \
    "vault-server" "$CN_SERVER" "serverAuth" "$SPIFFE_VAULT" "$DAYS" \
    "$EXTRA_BASE"
  SPIFFE_PAIRS+=("server=${SPIFFE_VAULT}")
else
  echo "[2/5] Unique vault leaves (SPIFFE per node under $TRUST_DOMAIN)"
  IFS=',' read -r -a NODE_IDS <<< "${NODE_IDS_CSV}"
  for node_id in "${NODE_IDS[@]}"; do
    node_id="$(echo "$node_id" | tr -d '[:space:]')"
    [[ -n "$node_id" ]] || continue
    spiffe_id="spiffe://${TRUST_DOMAIN}/vault/${node_id}"
    mkdir -p "nodes/${node_id}"
    EXTRA_SAN="$(mtls_onion_extra_san "DNS:localhost,DNS:${node_id},DNS:vault-1,DNS:vault-2,DNS:vault-3,IP:127.0.0.1" "${VAULT_LAB_MTLS_ONION_SANS:-}")"
    (
      cd "nodes/${node_id}"
      cp -f ../../ca.crt ../../ca.key .
      mtls_issue_leaf "server" "${node_id}" "serverAuth" "$spiffe_id" "$DAYS" "$EXTRA_SAN"
      mtls_issue_leaf "client" "${node_id}-client" "clientAuth" "$spiffe_id" "$DAYS" \
        "DNS:localhost,DNS:${node_id}"
      rm -f ca.key
      chmod 0600 server.key client.key
    )
    SPIFFE_PAIRS+=("${node_id}=${spiffe_id}")
  done
  FIRST="${NODE_IDS[0]// /}"
  cp -f "nodes/${FIRST}/server.crt" vault-server.crt
  cp -f "nodes/${FIRST}/server.key" vault-server.key
  chmod 0600 vault-server.key
  SPIFFE_VAULT="spiffe://${TRUST_DOMAIN}/vault/${FIRST}"
fi

echo "[3/5] Vault client cert for kfe↔vault (CN=$CN_CLIENT, SPIFFE=$SPIFFE_KFE)"
mtls_issue_leaf \
  "vault-client" "$CN_CLIENT" "clientAuth" "$SPIFFE_KFE" "$DAYS" \
  "DNS:localhost,DNS:$CN_CLIENT"

echo "[4/5] Java materials (PKCS#8 + PKCS12) + SPIFFE-like tree"
mtls_write_java_materials "$OUT_DIR" "$P12_PASS"
mtls_sync_spiffe_tree "$OUT_DIR" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"
mtls_write_rotation_json "$OUT_DIR" "$((DAYS * 24))" "$SPIFFE_KFE" "${SPIFFE_PAIRS[@]}"

chmod 0600 ca.key vault-server.key vault-client.key vault-client.pkcs8.key 2>/dev/null || true
chmod 0600 kfe-client.p12 truststore.p12 2>/dev/null || true

ALLOWLIST=""
for pair in "${SPIFFE_PAIRS[@]}"; do
  sid="${pair#*=}"
  if [[ -z "$ALLOWLIST" ]]; then ALLOWLIST="$sid"; else ALLOWLIST="${ALLOWLIST},${sid}"; fi
done

echo "[5/5] Env hint (lab / staging visualize):"
cat <<EOF
  VAULT_AUTH_MODE=mtls
  VAULT_TLS_CERT_PATH=$OUT_DIR/vault-server.crt
  VAULT_TLS_KEY_PATH=$OUT_DIR/vault-server.key
  VAULT_TLS_CLIENT_CA_PATH=$OUT_DIR/ca.crt
  VAULT_TLS_PEER_SPIFFE_ID=${ALLOWLIST}
  # kfe (PEM):
  #   kfe.vaultmesh.tls.enabled=true
  #   kfe.vaultmesh.tls.cert-path=$OUT_DIR/vault-client.crt
  #   kfe.vaultmesh.tls.key-path=$OUT_DIR/vault-client.pkcs8.key
  #   kfe.vaultmesh.tls.ca-path=$OUT_DIR/ca.crt
  # Ceremony CA (unique SPIFFE + short TTL): ./scripts/gen_ceremony_mtls_certs.sh
  # SPIFFE-like: $OUT_DIR/spiffe/ (see docs/MTLS_SPIFFE_LAYOUT.md)
Lab mTLS materials written to $OUT_DIR (not for mainnet).
EOF
