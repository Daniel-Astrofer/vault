#!/usr/bin/env bash
set -euo pipefail

# Generate staging mTLS certs automatically for vault-mesh-staging compose.
# Uses mtls_cert_lib.sh for CA + per-vault server/client certs.
# Called by ensure-vault-mesh-lab.sh when KEROSENE_VAULT_MESH_PROFILE=staging.
#
# Usage:
#   ./scripts/vault/gen_staging_mtls_certs.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=mtls_cert_lib.sh
if [[ -f "$SCRIPT_DIR/mtls_cert_lib.sh" ]]; then
  source "$SCRIPT_DIR/mtls_cert_lib.sh"
fi

OUT_DIR="${VAULT_STAGING_MTLS_OUT:-$VAULT_ROOT/lab-certs}"
DAYS="${VAULT_STAGING_MTLS_DAYS:-365}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.lab}"
CA_CN="${VAULT_STAGING_CA_CN:-kerosene-staging-ca}"
SERVER_CN="${VAULT_STAGING_SERVER_CN:-kerosene-vault-staging}"
CLIENT_CN="${VAULT_STAGING_CLIENT_CN:-kerosene-kfe-staging}"
P12_PASS="${VAULT_STAGING_P12_PASSWORD:-changeit}"

echo "== Staging mTLS Cert Gen =="
echo "  Output: $OUT_DIR"
echo "  Days: $DAYS"
echo "  Trust domain: $TRUST_DOMAIN"

mkdir -p "$OUT_DIR"

# Check if certs already exist and are valid
if [[ -f "$OUT_DIR/vault-server.crt" && -f "$OUT_DIR/vault-server.key" ]]; then
  if openssl x509 -checkend 86400 -noout -in "$OUT_DIR/vault-server.crt" 2>/dev/null; then
    echo "[+] Staging certs already exist and are valid (24h+ remaining)."
    exit 0
  else
    echo "[!] Existing staging certs expired or near expiry. Regenerating..."
    rm -f "$OUT_DIR/ca.crt" "$OUT_DIR/ca.key" "$OUT_DIR/vault-server."* "$OUT_DIR/vault-client."*
  fi
fi

echo "--- Generating staging CA ---"
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
  -keyout "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
  -subj "/CN=$CA_CN/O=Kerosene Staging/C=BR" 2>/dev/null

echo "--- Generating staging vault server cert ---"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT_DIR/vault-server.key" -out "$OUT_DIR/vault-server.csr" \
  -subj "/CN=$SERVER_CN/O=Kerosene Staging/C=BR" 2>/dev/null

# Add SPIFFE URI SAN
cat > "$OUT_DIR/vault-server.ext" <<EXTS
subjectAltName=DNS:localhost,DNS:vault-1,DNS:vault-2,DNS:vault-3,IP:127.0.0.1,URI:spiffe://${TRUST_DOMAIN}/vault/server
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
EXTS

openssl x509 -req -in "$OUT_DIR/vault-server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/vault-server.crt" -days "$DAYS" -sha256 \
  -extfile "$OUT_DIR/vault-server.ext" 2>/dev/null
rm -f "$OUT_DIR/vault-server.csr" "$OUT_DIR/vault-server.ext"

echo "--- Generating staging vault client cert ---"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT_DIR/vault-client.key" -out "$OUT_DIR/vault-client.csr" \
  -subj "/CN=$CLIENT_CN/O=Kerosene Staging/C=BR" 2>/dev/null

cat > "$OUT_DIR/vault-client.ext" <<EXTS
subjectAltName=URI:spiffe://${TRUST_DOMAIN}/kfe
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EXTS

openssl x509 -req -in "$OUT_DIR/vault-client.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/vault-client.crt" -days "$DAYS" -sha256 \
  -extfile "$OUT_DIR/vault-client.ext" 2>/dev/null
rm -f "$OUT_DIR/vault-client.csr" "$OUT_DIR/vault-client.ext"

# Set restrictive permissions
chmod 600 "$OUT_DIR/ca.key" "$OUT_DIR/vault-server.key" "$OUT_DIR/vault-client.key"
chmod 644 "$OUT_DIR/ca.crt" "$OUT_DIR/vault-server.crt" "$OUT_DIR/vault-client.crt"

echo "[+] Staging mTLS certs generated in $OUT_DIR"
echo "  CA:        $OUT_DIR/ca.crt"
echo "  Server:    $OUT_DIR/vault-server.crt + .key"
echo "  Client:    $OUT_DIR/vault-client.crt + .key"
echo "  Expiry:    $(openssl x509 -enddate -noout -in "$OUT_DIR/vault-server.crt" | cut -d= -f2)"
