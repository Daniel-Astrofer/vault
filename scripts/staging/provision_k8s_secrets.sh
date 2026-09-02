#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${KEROSENE_STAGING_NAMESPACE:-kerosene-staging}"
CERT_DIR="${VAULT_CEREMONY_MTLS_OUT:-}"
KUBECTL_BIN="${KUBECTL:-kubectl}"

if [[ -z "$CERT_DIR" ]]; then
  echo "Set VAULT_CEREMONY_MTLS_OUT to a ceremony certificate directory." >&2
  exit 2
fi

for command_name in "$KUBECTL_BIN" openssl; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command not found: $command_name" >&2
    exit 127
  }
done

for required_file in ca.crt vault-client.crt vault-client.pkcs8.key; do
  [[ -s "$CERT_DIR/$required_file" ]] || {
    echo "Missing ceremony file: $CERT_DIR/$required_file" >&2
    exit 2
  }
done

"$KUBECTL_BIN" create namespace "$NAMESPACE" \
  --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f - >/dev/null

for secret_file in jwt-secret aes-secret password-pepper attestation-root kfe-column-crypto-key; do
  if [[ ! -s "$CERT_DIR/$secret_file" ]]; then
    umask 077
    if [[ "$secret_file" == "aes-secret" || "$secret_file" == "kfe-column-crypto-key" ]]; then
      openssl rand -base64 32 > "$CERT_DIR/$secret_file"
    else
      openssl rand -base64 48 > "$CERT_DIR/$secret_file"
    fi
  fi
  chmod 0600 "$CERT_DIR/$secret_file"
done

jwt_secret_b64="$(base64 -w0 < "$CERT_DIR/jwt-secret")"
aes_secret_b64="$(base64 -w0 < "$CERT_DIR/aes-secret")"
password_pepper_b64="$(base64 -w0 < "$CERT_DIR/password-pepper")"
kfe_column_crypto_key_b64="$(base64 -w0 < "$CERT_DIR/kfe-column-crypto-key")"
secret_patch="$(printf '{"data":{"jwt-secret":"%s","aes-secret":"%s","password-pepper":"%s","kfe-column-crypto-key":"%s"}}' \
  "$jwt_secret_b64" "$aes_secret_b64" "$password_pepper_b64" "$kfe_column_crypto_key_b64")"
"$KUBECTL_BIN" -n "$NAMESPACE" patch secret server-secrets \
  --type=merge -p "$secret_patch" >/dev/null

"$KUBECTL_BIN" -n "$NAMESPACE" create secret generic kfe-vault-mtls-certs \
  --from-file=ca.crt="$CERT_DIR/ca.crt" \
  --from-file=vault-client.crt="$CERT_DIR/vault-client.crt" \
  --from-file=vault-client.pkcs8.key="$CERT_DIR/vault-client.pkcs8.key" \
  --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f - >/dev/null

for vault_id in 1 2 3; do
  node_dir="$CERT_DIR/nodes/vault-${vault_id}"
  for required_file in server.crt server.key client.crt client.key; do
    [[ -s "$node_dir/$required_file" ]] || {
      echo "Missing vault-${vault_id} ceremony file: $node_dir/$required_file" >&2
      exit 2
    }
  done

  passphrase_file="$node_dir/data-passphrase"
  if [[ ! -s "$passphrase_file" ]]; then
    umask 077
    openssl rand -base64 48 > "$passphrase_file"
  fi
  chmod 0600 "$passphrase_file"

  "$KUBECTL_BIN" -n "$NAMESPACE" create secret generic "vault-${vault_id}-secrets" \
    --from-file=data-passphrase="$passphrase_file" \
    --from-file=attestation-root="$CERT_DIR/attestation-root" \
    --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f - >/dev/null

  "$KUBECTL_BIN" -n "$NAMESPACE" create secret generic "vault-${vault_id}-mtls-certs" \
    --from-file=ca.crt="$CERT_DIR/ca.crt" \
    --from-file=vault-server.crt="$node_dir/server.crt" \
    --from-file=vault-server.key="$node_dir/server.key" \
    --from-file=vault-client.crt="$node_dir/client.crt" \
    --from-file=vault-client.key="$node_dir/client.key" \
    --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f - >/dev/null
done

echo "Vault staging secrets provisioned in namespace $NAMESPACE."
echo "Secret values were not printed. Back up the ceremony directory securely."
