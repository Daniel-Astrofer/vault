#!/usr/bin/env bash
set -euo pipefail

# Generate X25519 key pairs for Tor HiddenServiceAuthorizeClient stealth.
# Each authorized client gets a x25519 private key + .auth file.
# Output to $OUTPUT_DIR (default: infra/runtime/tor/authorized_clients).
#
# Usage:
#   ./scripts/vault/gen_tor_auth_clients.sh [--client-count N] [--output-dir DIR]
#
# After generation, copy .auth files to Tor HS authorized_clients/ directory.
# Each operator keeps their private key secret.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLIENT_COUNT="${1:-3}"
OUTPUT_DIR="${2:-$REPO_ROOT/infra/runtime/tor/authorized_clients}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "[!] openssl required for X25519 key generation" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

HS_NAME="${VAULT_TOR_HS_NAME:-kerosene_service}"
AUTH_DIR="$OUTPUT_DIR/$HS_NAME"
mkdir -p "$AUTH_DIR"

echo "== Generating $CLIENT_COUNT Tor authorized client keys =="
echo "  Output: $AUTH_DIR"
echo ""

for i in $(seq 1 "$CLIENT_COUNT"); do
  client_name="client-$i"
  client_dir="$AUTH_DIR/$client_name"
  mkdir -p "$client_dir"

  # Generate X25519 private key
  openssl genpkey -algorithm X25519 -out "$client_dir/${client_name}.x25519.key" 2>/dev/null

  # Extract public key (raw 32 bytes) and encode as base32 for Tor
  pub_der="$(openssl pkey -in "$client_dir/${client_name}.x25519.key" -pubout -outform DER 2>/dev/null | tail -c 44 | od -An -tx1 | tr -d ' \n')"
  # Tor expects descriptor:x25519:<base32-encoded-public-key>
  # Generate an arbitrary but stable descriptor cookie
  descriptor="$(echo -n "$client_name-kerosene-vault-tor-auth" | sha256sum | head -c 16)"

  # Create .auth file: <descriptor>:x25519:<base32-pubkey>
  echo "${descriptor}:x25519:${pub_der}" > "$client_dir/${client_name}.auth"

  chmod 600 "$client_dir/${client_name}.x25519.key"
  chmod 644 "$client_dir/${client_name}.auth"

  echo "  [$client_name] descriptor=$descriptor"
  echo "    private key: $client_dir/${client_name}.x25519.key"
  echo "    .auth file:  $client_dir/${client_name}.auth"
done

echo ""
echo "[+] Generated $CLIENT_COUNT Tor authorized client keys in $AUTH_DIR"
echo ""
echo "Next steps:"
echo "  1. Copy .auth files to each Tor sidecar's authorized_clients/ directory:"
echo "     cp $AUTH_DIR/client-*.auth /var/lib/tor/$HS_NAME/authorized_clients/"
echo "  2. Distribute private keys securely to operators (offline/air-gapped)"
echo "  3. In torrc, enable: HiddenServiceAuthorizeClient stealth $HS_NAME"
echo "  4. Restart Tor daemons"
