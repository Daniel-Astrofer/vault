#!/usr/bin/env bash
# Staging ceremony: start 3 vault nodes in ceremony mode + execute DKG
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CEREMONY_CERTS="${VAULT_CEREMONY_DIR:-$REPO_ROOT/var/ceremony-certs}"
VAULT_BIN="${VAULT_BIN:-$REPO_ROOT/target/debug/kerosene-vault}"
STAGING_DATA="${VAULT_STAGING_DATA_DIR:-$REPO_ROOT/var/staging}"
AUDIT_PUBKEYS="${CEREMONY_CERTS}/audit/allowlist.txt"

# Node port map
declare -A PORTS=( ["vault-1"]="7801" ["vault-2"]="7802" ["vault-3"]="7803" )

cleanup() {
  echo ""
  echo "=== Cleaning up vault processes ==="
  for pid in "${VAULT_PIDS[@]-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "=== Cleanup complete ==="
}

VAULT_PIDS=()

echo "============================================================"
echo "  Kerosene Vault - Staging Ceremony Mode"
echo "  Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# Common ceremony env (matches vault-mesh-ceremony.compose.yaml semantics)
export KEROSENE_ENV=staging
export VAULT_CEREMONY_MODE=staging
export VAULT_DKG_MODE=distributed_wire
export VAULT_GENESIS_N=3
export VAULT_NODE_TIER=domestic
export ATTESTATION_MODE=software
export VAULT_SHARE_STORE=aead_disk
export VAULT_AUTH_MODE=mtls
export VAULT_TRANSPORT=clearnet
export VAULT_MTLS_TRUST_DOMAIN=kerosene.ceremony
export VAULT_TLS_VERIFY_MODE=hostname
export VAULT_AUDIT_PUBKEYS_PATH="${AUDIT_PUBKEYS}"
export BITCOIN_NETWORK=testnet3
export LAB_ATTESTATION_ROOT=kerosene-ceremony-root
export VAULT_TLS_CLIENT_CA_PATH="${CEREMONY_CERTS}/ca.crt"

echo "Starting 3 vault nodes..."
echo ""

for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  data_dir="${STAGING_DATA}/${node}/data"
  mkdir -p "$data_dir"

  echo "--- $node (port $port) ---"

  export VAULT_NODE_ID="$node"
  export VAULT_LISTEN_ADDR="127.0.0.1:${port}"
  export VAULT_TLS_CERT_PATH="${CEREMONY_CERTS}/nodes/${node}/server.crt"
  export VAULT_TLS_KEY_PATH="${CEREMONY_CERTS}/nodes/${node}/server.key"
  export VAULT_TLS_CLIENT_CERT_PATH="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  export VAULT_TLS_CLIENT_KEY_PATH="${CEREMONY_CERTS}/nodes/${node}/client.key"
  export VAULT_DATA_DIR="${data_dir}"
  export VAULT_DATA_PASSPHRASE="${STAGING_DATA}/${node}/data-passphrase"
  export LAB_ATTESTATION_ROOT="${STAGING_DATA}/${node}"

  # Seed peers (exclude self, HTTPS due to mTLS)
  SEED_PARTS=()
  for peer in vault-1 vault-2 vault-3; do
    [[ "$peer" == "$node" ]] && continue
    pport="${PORTS[$peer]}"
    SEED_PARTS+=("${peer}=https://localhost:${pport}")
  done
  IFS=',' eval 'VAULT_SEED_PEERS="${SEED_PARTS[*]}"'
  export VAULT_SEED_PEERS

  # Write data passphrase file
  echo -n "staging-ceremony-passphrase-2026" > "${VAULT_DATA_PASSPHRASE}"

  echo "  VAULT_SEED_PEERS=${VAULT_SEED_PEERS}"

  "$VAULT_BIN" &
  pid=$!
  VAULT_PIDS+=("$pid")
  echo "  PID=$pid"
  echo ""
  sleep 2
done

trap cleanup EXIT INT TERM

echo "=== Waiting for vault nodes to become healthy ==="
for attempt in $(seq 1 20); do
  all_healthy=true
  for node in vault-1 vault-2 vault-3; do
    port="${PORTS[$node]}"
    client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
    client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"
    if ! curl -skf --connect-timeout 2 \
      --cert "$client_cert" --key "$client_key" \
      --cacert "${CEREMONY_CERTS}/ca.crt" \
      "https://localhost:${port}/v1/health" >/dev/null 2>&1; then
      all_healthy=false
      break
    fi
  done
  if $all_healthy; then
    echo "  All nodes healthy after ${attempt} attempts!"
    break
  fi
  if [[ "$attempt" -eq 20 ]]; then
    echo "  ERROR: Not all nodes became healthy"
    cleanup
    exit 1
  fi
  sleep 2
done

echo ""
echo "============================================================"
echo "  Staging mesh ready - executing DKG ceremony"
echo "============================================================"
echo ""

SESSION_ID="staging-ceremony-$(date +%s)"
echo "Session: $SESSION_ID"

# Step 1: Start round1 on each node
echo "[1/6] Starting DKG round1..."
declare -A PKGS
for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"

  R1=$(curl -sk -X POST "https://localhost:${port}/v1/dkg/round1" \
    --cert "$client_cert" --key "$client_key" \
    --cacert "${CEREMONY_CERTS}/ca.crt" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Node-Id: ${node}" \
    -d "$(printf '{"session_id":"%s","roster":["vault-1","vault-2","vault-3"],"max_signers":3,"min_signers":2,"fanout":false}' "$SESSION_ID")" 2>&1)

  PKGS["$node"]="$R1"
  echo "  $node: started round1"
done

# Step 2: Exchange round1 packages
echo "[2/6] Exchanging round1 packages..."
for sender in vault-1 vault-2 vault-3; do
  PKG_JSON="${PKGS[$sender]}"
  PKG_HEX=$(echo "$PKG_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['package_hex'])")
  SENDER_ID=$(echo "$PKG_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['sender_identifier'])")
  TRANS_HEX=$(echo "$PKG_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['transcript_hex'])")

  for recipient in vault-1 vault-2 vault-3; do
    [[ "$recipient" == "$sender" ]] && continue
    rport="${PORTS[$recipient]}"
    rcert="${CEREMONY_CERTS}/nodes/${recipient}/client.crt"
    rkey="${CEREMONY_CERTS}/nodes/${recipient}/client.key"

    curl -sk -X POST "https://localhost:${rport}/v1/dkg/round1" \
      --cert "$rcert" --key "$rkey" \
      --cacert "${CEREMONY_CERTS}/ca.crt" \
      -H "Content-Type: application/json" \
      -H "X-Vault-Node-Id: ${sender}" \
      -d "$(printf '{"session_id":"%s","package_hex":"%s","sender_node_id":"%s","sender_identifier":%s,"max_signers":3,"min_signers":2,"transcript_hex":"%s"}' "$SESSION_ID" "$PKG_HEX" "$sender" "$SENDER_ID" "$TRANS_HEX")" > /dev/null 2>&1
  done
  echo "  $sender: sent to peers"
done

# Step 3: Collect round2 outbound packages
echo "[3/6] Collecting round2 outbound..."
for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"

  R2=$(curl -sk -X POST "https://localhost:${port}/v1/dkg/round2" \
    --cert "$client_cert" --key "$client_key" \
    --cacert "${CEREMONY_CERTS}/ca.crt" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Node-Id: ${node}" \
    -d "$(printf '{"session_id":"%s","deliver":true}' "$SESSION_ID")" 2>&1)

  echo "$R2" > "${STAGING_DATA}/round2_${node}.json"
  COUNT=$(echo "$R2" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('outbound',[])))" 2>/dev/null || echo 0)
  echo "  $node: $COUNT outbound packages"
done

# Step 4: Deliver round2 packages
echo "[4/6] Delivering round2 packages..."
for sender in vault-1 vault-2 vault-3; do
  JSON="${STAGING_DATA}/round2_${sender}.json"
  [[ -f "$JSON" ]] || continue
  COUNT=$(python3 -c "import sys,json; d=json.load(open('$JSON')); print(len(d.get('outbound',[])))" 2>/dev/null || echo 0)

  for idx in $(seq 0 $((COUNT - 1))); do
    RECIPIENT=$(python3 -c "
import sys,json
d=json.load(open('$JSON'))
print(d['outbound'][$idx]['recipient_node_id'])
" 2>/dev/null || continue)

    rport="${PORTS[$RECIPIENT]}"
    rcert="${CEREMONY_CERTS}/nodes/${RECIPIENT}/client.crt"
    rkey="${CEREMONY_CERTS}/nodes/${RECIPIENT}/client.key"

    python3 -c "
import sys,json
d=json.load(open('$JSON'))
print(json.dumps(d['outbound'][$idx]))
" 2>/dev/null | curl -sk -X POST "https://localhost:${rport}/v1/dkg/round2" \
      --cert "$rcert" --key "$rkey" \
      --cacert "${CEREMONY_CERTS}/ca.crt" \
      -H "Content-Type: application/json" \
      -H "X-Vault-Node-Id: ${sender}" \
      -d "@-" > /dev/null 2>&1
  done
  echo "  $sender: delivered"
done

# Step 5: Status check
echo "[5/6] Status after round2..."
for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"
  STATUS=$(curl -sk "https://localhost:${port}/v1/dkg/status?session_id=${SESSION_ID}" \
    --cert "$client_cert" --key "$client_key" \
    --cacert "${CEREMONY_CERTS}/ca.crt" \
    -H "X-Vault-Node-Id: ${node}" 2>&1)

  R2R=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('round2_received','?'))" 2>/dev/null || echo "?")
  echo "  $node: round2_received=$R2R"
done

# Step 6: Finalize round3
echo "[6/6] Finalizing round3..."
for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"

  R3=$(curl -sk -X POST "https://localhost:${port}/v1/dkg/round3" \
    --cert "$client_cert" --key "$client_key" \
    --cacert "${CEREMONY_CERTS}/ca.crt" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Node-Id: ${node}" \
    -d "$(printf '{"session_id":"%s","finalize":true}' "$SESSION_ID")" 2>&1)

  COMPLETE=$(echo "$R3" | python3 -c "import sys,json; print(json.load(sys.stdin).get('complete','?'))" 2>/dev/null || echo "?")
  VK=$(echo "$R3" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('verifying_key_hex',''); print(v[:20] if v else 'null')" 2>/dev/null || echo "?")
  echo "  $node: complete=$COMPLETE vk=$VK"
done

echo ""
echo "=== Final health ==="
for node in vault-1 vault-2 vault-3; do
  port="${PORTS[$node]}"
  client_cert="${CEREMONY_CERTS}/nodes/${node}/client.crt"
  client_key="${CEREMONY_CERTS}/nodes/${node}/client.key"
  HEALTH=$(curl -sk "https://localhost:${port}/v1/health" \
    --cert "$client_cert" --key "$client_key" \
    --cacert "${CEREMONY_CERTS}/ca.crt" 2>&1)
  echo "  $node: $HEALTH"
done

echo ""
echo "============================================================"
echo "  Staging Ceremony DKG complete!"
echo "  Session: $SESSION_ID"
echo "============================================================"

wait
