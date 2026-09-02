#!/usr/bin/env bash
# Execute DKG ceremony on existing vault mesh with manual round2 delivery
set -euo pipefail

TOKEN="kerosene-vault-lab-only"
SESSION_ID="${1:-""}"

if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="staging-ceremony-$(date +%s)"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA_DIR="${VAULT_STAGING_DATA_DIR:-$REPO_ROOT/var/staging}"
mkdir -p "$DATA_DIR"

echo "============================================================"
echo "  Kerosene Vault - DKG Ceremony"
echo "  Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  Session: $SESSION_ID"
echo "============================================================"
echo ""

# Step 1: Start round1 on all 3 nodes
echo "[1/6] Starting DKG round1 on all 3 nodes..."
PACKAGES=()
for node in vault-1 vault-2 vault-3; do
  port="${node##*-}"
  port=$((7700 + port))
  R1=$(curl -sk -X POST "http://localhost:${port}/v1/dkg/round1" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Token: $TOKEN" \
    -d "$(printf '{"session_id":"%s","roster":["vault-1","vault-2","vault-3"],"max_signers":3,"min_signers":2,"fanout":false}' "$SESSION_ID")" 2>&1)

  PACKAGE_HEX=$(echo "$R1" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['package_hex'])")
  SENDER_ID=$(echo "$R1" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['sender_identifier'])")
  TRANSCRIPT_HEX=$(echo "$R1" | python3 -c "import sys,json; print(json.load(sys.stdin)['round1']['transcript_hex'])")

  PACKAGES+=("$node:$SENDER_ID:$PACKAGE_HEX:$TRANSCRIPT_HEX")
  echo "  $node (ID=$SENDER_ID): started"
done

# Step 2: Exchange round1 packages
echo "[2/6] Exchanging round1 packages..."
for pkg_info in "${PACKAGES[@]}"; do
  IFS=':' read -r sender_node sender_id pkg_hex trans_hex <<< "$pkg_info"
  for recipient in vault-1 vault-2 vault-3; do
    [[ "$recipient" == "$sender_node" ]] && continue
    r_port="${recipient##*-}"
    r_port=$((7700 + r_port))
    curl -sk -X POST "http://localhost:${r_port}/v1/dkg/round1" \
      -H "Content-Type: application/json" \
      -H "X-Vault-Token: $TOKEN" \
      -d "$(printf '{"session_id":"%s","package_hex":"%s","sender_node_id":"%s","sender_identifier":%s,"max_signers":3,"min_signers":2,"transcript_hex":"%s"}' "$SESSION_ID" "$pkg_hex" "$sender_node" "$sender_id" "$trans_hex")" > /dev/null 2>&1
  done
  echo "  $sender_node: sent to peers"
done

# Step 3: Get round2 outbound packages
echo "[3/6] Collecting round2 outbound packages..."
R2_PACKAGES=()
for node in vault-1 vault-2 vault-3; do
  port="${node##*-}"
  port=$((7700 + port))
  R2_RESP=$(curl -sk -X POST "http://localhost:${port}/v1/dkg/round2" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Token: $TOKEN" \
    -d "$(printf '{"session_id":"%s","deliver":true}' "$SESSION_ID")" 2>&1)

  # Parse outbound packages from response
  echo "$R2_RESP" > "${DATA_DIR}/round2_${node}.json"
  PACKAGE_COUNT=$(echo "$R2_RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('outbound',[])))" 2>/dev/null || echo "parse_error")
  echo "  $node: $PACKAGE_COUNT outbound packages"
done

# Step 4: Deliver round2 packages to correct recipients
echo "[4/6] Delivering round2 packages..."
for node in vault-1 vault-2 vault-3; do
  json_file="${DATA_DIR}/round2_${node}.json"
  if [[ ! -f "$json_file" ]]; then continue; fi

  # Extract all outbound packages
  PACKAGE_COUNT=$(python3 -c "import sys,json; d=json.load(open('$json_file')); print(len(d.get('outbound',[])))" 2>/dev/null || echo 0)

  for idx in $(seq 0 $((PACKAGE_COUNT - 1))); do
    PKG=$(python3 -c "
import sys,json
d=json.load(open('$json_file'))
pkg=d['outbound'][$idx]
print(json.dumps(pkg))
" 2>/dev/null || echo "")

    if [[ -z "$PKG" ]]; then continue; fi

    RECIPIENT_ID=$(echo "$PKG" | python3 -c "import sys,json; print(json.load(sys.stdin)['recipient_node_id'])" 2>/dev/null || echo "")
    if [[ -z "$RECIPIENT_ID" ]]; then continue; fi

    r_port="${RECIPIENT_ID##*-}"
    r_port=$((7700 + r_port))

    echo "  $node -> $RECIPIENT_ID"
    curl -sk -X POST "http://localhost:${r_port}/v1/dkg/round2" \
      -H "Content-Type: application/json" \
      -H "X-Vault-Token: $TOKEN" \
      -d "$PKG" > /dev/null 2>&1
  done
done

# Step 5: Check status and finalize round3
echo "[5/6] Status after round2..."
for node in vault-1 vault-2 vault-3; do
  port="${node##*-}"
  port=$((7700 + port))
  STATUS=$(curl -sk "http://localhost:${port}/v1/dkg/status?session_id=${SESSION_ID}" \
    -H "X-Vault-Token: $TOKEN" 2>&1)
  echo "  $node: phase=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('phase','?'))" 2>/dev/null), round2=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('round2_received','?'))" 2>/dev/null), complete=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('complete','?'))" 2>/dev/null)"
done

echo ""
echo "[6/6] Finalizing round3..."
for node in vault-1 vault-2 vault-3; do
  port="${node##*-}"
  port=$((7700 + port))
  R3=$(curl -sk -X POST "http://localhost:${port}/v1/dkg/round3" \
    -H "Content-Type: application/json" \
    -H "X-Vault-Token: $TOKEN" \
    -d "$(printf '{"session_id":"%s"}' "$SESSION_ID")" 2>&1)

  R3_PHASE=$(echo "$R3" | python3 -c "import sys,json; print(json.load(sys.stdin).get('phase','?'))" 2>/dev/null || echo "?")
  R3_COMPLETE=$(echo "$R3" | python3 -c "import sys,json; print(json.load(sys.stdin).get('complete','?'))" 2>/dev/null || echo "?")
  VK=$(echo "$R3" | python3 -c "import sys,json; v=json.load(sys.stdin).get('verifying_key_hex',''); print(v[:16] if v else 'null')" 2>/dev/null || echo "?")
  echo "  $node: phase=$R3_PHASE, complete=$R3_COMPLETE, vk=$VK"
done

echo ""
echo "=== Final health check ==="
for node in vault-1 vault-2 vault-3; do
  port="${node##*-}"
  port=$((7700 + port))
  HEALTH=$(curl -sk "http://localhost:${port}/v1/health" 2>&1)
  echo "  $node: $HEALTH"
done

echo ""
echo "============================================================"
echo "  DKG Ceremony complete!"
echo "  Session: $SESSION_ID"
echo "============================================================"
