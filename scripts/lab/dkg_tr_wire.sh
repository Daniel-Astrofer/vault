#!/usr/bin/env bash
# Lab: run over-wire Taproot FROST DKG across 3 vault peers (no dealer).
# Mirrors lab_dkg_wire.sh but hits /v1/dkg/tr/* and persists frost-tr-* shares
# (even-Y at finalize). After this ceremony, restart the vaults so load_tr_shares
# populates runtime.frost_tr and /v1/bitcoin/deposit?bucket=USERS returns tb1p/bcrt1p.
#
# Auth (peer rounds):
#   VAULT_AUTH_MODE=static_token  → X-Vault-Token (default lab)
#   VAULT_AUTH_MODE=mtls          → HTTPS + per-node vault peer client cert
#
# mTLS note: DKG routes are VaultPeer-class. The kfe-role vault-client.crt cannot
# call them; each cross-post must be presented with the ORIGINATOR node's own
# vault peer client cert (lab-certs/nodes/<node>/client.crt, spiffe .../vault/<node>).
# Starts/deliver/finalize use the TARGET vault's own peer cert.
#
# Usage (repo root):
#   VAULT_DKG_MODE=distributed_wire docker compose -f infra/docker/compose/vault-mesh-lab.compose.yaml up --build -d
#   ./scripts/vault/lab_dkg_tr_wire.sh
#
# mTLS lab:
#   VAULT_AUTH_MODE=mtls \
#   VAULT_TLS_CA=./backend/kerosene-vault/lab-certs/ca.crt \
#   VAULT1_URL=https://127.0.0.1:7701 VAULT2_URL=https://127.0.0.1:7702 VAULT3_URL=https://127.0.0.1:7703 \
#   ./scripts/vault/lab_dkg_tr_wire.sh
set -euo pipefail

AUTH_MODE="${VAULT_AUTH_MODE:-static_token}"
TOKEN="${VAULT_API_TOKEN:-kerosene-vault-lab-only}"
SESSION_ID="${VAULT_DKG_TR_SESSION:-lab-dkg-tr-$(date -u +%Y%m%dT%H%M%SZ)}"
ROSTER='["vault-1","vault-2","vault-3"]'
MAX=3
MIN=2

NODE_IDS=(vault-1 vault-2 vault-3)
BASES=(
  "${VAULT1_URL:-http://127.0.0.1:7701}"
  "${VAULT2_URL:-http://127.0.0.1:7702}"
  "${VAULT3_URL:-http://127.0.0.1:7703}"
)

# Resolve per-node vault peer client cert/key (mTLS only).
LAB_CERTS=""
PEER_CERT_DIR=""
if [[ "$AUTH_MODE" == "mtls" || "$AUTH_MODE" == "mutual_tls" ]]; then
  CA="${VAULT_TLS_CA:-${VAULT_TLS_CLIENT_CA_PATH:-}}"
  if [[ -z "$CA" ]]; then
    echo "mTLS lab requires VAULT_TLS_CA" >&2
    exit 1
  fi
  LAB_CERTS="$(cd "$(dirname "$CA")" && pwd)"
  PEER_CERT_DIR="${VAULT_PEER_CERT_DIR:-${LAB_CERTS}/nodes}"
fi

cert_for() { echo "${PEER_CERT_DIR}/$1/client.crt"; }
key_for()  { echo "${PEER_CERT_DIR}/$1/client.key"; }

# post_json_as <node_id> <url> <body>  — presents node's peer cert (mTLS) or token.
post_json_as() {
  local node="$1" url="$2" body="$3"
  local auth=()
  case "$AUTH_MODE" in
    mtls|mutual_tls)
      local c k
      c="$(cert_for "$node")"; k="$(key_for "$node")"
      if [[ ! -f "$c" || ! -f "$k" ]]; then
        echo "missing peer cert for $node: $c" >&2; exit 1
      fi
      auth=(--cert "$c" --key "$k" --cacert "${VAULT_TLS_CA}")
      ;;
    static_token|*)
      auth=(-H "X-Vault-Token: ${TOKEN}")
      ;;
  esac
  curl -fsS -X POST "${auth[@]}" -H "Content-Type: application/json" -d "$body" "$url"
}

base_for_node() {
  case "$1" in
    vault-1) echo "${BASES[0]}" ;;
    vault-2) echo "${BASES[1]}" ;;
    vault-3) echo "${BASES[2]}" ;;
    *) echo "unknown node $1" >&2; return 1 ;;
  esac
}

echo "== Over-wire Taproot DKG session=$SESSION_ID (n=$MAX t=$MIN, auth=$AUTH_MODE, no dealer) =="
echo "   ToB: TR-distinct transcript; roster+threshold frozen at round1; even-Y at finalize"

echo "-- Round1 start on each vault"
declare -a R1_MSGS=()
for i in 0 1 2; do
  node="${NODE_IDS[$i]}"; base="${BASES[$i]}"
  resp="$(post_json_as "$node" "${base}/v1/dkg/tr/round1" "$(cat <<EOF
{"session_id":"${SESSION_ID}","max_signers":${MAX},"min_signers":${MIN},"roster":${ROSTER},"fanout":false}
EOF
)")"
  msg="$(echo "$resp" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["round1"]))')"
  R1_MSGS+=("$msg")
  echo "  started at $base ($node)"
done

echo "-- Round1 ingest (cross-post each originator's package to peers; originator cert)"
for msg in "${R1_MSGS[@]}"; do
  sender="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sender_node_id"])')"
  for target in "${NODE_IDS[@]}"; do
    [[ "$target" == "$sender" ]] && continue
    post_json_as "$sender" "$(base_for_node "$target")/v1/dkg/tr/round1" "$msg" >/dev/null
  done
done

echo "-- Round2 deliver (each vault emits its outbound; target cert) + cross-ingest"
declare -a R2_MSGS=()
for i in 0 1 2; do
  node="${NODE_IDS[$i]}"; base="${BASES[$i]}"
  resp="$(post_json_as "$node" "${base}/v1/dkg/tr/round2" "{\"session_id\":\"${SESSION_ID}\",\"deliver\":true,\"fanout\":false}")"
  while IFS= read -r line; do
    [[ -n "$line" ]] && R2_MSGS+=("$line")
  done < <(echo "$resp" | python3 -c 'import json,sys; [print(json.dumps(m)) for m in json.load(sys.stdin).get("outbound",[])]')
done

for msg in "${R2_MSGS[@]}"; do
  sender="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sender_node_id"])')"
  recip="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["recipient_node_id"])')"
  post_json_as "$sender" "$(base_for_node "$recip")/v1/dkg/tr/round2" "$msg" >/dev/null
done

echo "-- Round3 finalize (each vault persists only its even-Y Taproot share)"
for i in 0 1 2; do
  node="${NODE_IDS[$i]}"; base="${BASES[$i]}"
  st="$(post_json_as "$node" "${base}/v1/dkg/tr/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base ($node) -> $st"
done

echo "OK: over-wire TR DKG complete (restart vaults so load_tr_shares installs frost_tr)."
