#!/usr/bin/env bash
# Lab: run over-wire FROST DKG across 3 vault peers (no dealer).
# Expects vault-mesh-lab.compose.yaml with VAULT_DKG_MODE=distributed_wire.
#
# Auth (peer rounds):
#   VAULT_AUTH_MODE=static_token  → X-Vault-Token (default lab)
#   VAULT_AUTH_MODE=mtls          → HTTPS + client cert (no X-Vault-Token)
#
# Usage (repo root):
#   VAULT_DKG_MODE=distributed_wire docker compose -f infra/docker/compose/vault-mesh-lab.compose.yaml up --build -d
#   ./scripts/vault/lab_dkg_wire.sh
#
# mTLS lab (after ./scripts/vault/gen_lab_mtls_certs.sh):
#   VAULT_AUTH_MODE=mtls \
#   VAULT_TLS_CLIENT_CERT=./backend/kerosene-vault/lab-certs/vault-client.crt \
#   VAULT_TLS_CLIENT_KEY=./backend/kerosene-vault/lab-certs/vault-client.key \
#   VAULT_TLS_CA=./backend/kerosene-vault/lab-certs/ca.crt \
#   VAULT1_URL=https://127.0.0.1:7701 VAULT2_URL=https://127.0.0.1:7702 VAULT3_URL=https://127.0.0.1:7703 \
#   ./scripts/vault/lab_dkg_wire.sh
#
# In-process fallback (no compose peers): VAULT_DKG_MODE=distributed inside one process.
set -euo pipefail

AUTH_MODE="${VAULT_AUTH_MODE:-static_token}"
TOKEN="${VAULT_API_TOKEN:-kerosene-vault-lab-only}"
SESSION_ID="${VAULT_DKG_SESSION:-lab-dkg-$(date -u +%Y%m%dT%H%M%SZ)}"
ROSTER='["vault-1","vault-2","vault-3"]'
MAX=3
MIN=2

BASES=(
  "${VAULT1_URL:-http://127.0.0.1:7701}"
  "${VAULT2_URL:-http://127.0.0.1:7702}"
  "${VAULT3_URL:-http://127.0.0.1:7703}"
)

CURL_AUTH=()
case "$AUTH_MODE" in
  mtls|mutual_tls)
    CERT="${VAULT_TLS_CLIENT_CERT:-${VAULT_TLS_CLIENT_CERT_PATH:-}}"
    KEY="${VAULT_TLS_CLIENT_KEY:-${VAULT_TLS_CLIENT_KEY_PATH:-}}"
    CA="${VAULT_TLS_CA:-${VAULT_TLS_CLIENT_CA_PATH:-}}"
    if [[ -z "$CERT" || -z "$KEY" || -z "$CA" ]]; then
      echo "mTLS lab requires VAULT_TLS_CLIENT_CERT, VAULT_TLS_CLIENT_KEY, VAULT_TLS_CA" >&2
      exit 1
    fi
    CURL_AUTH=(--cert "$CERT" --key "$KEY" --cacert "$CA")
    # Host driver must not send static token (vault refuses it in mTLS mode).
    ;;
  static_token|*)
    CURL_AUTH=(-H "X-Vault-Token: ${TOKEN}")
    ;;
esac

post_json() {
  local url="$1"
  local body="$2"
  curl -fsS -X POST \
    "${CURL_AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$url"
}

echo "== Over-wire DKG session=$SESSION_ID (n=$MAX t=$MIN, auth=$AUTH_MODE, no dealer) =="
echo "   ToB: roster+threshold frozen at round1; transcript bound on wire messages"

echo "-- Round1 start on each vault"
declare -a R1_MSGS=()
for base in "${BASES[@]}"; do
  resp="$(post_json "${base}/v1/dkg/round1" "$(cat <<EOF
{"session_id":"${SESSION_ID}","max_signers":${MAX},"min_signers":${MIN},"roster":${ROSTER},"fanout":false}
EOF
)")"
  msg="$(echo "$resp" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["round1"]))')"
  R1_MSGS+=("$msg")
  echo "  started at $base"
done

echo "-- Round1 ingest (cross-post packages; rejects threshold bump / late join)"
for base in "${BASES[@]}"; do
  for msg in "${R1_MSGS[@]}"; do
    post_json "${base}/v1/dkg/round1" "$msg" >/dev/null
  done
done

echo "-- Round2 deliver + cross-ingest"
declare -a R2_MSGS=()
for base in "${BASES[@]}"; do
  resp="$(post_json "${base}/v1/dkg/round2" "{\"session_id\":\"${SESSION_ID}\",\"deliver\":true,\"fanout\":false}")"
  while IFS= read -r line; do
    [[ -n "$line" ]] && R2_MSGS+=("$line")
  done < <(echo "$resp" | python3 -c 'import json,sys; [print(json.dumps(m)) for m in json.load(sys.stdin).get("outbound",[])]')
done

for msg in "${R2_MSGS[@]}"; do
  recip="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["recipient_node_id"])')"
  case "$recip" in
    vault-1) base="${BASES[0]}" ;;
    vault-2) base="${BASES[1]}" ;;
    vault-3) base="${BASES[2]}" ;;
    *) echo "unknown recipient $recip"; exit 1 ;;
  esac
  post_json "${base}/v1/dkg/round2" "$msg" >/dev/null
done

echo "-- Round3 finalize (each vault keeps only its share)"
for base in "${BASES[@]}"; do
  st="$(post_json "${base}/v1/dkg/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base -> $st"
done

echo "OK: over-wire DKG complete (lab only; not go-live)."
