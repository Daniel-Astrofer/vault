#!/usr/bin/env bash
# Production-native / lab-shared over-wire FROST DKG (no dealer).
# Same protocol as lab_dkg_wire.sh; defaults toward ceremony (mTLS + seated roster).
#
# Lab visualize:
#   VAULT_DKG_MODE=distributed_wire docker compose -f infra/docker/compose/vault-mesh-lab.compose.yaml up --build -d
#   VAULT_AUTH_MODE=static_token ./scripts/vault/genesis_dkg_wire.sh
#
# Production / all-domestic (Ryzen):
#   # after checklist + compose with VAULT_CEREMONY_MODE=production ATTESTATION_MODE=software
#   VAULT_AUTH_MODE=mtls \
#   VAULT_TLS_CLIENT_CERT=... VAULT_TLS_CLIENT_KEY=... VAULT_TLS_CA=... \
#   ./scripts/vault/genesis_dkg_wire.sh
#
# Mixed SEV-priority: set VAULT_PEER_TIERS on each node before boot; omit ROSTER to use
# seated genesis_roster from GET /v1/health.
set -euo pipefail

AUTH_MODE="${VAULT_AUTH_MODE:-mtls}"
TOKEN="${VAULT_API_TOKEN:-}"
SESSION_ID="${VAULT_DKG_SESSION:-ceremony-dkg-$(date -u +%Y%m%dT%H%M%SZ)}"
# Empty ROSTER → each vault uses its seated genesis_roster (SEV-priority).
ROSTER_JSON="${VAULT_DKG_ROSTER_JSON:-}"
MAX="${VAULT_DKG_MAX:-}"
MIN="${VAULT_DKG_MIN:-}"

BASES=(
  "${VAULT1_URL:-https://127.0.0.1:7701}"
  "${VAULT2_URL:-https://127.0.0.1:7702}"
  "${VAULT3_URL:-https://127.0.0.1:7703}"
)

CURL_AUTH=()
case "$AUTH_MODE" in
  mtls|mutual_tls)
    CERT="${VAULT_TLS_CLIENT_CERT:-${VAULT_TLS_CLIENT_CERT_PATH:-}}"
    KEY="${VAULT_TLS_CLIENT_KEY:-${VAULT_TLS_CLIENT_KEY_PATH:-}}"
    CA="${VAULT_TLS_CA:-${VAULT_TLS_CLIENT_CA_PATH:-}}"
    if [[ -z "$CERT" || -z "$KEY" || -z "$CA" ]]; then
      echo "mTLS requires VAULT_TLS_CLIENT_CERT, VAULT_TLS_CLIENT_KEY, VAULT_TLS_CA" >&2
      exit 1
    fi
    CURL_AUTH=(--cert "$CERT" --key "$KEY" --cacert "$CA")
    ;;
  static_token|*)
    if [[ -z "$TOKEN" ]]; then
      echo "static_token auth requires VAULT_API_TOKEN" >&2
      exit 1
    fi
    CURL_AUTH=(-H "X-Vault-Token: ${TOKEN}")
    # Lab HTTP defaults when not overridden.
    BASES=(
      "${VAULT1_URL:-http://127.0.0.1:7701}"
      "${VAULT2_URL:-http://127.0.0.1:7702}"
      "${VAULT3_URL:-http://127.0.0.1:7703}"
    )
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

get_json() {
  local url="$1"
  curl -fsS "${CURL_AUTH[@]}" "$url"
}

echo "== Over-wire FROST DKG session=$SESSION_ID (auth=$AUTH_MODE, no dealer) =="
echo "   Same binary path as lab; seating from boot (SEV > SGX > domestic)"

# Resolve roster from first vault health when not provided.
if [[ -z "$ROSTER_JSON" ]]; then
  health="$(get_json "${BASES[0]}/v1/health")"
  ROSTER_JSON="$(echo "$health" | python3 -c 'import json,sys; h=json.load(sys.stdin); print(json.dumps(h.get("genesis_roster") or []))')"
  echo "   seated genesis_roster from health: $ROSTER_JSON"
  echo "   node_tier=$(echo "$health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("node_tier"))') attestation_mode=$(echo "$health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("attestation_mode"))') tee_available=$(echo "$health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tee_available"))')"
fi

if [[ -z "$MAX" ]]; then
  MAX="$(echo "$ROSTER_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
fi
if [[ -z "$MIN" ]]; then
  MIN="$(python3 -c "print(max(2, (2*int('${MAX}')+2)//3))")"
fi

START_BODY="$(python3 - <<PY
import json
roster=json.loads('''${ROSTER_JSON}''')
print(json.dumps({
  "session_id": "${SESSION_ID}",
  "max_signers": int("${MAX}"),
  "min_signers": int("${MIN}"),
  "roster": roster,
  "fanout": False,
}))
PY
)"

echo "-- Round1 start on each vault (roster must match seating in production)"
declare -a R1_MSGS=()
for base in "${BASES[@]}"; do
  resp="$(post_json "${base}/v1/dkg/round1" "$START_BODY")"
  msg="$(echo "$resp" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["round1"]))')"
  R1_MSGS+=("$msg")
  echo "  started at $base"
done

echo "-- Round1 ingest"
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

# Map recipient → base by health node_id order when possible; fall back to vault-1..3.
declare -A BASE_BY_ID=()
i=0
for base in "${BASES[@]}"; do
  nid="$(get_json "${base}/v1/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("node_id",""))' || true)"
  if [[ -n "$nid" ]]; then
    BASE_BY_ID["$nid"]="$base"
  fi
  i=$((i+1))
done

for msg in "${R2_MSGS[@]}"; do
  recip="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["recipient_node_id"])')"
  base="${BASE_BY_ID[$recip]:-}"
  if [[ -z "$base" ]]; then
    case "$recip" in
      vault-1) base="${BASES[0]}" ;;
      vault-2) base="${BASES[1]}" ;;
      vault-3) base="${BASES[2]}" ;;
      *) echo "unknown recipient $recip"; exit 1 ;;
    esac
  fi
  post_json "${base}/v1/dkg/round2" "$msg" >/dev/null
done

echo "-- Round3 finalize (each vault keeps only its share)"
for base in "${BASES[@]}"; do
  st="$(post_json "${base}/v1/dkg/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base -> $st"
done

echo "OK: over-wire DKG complete (production-native path; lab uses same rounds)."
