#!/usr/bin/env bash
# Production-native over-wire FROST DKG (no dealer).
#
# `VAULT_DKG_KEYSET` selects independent material:
#   plain     intent/proof FROST (default, legacy-compatible)
#   users     Taproot USERS omnibus
#   channels  Taproot CHANNELS key (distinct transcript and sealed namespace)
#
# Production / all-domestic (Ryzen):
#   # after the private operations overlay has started the seated members
#   VAULT_AUTH_MODE=mtls \
#   VAULT_TLS_CLIENT_CERT=... VAULT_TLS_CLIENT_KEY=... VAULT_TLS_CA=... \
#   VAULT1_URL=https://member-1.onion VAULT2_URL=https://member-2.onion \
#   VAULT3_URL=https://member-3.onion VAULT_SOCKS_PROXY=socks5h://127.0.0.1:9050 \
#   VAULT_DKG_KEYSET=users ./scripts/ceremony/dkg_wire.sh
#   VAULT_DKG_KEYSET=channels ./scripts/ceremony/dkg_wire.sh
#
# Mixed SEV-priority: set VAULT_PEER_TIERS on each node before boot; omit ROSTER to use
# seated genesis_roster from GET /v1/health.
set -euo pipefail

AUTH_MODE="${VAULT_AUTH_MODE:-mtls}"
KEYSET="${VAULT_DKG_KEYSET:-plain}"
case "$KEYSET" in
  plain) DKG_PATH="/v1/dkg" ;;
  users|tr-users) KEYSET="users"; DKG_PATH="/v1/dkg/tr" ;;
  channels|tr-channels) KEYSET="channels"; DKG_PATH="/v1/dkg/tr/channels" ;;
  *) echo "VAULT_DKG_KEYSET must be plain, users, or channels" >&2; exit 1 ;;
esac
SESSION_ID="${VAULT_DKG_SESSION:-ceremony-dkg-${KEYSET}-$(date -u +%Y%m%dT%H%M%SZ)}"
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
declare -a CERTS=()
declare -a KEYS=()
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
    for i in 1 2 3; do
      cert_var="VAULT${i}_TLS_CLIENT_CERT"
      key_var="VAULT${i}_TLS_CLIENT_KEY"
      CERTS+=("${!cert_var:-$CERT}")
      KEYS+=("${!key_var:-$KEY}")
    done
    ;;
  *)
    echo "Production ceremony requires VAULT_AUTH_MODE=mtls." >&2
    exit 1
    ;;
esac

CURL_TRANSPORT=()
if [[ -n "${VAULT_SOCKS_PROXY:-}" ]]; then
  CURL_TRANSPORT=(--proxy "$VAULT_SOCKS_PROXY")
fi
CURL_RELIABILITY=(--connect-timeout "${VAULT_CURL_CONNECT_TIMEOUT:-15}" --max-time "${VAULT_CURL_MAX_TIME:-60}" --retry "${VAULT_CURL_RETRIES:-4}" --retry-delay 2 --retry-all-errors)

post_json_as() {
  local member_index="$1"
  shift
  local url="$1"
  local body="$2"
  curl -fsS -X POST \
    "${CURL_RELIABILITY[@]}" \
    "${CURL_TRANSPORT[@]}" \
    --cert "${CERTS[$member_index]}" --key "${KEYS[$member_index]}" --cacert "$CA" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$url"
}

get_json_as() {
  local member_index="$1"
  shift
  local url="$1"
  curl -fsS "${CURL_RELIABILITY[@]}" "${CURL_TRANSPORT[@]}" \
    --cert "${CERTS[$member_index]}" --key "${KEYS[$member_index]}" --cacert "$CA" "$url"
}

echo "== Over-wire FROST DKG keyset=$KEYSET session=$SESSION_ID (auth=$AUTH_MODE, no dealer) =="
echo "   Seating comes from authenticated member health (SEV > SGX > domestic)."

# Resolve roster from first vault health when not provided.
if [[ -z "$ROSTER_JSON" ]]; then
  health="$(get_json_as 0 "${BASES[0]}/v1/health")"
  ROSTER_JSON="$(echo "$health" | python3 -c 'import json,sys; h=json.load(sys.stdin); print(json.dumps(h.get("genesis_roster") or []))')"
  if [[ "$ROSTER_JSON" == "[]" ]]; then
    ROSTER_JSON="$(python3 -c 'import json,os; print(json.dumps([x.strip() for x in os.environ.get("VAULT_DKG_NODE_IDS", "vault-1,vault-2,vault-3").split(",") if x.strip()]))')"
    echo "   hardened health omits member identities; using VAULT_DKG_NODE_IDS: $ROSTER_JSON"
  fi
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
for i in "${!BASES[@]}"; do
  base="${BASES[$i]}"
  resp="$(post_json_as "$i" "${base}${DKG_PATH}/round1" "$START_BODY")"
  msg="$(echo "$resp" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["round1"]))')"
  R1_MSGS+=("$msg")
  echo "  started at $base"
done

echo "-- Round1 ingest"
for base in "${BASES[@]}"; do
  for sender in "${!R1_MSGS[@]}"; do
    post_json_as "$sender" "${base}${DKG_PATH}/round1" "${R1_MSGS[$sender]}" >/dev/null
  done
done

echo "-- Round2 deliver + cross-ingest"
declare -a R2_MSGS=()
declare -a R2_SENDERS=()
for i in "${!BASES[@]}"; do
  base="${BASES[$i]}"
  resp="$(post_json_as "$i" "${base}${DKG_PATH}/round2" "{\"session_id\":\"${SESSION_ID}\",\"deliver\":true,\"fanout\":false}")"
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      R2_MSGS+=("$line")
      R2_SENDERS+=("$i")
    fi
  done < <(echo "$resp" | python3 -c 'import json,sys; [print(json.dumps(m)) for m in json.load(sys.stdin).get("outbound",[])]')
done

# Map recipient → base by health node_id order when possible; fall back to vault-1..3.
declare -A BASE_BY_ID=()
i=0
for i in "${!BASES[@]}"; do
  base="${BASES[$i]}"
  nid="$(get_json_as "$i" "${base}/v1/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("node_id",""))' || true)"
  if [[ -n "$nid" ]]; then
    BASE_BY_ID["$nid"]="$base"
    BASE_BY_ID["${nid}:index"]="$i"
  fi
  i=$((i+1))
done

for msg_index in "${!R2_MSGS[@]}"; do
  msg="${R2_MSGS[$msg_index]}"
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
  post_json_as "${R2_SENDERS[$msg_index]}" "${base}${DKG_PATH}/round2" "$msg" >/dev/null
done

echo "-- Round3 finalize (each vault keeps only its share)"
for i in "${!BASES[@]}"; do
  base="${BASES[$i]}"
  st="$(post_json_as "$i" "${base}${DKG_PATH}/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base -> $st"
done

echo "OK: production over-wire DKG completed for keyset=$KEYSET."
