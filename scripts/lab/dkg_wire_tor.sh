#!/usr/bin/env bash
# Lab / Gate exercise: over-wire FROST DKG across 3 vaults on **real Tor**.
# Same distributed_wire path as production; peers are .onion via SOCKS5h.
#
# Usage (repo root):
#   ./scripts/vault/lab_dkg_wire_tor.sh
#   VAULT_AUTH_MODE=mtls ./scripts/vault/lab_dkg_wire_tor.sh
#
# Env:
#   SKIP_COMPOSE=1          — reuse already-running mesh; needs VAULT{1,2,3}_ONION
#   VAULT_AUTH_MODE         — static_token (lab smoke, default) | mtls (ceremony path)
#   VAULT_API_TOKEN         — lab token when static_token (default kerosene-vault-lab-only)
#   TOR_SOCKS_HOST_PORT     — host SOCKS for operator curl (default 127.0.0.1:19051)
#   VAULT_LAB_MTLS_OUT       — cert dir for mtls (default backend/kerosene-vault/lab-certs)
#
# See docs/CEREMONY_TOR.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/infra/docker/compose/vault-mesh-tor.compose.yaml"
AUTH_MODE="${VAULT_AUTH_MODE:-static_token}"
TOKEN="${VAULT_API_TOKEN:-kerosene-vault-lab-only}"
SESSION_ID="${VAULT_DKG_SESSION:-tor-dkg-$(date -u +%Y%m%dT%H%M%SZ)}"
ROSTER='["vault-1","vault-2","vault-3"]'
MAX=3
MIN=2
SOCKS="${TOR_SOCKS_HOST_PORT:-127.0.0.1:19051}"
CERTS="${VAULT_LAB_MTLS_OUT:-$ROOT/var/lab-certs}"
CURL_SOCKS=(--socks5-hostname "$SOCKS")

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

read_onion() {
  local container="$1"
  local onion
  onion="$(docker exec "$container" cat /var/lib/tor/kerosene_service/hostname 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ -z "$onion" || "$onion" != *.onion ]]; then
    return 1
  fi
  printf '%s\n' "$onion"
}

wait_onions() {
  local deadline=$(( $(date +%s) + 180 ))
  echo "== Waiting for Tor onion hostnames (real network bootstrap) =="
  while true; do
    if VAULT1_ONION="$(read_onion kerosene-vault-tor-1)" \
      && VAULT2_ONION="$(read_onion kerosene-vault-tor-2)" \
      && VAULT3_ONION="$(read_onion kerosene-vault-tor-3)"; then
      export VAULT1_ONION VAULT2_ONION VAULT3_ONION
      echo "  vault-1 onion: $VAULT1_ONION"
      echo "  vault-2 onion: $VAULT2_ONION"
      echo "  vault-3 onion: $VAULT3_ONION"
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      echo "Tor onions not ready within 180s" >&2
      compose logs --tail=80 tor-1 tor-2 tor-3 >&2 || true
      exit 1
    fi
    sleep 3
  done
}

ensure_mtls_certs() {
  mkdir -p "$CERTS"
  export VAULT_LAB_MTLS_OUT="$CERTS"
  export VAULT_LAB_MTLS_ONION_SANS="${VAULT1_ONION},${VAULT2_ONION},${VAULT3_ONION}"
  if [[ -f "$CERTS/ca.crt" && -f "$CERTS/vault-server.crt" ]]; then
    echo "== Rotating lab mTLS leaves with onion DNS SANs =="
    "$ROOT/scripts/lab/rotate_mtls_certs.sh"
  else
    echo "== Generating lab mTLS certs (SPIFFE URI + onion DNS SANs) =="
    "$ROOT/scripts/lab/gen_mtls_certs.sh"
  fi
}

setup_curl_auth() {
  case "$AUTH_MODE" in
    mtls|mutual_tls)
      CURL_AUTH=(
        --cert "$CERTS/vault-client.crt"
        --key "$CERTS/vault-client.key"
        --cacert "$CERTS/ca.crt"
      )
      SCHEME=https
      ;;
    static_token|*)
      CURL_AUTH=(-H "X-Vault-Token: ${TOKEN}")
      SCHEME=http
      ;;
  esac
}

wait_health_onion() {
  local onion="$1"
  local url="${SCHEME}://${onion}:7701/v1/health"
  local deadline=$(( $(date +%s) + 300 ))
  echo "== Waiting for vault health via Tor: $url =="
  while true; do
    if curl -fsS "${CURL_SOCKS[@]}" "${CURL_AUTH[@]}" "$url" >/dev/null 2>&1; then
      echo "  OK $onion"
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      echo "vault $onion not healthy via Tor within 300s" >&2
      exit 1
    fi
    sleep 5
  done
}

post_json() {
  local url="$1"
  local body="$2"
  local attempt=1
  local max_attempts=6
  local delay=2
  while true; do
    if out="$(curl -fsS "${CURL_SOCKS[@]}" "${CURL_AUTH[@]}" \
      -X POST -H "Content-Type: application/json" -d "$body" "$url" 2>/tmp/kerosene-tor-dkg-curl.err)"; then
      printf '%s\n' "$out"
      return 0
    fi
    if (( attempt >= max_attempts )); then
      echo "POST failed after $max_attempts attempts: $url" >&2
      cat /tmp/kerosene-tor-dkg-curl.err >&2 || true
      exit 1
    fi
    # Jittered backoff — circuit drops / high latency are expected on Tor.
    sleep $(( delay + (RANDOM % 3) ))
    delay=$(( delay * 2 ))
    attempt=$(( attempt + 1 ))
  done
}

if [[ "${SKIP_COMPOSE:-0}" != "1" ]]; then
  echo "== Building/starting Tor sidecars =="
  compose up --build -d tor-1 tor-2 tor-3
  wait_onions
  if [[ "$AUTH_MODE" == "mtls" || "$AUTH_MODE" == "mutual_tls" ]]; then
    ensure_mtls_certs
    export VAULT_AUTH_MODE=mtls
    export VAULT_TLS_VERIFY_MODE="${VAULT_TLS_VERIFY_MODE:-onion_or_spiffe}"
  fi
  echo "== Starting vaults with onion peer seeds (no clearnet host ports, auth=$AUTH_MODE) =="
  compose up --build -d vault-1 vault-2 vault-3
else
  : "${VAULT1_ONION:?VAULT1_ONION required when SKIP_COMPOSE=1}"
  : "${VAULT2_ONION:?VAULT2_ONION required when SKIP_COMPOSE=1}"
  : "${VAULT3_ONION:?VAULT3_ONION required when SKIP_COMPOSE=1}"
  export VAULT1_ONION VAULT2_ONION VAULT3_ONION
fi

setup_curl_auth

BASES=(
  "${SCHEME}://${VAULT1_ONION}:7701"
  "${SCHEME}://${VAULT2_ONION}:7701"
  "${SCHEME}://${VAULT3_ONION}:7701"
)

wait_health_onion "$VAULT1_ONION"
wait_health_onion "$VAULT2_ONION"
wait_health_onion "$VAULT3_ONION"

echo "== Over-wire DKG session=$SESSION_ID via Tor SOCKS $SOCKS (n=$MAX t=$MIN, distributed_wire, auth=$AUTH_MODE) =="

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

echo "-- Round1 ingest (cross-post; Tor retries on failure)"
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

echo "-- Round3 finalize"
for base in "${BASES[@]}"; do
  st="$(post_json "${base}/v1/dkg/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base -> $st"
done

echo "OK: over-wire DKG complete over real Tor (auth=$AUTH_MODE)."
echo "    Production ceremony: VAULT_CEREMONY_MODE=production + mTLS + onion_or_spiffe — docs/CEREMONY_TOR.md"
echo "    Deploy default is vault-mesh-lab; opt-in: KEROSENE_VAULT_MESH_PROFILE=tor bash infra/deploy.sh"
