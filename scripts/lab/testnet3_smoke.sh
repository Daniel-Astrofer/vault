#!/usr/bin/env bash
# Lab P0 smoke — MODE=lab-visualize only. Not a production go-live check.
# Expects vault-mesh-lab.compose.yaml (testnet3 + static_token) listening on :7701.
#
# Usage (repo root):
#   docker compose -f infra/docker/compose/vault-mesh-lab.compose.yaml up --build -d
#   ./scripts/vault/lab_testnet3_smoke.sh
set -euo pipefail

BASE_URL="${VAULT_SMOKE_BASE_URL:-http://127.0.0.1:7701}"
# Must match VAULT_API_TOKEN in vault-mesh-lab.compose.yaml and kfe.vaultmesh.api-token.
TOKEN="${VAULT_API_TOKEN:-kerosene-vault-lab-only}"
# Deterministic lab message hash (64 hex chars) — vault validates shape; signing may still fail-stop.
MSG_HASH="${VAULT_SMOKE_MSG_HASH:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
SESSION_ID="${VAULT_SMOKE_SESSION_ID:-lab-smoke-$(date -u +%Y%m%dT%H%M%SZ)}"

echo "== Vault Mesh Lab P0 smoke (testnet3 / lab-visualize) =="
echo "MODE=lab-visualize  base=$BASE_URL  session=$SESSION_ID"
echo "Lab ≠ go-live: dealer_lab + static_token are visualization adapters only."

echo
echo "-- GET /v1/health (public)"
health="$(curl -fsS "$BASE_URL/v1/health")"
echo "$health"

echo
echo "-- POST /sign/{session}/{hash} with X-Vault-Token"
code="$(curl -sS -o /tmp/vault-lab-smoke-body.json -w '%{http_code}' \
  -X POST \
  -H "X-Vault-Token: ${TOKEN}" \
  "${BASE_URL}/sign/${SESSION_ID}/${MSG_HASH}")"
echo "HTTP $code"
cat /tmp/vault-lab-smoke-body.json
echo

if [[ "$code" == "401" || "$code" == "403" ]]; then
  echo "FAIL: token rejected — align VAULT_API_TOKEN with compose / kfe.vaultmesh.api-token"
  exit 1
fi

# 2xx accepted; 4xx business reject (fail-stop / not ready) still proves auth + route.
if [[ "$code" =~ ^2 ]]; then
  echo "OK: sign path accepted (lab visualization)"
elif [[ "$code" =~ ^4 ]]; then
  echo "OK: sign path reached vault (auth ok; business status HTTP $code — lab may be pre-DKG)"
else
  echo "FAIL: unexpected HTTP $code"
  exit 1
fi

echo
echo "Smoke complete. Remember: Lab P0 ≠ Production Gate."
