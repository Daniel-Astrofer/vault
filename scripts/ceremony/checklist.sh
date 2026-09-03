#!/usr/bin/env bash
# F8 production genesis ceremony checklist (human + automation gate).
# Does NOT perform DKG — prints required steps and fails if env is unsafe.
#
# Native ceremony supports:
#   - all-domestic (Ryzen/home PC): VAULT_NODE_TIER=domestic ATTESTATION_MODE=software
#   - mixed: SEV/SGX peers preferred for genesis seats via VAULT_PEER_TIERS
# Does NOT require every node to have EPYC/SEV. Refuses fake TEE claims / staging stub in prod.
#
# Same code path as lab over-wire DKG: VAULT_DKG_MODE=distributed_wire (config differs only).
set -euo pipefail

echo "== Kerosene vault genesis ceremony checklist (F8) =="
MODE="${VAULT_CEREMONY_MODE:-${KEROSENE_ENV:-lab}}"
TIER="${VAULT_NODE_TIER:-auto}"
ATT="${ATTESTATION_MODE:-}"
DKG="${VAULT_DKG_MODE:-${VAULT_DKG:-}}"
echo "ceremony_mode=$MODE node_tier=$TIER attestation_mode=${ATT:-unset} dkg_mode=${DKG:-unset}"

fail=0
check() {
  local ok="$1" msg="$2"
  if [[ "$ok" == "1" ]]; then
    echo "[OK] $msg"
  else
    echo "[!!] $msg"
    fail=1
  fi
}

case "$MODE" in
  production|prod)
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    check "$([[ "${ATTESTATION_STAGING_STUB:-0}" != "1" ]] && echo 1 || echo 0)" \
      "ATTESTATION_STAGING_STUB not enabled"
    check "$([[ -n "${VAULT_GENESIS_N:-}" ]] && echo 1 || echo 0)" \
      "VAULT_GENESIS_N set (${VAULT_GENESIS_N:-})"
    check "$([[ -n "${VAULT_SEED_PEERS:-}" ]] && echo 1 || echo 0)" \
      "VAULT_SEED_PEERS set"
    check "$([[ "${DKG}" == "distributed_wire" || "${DKG}" == "wire" || "${DKG}" == "over_wire" ]] && echo 1 || echo 0)" \
      "VAULT_DKG_MODE=distributed_wire (got ${DKG:-unset})"
    check "$([[ "${VAULT_AUTH_MODE:-}" == "mtls" || "${VAULT_AUTH_MODE:-}" == "mutual_tls" ]] && echo 1 || echo 0)" \
      "VAULT_AUTH_MODE=mtls (got ${VAULT_AUTH_MODE:-unset})"
    TRANSPORT="${VAULT_TRANSPORT:-tor}"
    check "$([[ "${TRANSPORT}" == "tor" || "${TRANSPORT}" == "onion" || "${TRANSPORT}" == "socks" ]] && echo 1 || echo 0)" \
      "VAULT_TRANSPORT=tor (got ${TRANSPORT})"
    check "$([[ -n "${VAULT_SOCKS_PROXY:-${VAULT_TOR_SOCKS:-}}" ]] && echo 1 || echo 0)" \
      "VAULT_SOCKS_PROXY set (${VAULT_SOCKS_PROXY:-${VAULT_TOR_SOCKS:-unset}})"
    check "$([[ "${VAULT_CLEARNET_PUBLISH:-0}" != "1" ]] && echo 1 || echo 0)" \
      "VAULT_CLEARNET_PUBLISH not enabled (no clearnet public vault bind)"
    VERIFY_MODE="${VAULT_TLS_VERIFY_MODE:-onion_or_spiffe}"
    check "$([[ "${VERIFY_MODE}" == "onion_or_spiffe" || "${VERIFY_MODE}" == "spiffe" || "${VERIFY_MODE}" == "tor" ]] && echo 1 || echo 0)" \
      "VAULT_TLS_VERIFY_MODE=onion_or_spiffe|spiffe for Tor ceremony (got ${VERIFY_MODE})"
    check "$([[ -n "${VAULT_TLS_CERT_PATH:-}" && -n "${VAULT_TLS_KEY_PATH:-}" && -n "${VAULT_TLS_CLIENT_CA_PATH:-}" ]] && echo 1 || echo 0)" \
      "VAULT_TLS_CERT_PATH / KEY / CLIENT_CA set for mTLS serve"
    check "$([[ -n "${VAULT_TLS_CLIENT_CERT_PATH:-}" && -n "${VAULT_TLS_CLIENT_KEY_PATH:-}" ]] && echo 1 || echo 0)" \
      "VAULT_TLS_CLIENT_CERT_PATH / KEY set for outbound peer mTLS"
    SPIFFE_ID="${VAULT_TLS_PEER_SPIFFE_ID:-${VAULT_MTLS_SPIFFE_VAULT:-}}"
    check "$([[ -n "${SPIFFE_ID}" && "${SPIFFE_ID}" == spiffe://* ]] && echo 1 || echo 0)" \
      "VAULT_TLS_PEER_SPIFFE_ID (or VAULT_MTLS_SPIFFE_VAULT) is spiffe://… (${SPIFFE_ID:-unset})"
    # Unique SPIFFE (not only shared vault/server alias) — SPIRE-equivalent Gate.
    if [[ -n "${SPIFFE_ID}" ]]; then
      case "${SPIFFE_ID}" in
        *,*)
          check 1 "SPIFFE allowlist is multi-id (unique vault SVIDs)"
          ;;
        */vault/server)
          check 0 "production requires unique SPIFFE per vault (not only shared …/vault/server); run gen_ceremony_mtls_certs.sh"
          ;;
        */vault/*)
          check 1 "SPIFFE uses unique per-vault ID (SPIRE-like)"
          ;;
        *)
          check 0 "VAULT_TLS_PEER_SPIFFE_ID must be spiffe://…/vault/{node_id} (or comma-separated allowlist)"
          ;;
      esac
    fi
    # F8: audit keys ≠ release ≠ settlement
    AUDIT_OK=0
    if [[ -n "${VAULT_AUDIT_PUBKEY_ALLOWLIST:-}" ]]; then
      AUDIT_OK=1
    elif [[ -n "${VAULT_AUDIT_PUBKEYS_PATH:-}" && -f "${VAULT_AUDIT_PUBKEYS_PATH}" ]]; then
      AUDIT_OK=1
    elif [[ -f "${VAULT_CEREMONY_MTLS_OUT:-}/audit/allowlist.txt" ]]; then
      AUDIT_OK=1
    elif [[ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ceremony-certs/audit/allowlist.txt" ]]; then
      AUDIT_OK=1
    elif [[ "${VAULT_SKIP_AUDIT_KEYS_CHECK:-0}" == "1" ]]; then
      echo "[..] VAULT_SKIP_AUDIT_KEYS_CHECK=1 — audit keys skipped (not for go-live)"
      AUDIT_OK=1
    fi
    check "$AUDIT_OK" \
      "mesh audit pubkey allowlist present (F8: audit ≠ release ≠ settlement; docs/AUDIT_KEYS.md)"

    # PQ checks: hybrid identity + envelope readiness
    check "$([[ -n "${VAULT_ML_DSA_SEED_PATH:-}" || -n "${VAULT_IDENTITY_SEED_PATH:-}" ]] && echo 1 || echo 0)" \
      "PQ identity seed path set (ML-DSA-65 for hybrid auth)"
    check "$([[ -n "${VAULT_ML_KEM_SEED_PATH:-}" || -n "${VAULT_KEM_SEED_PATH:-}" ]] && echo 1 || echo 0)" \
      "PQ KEM seed path set (ML-KEM-768 for hybrid envelope)"
    check "$([[ "${VAULT_PQ_SUITE:-hybrid-v2}" == "hybrid-v2" || "${VAULT_PQ_SUITE:-}" == "hybrid-v3" ]] && echo 1 || echo 0)" \
      "PQ suite_id is hybrid-v2 or later (got ${VAULT_PQ_SUITE:-hybrid-v2})"
    check "$([[ "${VAULT_PQ_DOWNGRADE_ALLOWED:-0}" != "1" ]] && echo 1 || echo 0)" \
      "PQ downgrade disabled (VAULT_PQ_DOWNGRADE_ALLOWED != 1)"

    if [[ -n "${VAULT_SEED_PEERS:-}" ]]; then
      if echo "${VAULT_SEED_PEERS}" | grep -q '\.onion'; then
        check 1 "VAULT_SEED_PEERS contain .onion addresses"
      else
        check 0 "VAULT_SEED_PEERS must be onion URLs under Tor (got clearnet/LAN)"
      fi
    fi

    case "${ATT}" in
      software|sev|sgx)
        check 1 "ATTESTATION_MODE is software|sev|sgx (got ${ATT})"
        ;;
      sim|"")
        check 0 "ATTESTATION_MODE must be software (domestic) or sev|sgx (got ${ATT:-unset}; sim is lab-only)"
        ;;
      *)
        check 0 "ATTESTATION_MODE is software|sev|sgx (got ${ATT})"
        ;;
    esac

    case "${TIER}" in
      domestic|sev|sgx|auto)
        check 1 "VAULT_NODE_TIER is domestic|sev|sgx|auto (got ${TIER})"
        ;;
      *)
        check 0 "VAULT_NODE_TIER is domestic|sev|sgx|auto (got ${TIER})"
        ;;
    esac

    if [[ "${ATT}" == "sev" || "${ATT}" == "sgx" || "${TIER}" == "sev" || "${TIER}" == "sgx" ]]; then
      echo "[..] TEE claim: ensure /dev/sev-guest (or SGX device) exists; stub forbidden in production"
      if [[ -e /dev/sev-guest || -e /dev/sev || -e /dev/sgx_enclave || -e /dev/sgx/enclave || -e /dev/isgx ]]; then
        check 1 "TEE device node present on this host"
      else
        check 0 "TEE device node missing (cannot advertise SEV/SGX without HW)"
      fi
    else
      echo "[..] Domestic-native path: AEAD share store + software measurement (TPM optional seal); not SEV"
    fi

    echo
    echo "Manual ceremony steps (same FROST wire path as lab; config only differs):"
    echo "  1. Bring N vaults with identical constitution seed / peer set on **private Tor mesh**"
    echo "     - VAULT_TRANSPORT=tor VAULT_SOCKS_PROXY=socks5h://127.0.0.1:9050"
    echo "     - VAULT_SEED_PEERS=id=http://….onion:7701 (no clearnet publish; https under mTLS)"
    echo "     - VAULT_AUTH_MODE=mtls + VAULT_TLS_* + VAULT_TLS_VERIFY_MODE=onion_or_spiffe"
    echo "     - VAULT_TLS_PEER_SPIFFE_ID=spiffe://…/vault/vault-1,spiffe://…/vault/vault-2,… (unique; gen_ceremony_mtls_certs.sh)"
    echo "     - Audit keys: ./scripts/gen_mesh_audit_keys.sh + source audit/env.hint (F8; ≠ release ≠ settlement)"
    echo "     - All domestic: VAULT_NODE_TIER=domestic ATTESTATION_MODE=software VAULT_SHARE_STORE=aead_disk"
    echo "     - Optional TPM: VAULT_SHARE_TPM_SEAL=1 (fail-closed without TPM; lab stub VAULT_SHARE_TPM_STUB=1; clear fallback lab-only)"
    echo "     - Mixed: set VAULT_PEER_TIERS=id=sev,... so seating prefers SEV > SGX > domestic"
    echo "     - Lab Tor mTLS: VAULT_AUTH_MODE=mtls ./scripts/vault/lab_dkg_wire_tor.sh"
    echo "  2. Verify honest labels on GET /v1/health (node_tier, attestation_mode, tee_available, genesis_roster)"
    echo "  3. Run ./scripts/vault/genesis_dkg_wire.sh via SOCKS to onions (mTLS client certs)"
    echo "  4. Freeze mpc-sidecar / HashiCorp wallet-arming (kfe.mpc.signing-enabled=false)"
    echo "  5. Enable kfe.vaultmesh.enabled=true + mesh-only=true (no hard tee_hw require)"
    echo "  6. Smoke Intent → Receipt; confirm fail-stop runbook"
    echo "  7. Do NOT re-enable mpc as silent rollback"
    echo "  Note: deploy default is vault-mesh-lab; use KEROSENE_VAULT_MESH_PROFILE=tor for Tor mesh."
    ;;
  staging)
    check "$([[ "${ATT}" == "sev" || "${ATT}" == "sgx" || "${ATT}" == "software" ]] && echo 1 || echo 0)" \
      "ATTESTATION_MODE is software|sev|sgx"
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    check "$([[ "${DKG}" == "distributed_wire" || "${DKG}" == "wire" || "${DKG}" == "over_wire" || -z "${DKG}" ]] && echo 1 || echo 0)" \
      "VAULT_DKG_MODE is distributed_wire or default (got ${DKG:-default})"
    check "$([[ "${VAULT_AUTH_MODE:-}" == "mtls" || "${VAULT_AUTH_MODE:-}" == "mutual_tls" ]] && echo 1 || echo 0)" \
      "VAULT_AUTH_MODE=mtls for staging ceremony (got ${VAULT_AUTH_MODE:-unset}; static_token refused)"
    if [[ "${VAULT_TRANSPORT:-clearnet}" == "tor" || "${VAULT_TRANSPORT:-}" == "onion" || "${VAULT_TRANSPORT:-}" == "socks" ]]; then
      VERIFY_MODE="${VAULT_TLS_VERIFY_MODE:-onion_or_spiffe}"
      check "$([[ "${VERIFY_MODE}" == "onion_or_spiffe" || "${VERIFY_MODE}" == "spiffe" || "${VERIFY_MODE}" == "tor" ]] && echo 1 || echo 0)" \
        "staging Tor: VAULT_TLS_VERIFY_MODE=onion_or_spiffe|spiffe (got ${VERIFY_MODE})"
    fi
    echo "Staging may use ATTESTATION_STAGING_STUB=1 for TEE claims until hardware arrives."
    echo "Domestic staging: VAULT_NODE_TIER=domestic ATTESTATION_MODE=software (no stub)."
    ;;
  *)
    echo "Lab mode: no production gates. Compose sets VAULT_NODE_TIER=domestic + ATTESTATION_MODE=sim."
    echo "Clearnet visualize: VAULT_DKG_MODE=distributed_wire + lab_dkg_wire.sh"
echo "Tor variability (token): ./scripts/vault/lab_dkg_wire_tor.sh"
echo "Tor ceremony-shaped mTLS: VAULT_AUTH_MODE=mtls ./scripts/vault/lab_dkg_wire_tor.sh"
    echo "  (docs/CEREMONY_TOR.md — onion SAN / SPIFFE verify)."
    ;;
esac

if [[ "$fail" -ne 0 ]]; then
  echo "Ceremony checklist FAILED"
  exit 1
fi
echo "Ceremony checklist PASSED (or lab)"
