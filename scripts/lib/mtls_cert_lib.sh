#!/usr/bin/env bash
# Shared helpers for lab/staging/ceremony mTLS materialization (SPIFFE-like).
# Lab CA is Gate-valid when leaves carry unique SPIFFE IDs + short TTL;
# production ops may drop in SPIRE without changing URI layout.
# shellcheck shell=bash

mtls_issue_leaf() {
  local prefix="$1"
  local cn="$2"
  local eku="$3"
  local spiffe_id="$4"
  local days="$5"
  local extra_san="$6"
  local org="${7:-Kerosene Lab}"

  openssl genrsa -out "${prefix}.key" 2048
  openssl req -new -key "${prefix}.key" -out "${prefix}.csr" \
    -subj "/C=CH/ST=Zurich/L=Zurich/O=${org}/OU=Vault Mesh/CN=${cn}"
  cat > "${prefix}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${extra_san},URI:${spiffe_id}
EOF
  openssl x509 -req -in "${prefix}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${prefix}.crt" -days "${days}" -sha256 -extfile "${prefix}.ext"
  rm -f "${prefix}.csr" "${prefix}.ext" ca.srl
}

mtls_write_java_materials() {
  local out_dir="$1"
  local p12_pass="$2"
  local client_key="${3:-${out_dir}/vault-client.key}"
  local client_crt="${4:-${out_dir}/vault-client.crt}"
  local pkcs8_out="${5:-${out_dir}/vault-client.pkcs8.key}"
  local p12_out="${6:-${out_dir}/kfe-client.p12}"
  local trust_out="${7:-${out_dir}/truststore.p12}"

  openssl pkcs8 -topk8 -nocrypt -in "${client_key}" -out "${pkcs8_out}"
  openssl pkcs12 -export \
    -inkey "${client_key}" \
    -in "${client_crt}" \
    -certfile "${out_dir}/ca.crt" \
    -out "${p12_out}" \
    -name kfe-client \
    -passout "pass:${p12_pass}"
  openssl pkcs12 -export \
    -nokeys \
    -in "${out_dir}/ca.crt" \
    -out "${trust_out}" \
    -name vault-mesh-ca \
    -passout "pass:${p12_pass}"
}

# Sync SPIFFE-like tree. Args: out_dir, spiffe_kfe, then vault_id=spiffe_uri pairs.
mtls_sync_spiffe_tree() {
  local out_dir="$1"
  local spiffe_kfe="$2"
  shift 2

  mkdir -p "${out_dir}/spiffe/kfe"
  cp -f "${out_dir}/ca.crt" "${out_dir}/spiffe/trust-bundle.pem"

  local readme_vaults=""
  local pair node_id spiffe_id src_crt src_key
  for pair in "$@"; do
    node_id="${pair%%=*}"
    spiffe_id="${pair#*=}"
    mkdir -p "${out_dir}/spiffe/vault/${node_id}"
    src_crt="${out_dir}/nodes/${node_id}/server.crt"
    src_key="${out_dir}/nodes/${node_id}/server.key"
    if [[ ! -f "${src_crt}" ]]; then
      # Flat lab layout fallback (shared vault-server leaf).
      src_crt="${out_dir}/vault-server.crt"
      src_key="${out_dir}/vault-server.key"
      mkdir -p "${out_dir}/spiffe/vault/server"
      cp -f "${src_crt}" "${out_dir}/spiffe/vault/server/svid.pem"
      cp -f "${src_key}" "${out_dir}/spiffe/vault/server/key.pem"
      chmod 0600 "${out_dir}/spiffe/vault/server/key.pem"
    fi
    cp -f "${src_crt}" "${out_dir}/spiffe/vault/${node_id}/svid.pem"
    cp -f "${src_key}" "${out_dir}/spiffe/vault/${node_id}/key.pem"
    chmod 0600 "${out_dir}/spiffe/vault/${node_id}/key.pem"
    readme_vaults="${readme_vaults}
  vault/${node_id}: ${spiffe_id}"
  done

  if [[ -f "${out_dir}/vault-client.crt" ]]; then
    cp -f "${out_dir}/vault-client.crt" "${out_dir}/spiffe/kfe/svid.pem"
    cp -f "${out_dir}/vault-client.key" "${out_dir}/spiffe/kfe/key.pem"
  elif [[ -f "${out_dir}/kfe/client.crt" ]]; then
    cp -f "${out_dir}/kfe/client.crt" "${out_dir}/spiffe/kfe/svid.pem"
    cp -f "${out_dir}/kfe/client.key" "${out_dir}/spiffe/kfe/key.pem"
  fi
  chmod 0600 "${out_dir}/spiffe/kfe/key.pem" 2>/dev/null || true

  cat > "${out_dir}/spiffe/README.txt" <<EOF
SPIFFE-like SVID mirror (SPIRE agent optional — drop-in compatible paths).
  trust domain bundle: trust-bundle.pem
  kfe:   ${spiffe_kfe}${readme_vaults}
See docs/MTLS_SPIFFE_LAYOUT.md
EOF
}

mtls_write_rotation_json() {
  local out_dir="$1"
  local ttl_hours="$2"
  local spiffe_kfe="$3"
  shift 3
  local issued expires
  issued="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if expires="$(date -u -d "+${ttl_hours} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then
    :
  elif expires="$(date -u -v+"${ttl_hours}"H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then
    :
  else
    expires="unknown"
  fi

  local vault_json=""
  local pair node_id spiffe_id first=1
  for pair in "$@"; do
    node_id="${pair%%=*}"
    spiffe_id="${pair#*=}"
    if [[ "$first" -eq 1 ]]; then
      first=0
    else
      vault_json="${vault_json},"
    fi
    vault_json="${vault_json}
    \"${node_id}\": \"${spiffe_id}\""
  done

  cat > "${out_dir}/rotation.json" <<EOF
{
  "issued_at": "${issued}",
  "expires_at": "${expires}",
  "ttl_hours": ${ttl_hours},
  "spiffe_kfe": "${spiffe_kfe}",
  "spiffe_vaults": {${vault_json}
  },
  "trust_bundle": "${out_dir}/spiffe/trust-bundle.pem",
  "profile": "spiffe-like-ceremony-ca"
}
EOF
}

mtls_onion_extra_san() {
  local base="$1"
  local onions="${2:-}"
  local o
  if [[ -z "${onions}" ]]; then
    echo "${base}"
    return
  fi
  IFS=',' read -r -a _onions <<< "${onions}"
  for o in "${_onions[@]}"; do
    o="$(echo "$o" | tr -d '[:space:]')"
    o="${o#http://}"; o="${o#https://}"; o="${o%%:*}"; o="${o%%/*}"
    [[ -n "$o" ]] || continue
    base="${base},DNS:${o}"
  done
  echo "${base}"
}

mtls_default_node_ids() {
  echo "${VAULT_MTLS_NODE_IDS:-vault-1,vault-2,vault-3}"
}
