#!/usr/bin/env bash
# measure_pcr_policy.sh — Capture expected TPM 2.0 PCR values for vault secure boot policy.
#
# Usage: ./measure_pcr_policy.sh [output_file]
#   Default output: /etc/kerosene/vault-pcr-policy.expected
#
# This script reads the SHA-256 PCR bank values for indices 0-7 and writes them
# to the expected policy file. The vault uses this file to verify boot integrity
# before unsealing any shares.
#
# Requirements:
#   - tpm2-tools (apt-get install tpm2-tools)
#   - Root or tss group membership
#   - TPM 2.0 device (/dev/tpmrm0 or /dev/tpm0)

set -euo pipefail

POLICY_FILE="${1:-/etc/kerosene/vault-pcr-policy.expected}"
PCR_BANK="${VAULT_PCR_BANK:-sha256}"
PCR_LIST="0,1,2,3,4,5,7"

# --- Pre-flight checks ---

if ! command -v tpm2_pcrread &>/dev/null; then
    echo "ERROR: tpm2_pcrread not found. Install tpm2-tools: apt-get install tpm2-tools" >&2
    exit 1
fi

if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
    echo "ERROR: No TPM device found (/dev/tpmrm0 or /dev/tpm0)" >&2
    exit 1
fi

# --- Read PCR values ---

echo "Reading TPM PCR values (${PCR_BANK}:${PCR_LIST})..."

# Capture raw output; we'll format it ourselves for deterministic output
PCR_RAW=$(tpm2_pcrread "${PCR_BANK}:${PCR_LIST}" 2>&1) || {
    echo "ERROR: tpm2_pcrread failed. Is the TPM accessible?" >&2
    echo "${PCR_RAW}" >&2
    exit 1
}

# --- Write policy file ---

mkdir -p "$(dirname "${POLICY_FILE}")"

cat > "${POLICY_FILE}" <<EOF
# Kerosene Vault Secure Boot PCR Policy
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Hostname: $(hostname)
# Kernel: $(uname -r)
# TPM Bank: ${PCR_BANK}
#
# Each line: PCR_INDEX: SHA256_HEX_VALUE
# Do not edit manually.
#
EOF

# Parse tpm2_pcrread output and write to file
# Expected format: "  sha256:" followed by PCR banks, then hex values
echo "${PCR_RAW}" | while IFS= read -r line; do
    # Skip header lines
    if [[ "${line}" =~ ^[[:space:]]*sha256: ]] || [[ "${line}" =~ ^[[:space:]]*$ ]]; then
        continue
    fi
    # Parse hex values per PCR index
    # tpm2_pcrread output format: "  0 : 0xA1B2C3D4..."
    if [[ "${line}" =~ ^[[:space:]]*([0-9]+)[[:space:]]*:[[:space:]]*0x([0-9a-fA-F]+) ]]; then
        pcr_idx="${BASH_REMATCH[1]}"
        pcr_value="${BASH_REMATCH[2]}"
        printf "%d: %s\n" "${pcr_idx}" "${pcr_value,,}"
    fi
done >> "${POLICY_FILE}"

# --- Compute composite digest ---

echo ""
echo "PCR values written to: ${POLICY_FILE}"
echo ""
echo "Composite digest (SHA-256 of all PCR values):"
# Extract hex values and hash them
COMPOSITE=$(grep -E '^[0-9]+:' "${POLICY_FILE}" | sort -n | cut -d' ' -f2 | tr -d '\n' | xxd -r -p | sha256sum | cut -d' ' -f1)
echo "  ${COMPOSITE}"
echo ""
echo "Add to vault config (NOT the composite, the policy file path):"
echo "  export VAULT_SECURE_BOOT_PCR_POLICY=${POLICY_FILE}"
echo ""
echo "Verification:"
echo "  diff <(sort ${POLICY_FILE}) <(tpm2_pcrread ${PCR_BANK}:${PCR_LIST} | grep -E '^[[:space:]]*[0-9]+' | sed 's/0x//g' | awk '{printf \"%d: %s\\n\", \$1, tolower(\$3)}')"

# --- Verify policy file has all expected PCRs ---

MISSING=$(for i in $(echo "${PCR_LIST}" | tr ',' ' '); do
    grep -q "^${i}:" "${POLICY_FILE}" || echo "${i}"
done)
if [ -n "${MISSING}" ]; then
    echo "WARNING: Missing PCR indices: ${MISSING}" >&2
fi

echo "Done."
