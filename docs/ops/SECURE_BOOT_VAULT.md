# Vault Mesh Secure Boot + PCR Policy

## Overview

The vault mesh enforces measured boot integrity via TPM 2.0 PCR policy. Before any
share is unsealed, the vault verifies that the boot chain (firmware → bootloader →
kernel) matches expected measurements. A PCR mismatch indicates possible firmware
or bootloader compromise and must refuse boot (fail-closed).

## PCR Bank Mapping

The vault binds to TPM SHA-256 PCR bank, indices 0-7 (measured boot chain):

| PCR | Component | What it measures |
|-----|-----------|-----------------|
| 0  | Firmware | UEFI/BIOS firmware binary hash |
| 1  | Firmware config | UEFI configuration data (boot order, secure boot settings) |
| 2  | External ROMs | Option ROMs (GPU, network card firmware) |
| 3  | External ROM config | Option ROM configuration |
| 4  | Bootloader | GRUB2 / systemd-boot binary (shim + grub EFI) |
| 5  | Bootloader config | GRUB config, kernel cmdline |
| 6  | Sleep/resume | Platform state transitions |
| 7  | Secure Boot state | PK, KEK, db, dbx certificates + secure boot policy |

Additional PCRs for application-specific measurement (optional):
- PCR 8: Kernel image + initramfs (GRUB-measured)
- PCR 9: initramfs contents (systemd-measured with `systemd-pcrphase`)
- PCR 14: shim MokList/MokListX (Machine Owner Key)

## Vault Boot Verification Procedure

### 1. Expected PCR Policy (First Boot / Baseline)

```bash
# Capture baseline PCR values after clean install
# Run as root on a freshly provisioned vault machine
tpm2_pcrread sha256:0,1,2,3,4,5,7 > /etc/kerosene/vault-pcr-policy.expected

# The policy file format is one hex value per PCR index:
# 0:  A1B2C3D4...
# 1:  E5F6A7B8...
# ...
```

### 2. Config Setting

```bash
# Set in vault environment:
export VAULT_SECURE_BOOT_PCR_POLICY=/etc/kerosene/vault-pcr-policy.expected
```

### 3. Boot-Time Verification

On startup, before unsealing any shares:

1. Read current PCR values: `tpm2_pcrread sha256:0,1,2,3,4,5,7`
2. Compare against expected policy file
3. Build composite digest: `SHA-256(PCR0_value || PCR1_value || ... || PCR7_value)`
4. Compare composite digest with baseline composite digest
5. If mismatch → refuse boot, log PCR values, emit alert

### 4. Fail-Closed Behavior

If PCR mismatch is detected:

```
ERROR: vault secure boot PCR mismatch
  PCR 4 (bootloader): expected A1B2... got F3E4...
  PCR 7 (secure boot): expected C5D6... got 9A0B...
  Boot refused — possible firmware/bootloader compromise.
  Manual intervention required.
  Run: `scripts/measure_pcr_policy.sh` to capture a new baseline if intentional.
```

Shares remain sealed. Vault does not start.

## Update Procedure

When the kernel, bootloader, or firmware is updated, PCR values change.
This is expected. The policy must be re-measured.

### Kernel Update

```bash
# 1. Schedule maintenance window (vault offline)
# 2. Apply updates
apt-get update && apt-get upgrade linux-image-amd64 grub-efi

# 3. Before reboot: record current expected policy
cp /etc/kerosene/vault-pcr-policy.expected /etc/kerosene/vault-pcr-policy.expected.pre-update

# 4. Reboot
reboot

# 5. After reboot: capture new baseline
scripts/measure_pcr_policy.sh

# 6. Verify new baseline is intentional
diff /etc/kerosene/vault-pcr-policy.expected.pre-update /etc/kerosene/vault-pcr-policy.expected

# 7. If diff shows only expected changes (PCR 4 changed for bootloader, PCR 7 unchanged):
#    Accept new policy. Vault can start.
# 8. If PCR 0, 1, or 7 changed unexpectedly:
#    INVESTIGATE. Possible firmware compromise.
```

### Firmware Update

PCRs 0-3 and 7 change after UEFI firmware update. This requires:
1. Multiple operators to witness the update
2. New baseline captured immediately after firmware flash
3. Previous policy archived for audit
4. TPM PCR banks re-sealed with new composite digest

## TPM Seal PCR Policy Binding

When `--features tpm` is enabled, the TSS seal operation binds to PCR values:

```
seal(pcr_selection=[0,1,2,3,4,5,7], pcr_composite_digest, auth_value)
```

The TPM will refuse to unseal if any bound PCR value changes. This means:
- Kernel update → PCR 4 changes → TPM refuses unseal → vault must be re-keyed with new PCR
- This is intentional: the kernel is part of the measured boot chain

For kernel updates on TPM-sealed vaults:
1. Unseal shares with old PCR values (vault must be running)
2. Re-export seeds/shares
3. Apply kernel update, reboot
4. Measure new PCR baseline
5. Re-import seeds/shares with new PCR policy

## Security Considerations

- PCR 0 (firmware) changes only on firmware update — first line of defense
- PCR 7 (secure boot state) must match exactly — any change = certificate tampering
- PCR 4 (bootloader) changes on GRUB update — most common PCR change
- When using CSV/TPM on VMs, PCRs reflect the hypervisor, not the guest
- TPM-backed VMs require HV-provided vTPM; PCR values reflect HV boot chain

## References

- TCG PC Client Platform Firmware Profile Specification
- TPM 2.0 Library Specification, Part 1: Architecture, Section 33 (PCR)
- Linux IMA (Integrity Measurement Architecture) for kernel-level measurement
- systemd-pcrphase for userspace PCR extension
