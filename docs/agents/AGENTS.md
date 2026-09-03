# Agent guide — Kerosene Vault

## Scope

Vault is a separate cryptographic trust domain for custody, threshold signing,
FROST/DKG/reshare, nonces and attestation adapters.

## Documentation

- Start at `docs/README.md`.
- Put boundaries in `architecture/`, API facts in `reference/`, ceremonies in
  `operations/`, and threat/control material in `security/`.
- Keep plans and superseded designs in `history/`; never use them as runbooks.

## Safety and integration

- Never commit shares, nonces, ceremony output, private certificates, macaroons
  or TPM/TEE private material.
- Production must reject lab/dealer features at compile time.
- Protocol changes consume versioned `kerosene-contracts` artifacts.
- Security-sensitive changes require focused tests and a threat-model update.

## Verification

Run the relevant Rust checks and update STATUS when a production gate changes.
CI may publish a candidate but must never activate a signer.
