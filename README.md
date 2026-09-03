# Kerosene Vault

Rust custody and threshold-signing service for Kerosene.

This repository owns threshold signing, FROST/DKG/reshare, nonce policy,
attestation adapters and Vault release validation. Its CI must never receive
production shares, TPM private material, LND macaroons or deployment authority.

It does not own authentication, financial ledger rules, service discovery or
deployment orchestration. It consumes versioned contracts and obtains peer
membership from Kerosene Node.

Documentation:

- [English](docs/en/README.md)
- [Português](docs/pt-BR/README.md)
- [Kerosene Node integration](docs/KEROSENE_NODE_INTEGRATION.md)
- [Repository boundary](docs/REPOSITORY_BOUNDARY.md)
- [Security documentation](docs/security/QUANTUM_THREAT_MODEL.md)
- [Repository layout](docs/REPOSITORY_LAYOUT.md)

Start with [English quickstart](docs/en/QUICKSTART.md) or
[início rápido em português](docs/pt-BR/QUICKSTART.md). Production readiness is
tracked in the corresponding `STATUS.md`; historical plans are not operational
runbooks.
