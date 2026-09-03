# Repository boundary

This repository is the canonical source for the custody and signing trust
domain, including FROST, DKG, reshare, signing policies, nonces and custody
audit evidence.

The root Cargo package is intentional while Vault remains one release unit.
Future daemons will be introduced as workspace members under `crates/` only
when they can be compiled and audited independently.

Vault consumes versioned protocols from `kerosene-contracts`. It must not read
source files from the archived monorepo or another service repository.

## Owned here

- custody-key lifecycle and protected share storage;
- distributed key generation, reshare and threshold signing;
- nonce safety, signing policy and custody audit evidence;
- Vault-side adapters for attestation and membership consumption.

## Owned elsewhere

- identity, discovery and membership: `kerosene-node`;
- schemas and wire contracts: `kerosene-contracts`;
- Auth, ledger and financial intent decisions: application services;
- manifests, secrets references and runtime orchestration: `kerosene-deploy`.

Vault may verify membership supplied by Node, but it does not define or mutate
the network roster. Node may identify Vault members, but it never receives a
FROST share or signing authority.
