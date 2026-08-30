# FROST v3 security notes

Status: compile/test compatibility, not production readiness.

## Enforced invariants

- A signing share is bound to one `SigningPackage` containing the exact message and commitment set.
- The signer API consumes each nonce package when producing a share.
- Aggregation rejects different commitment/share participant sets.
- Session participants are unique, fixed, and checked on every contribution.
- DKG round-1 packages are authenticated broadcasts; round-2 packages are recipient-confidential.
- DKG secret state is consumed when advancing rounds.
- Same-membership, same-threshold refresh uses the library refresh protocol.
- Membership or threshold changes fail closed until an authenticated wire reshare protocol exists.
- Dealer key generation is test/lab-only.

## Not solved here

- Durable single-use nonce storage across crashes, process boundaries, and retries.
- Authenticated, consistent multi-node DKG broadcast and confidential routing.
- Membership-changing wire reshare.
- Workload identity, authorization policy, anti-replay replication, attestation, and production ceremony.

Production must not enable dealer or in-process orchestration paths. Track these gaps as release blockers; do not infer security from passing unit tests.
