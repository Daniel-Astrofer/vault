<!--
Kerosene documentation metadata
status: review-required
audience: internal
owner: vault
source_of_truth: vault
last_reviewed: 2026-09-03
-->

# Local runtime material

This directory is deliberately ignored by Git. It contains generated material
only: certificates, private keys, ceremony packages, transcripts and local
node state.

- `ceremony-certs/`: local ceremony CA, mTLS leaves and audit material.
- `staging/`: local staging/lab ceremony output and node data.

Do not move its contents into `tests/fixtures` or commit them. Recreate test
fixtures from public, deterministic inputs instead.
