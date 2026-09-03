<!--
Kerosene documentation metadata
status: review-required
audience: internal
owner: vault
source_of_truth: vault
last_reviewed: 2026-09-03
-->

# Operational scripts

- `ceremony/`: ceremony preparation, certificate rotation, audit keys and
  transcript verification.
- `lab/`: explicitly non-production DKG, E2E and pentest helpers.
- `security/`: host-security maintenance and audit-signature utilities.
- `lib/`: shell helpers shared by the scripts above.

Generated output belongs under `var/` and is ignored by Git. It can contain
shares, nonces, certificates, private keys and transcripts; it is never a test
fixture or source artifact.

Vault scripts never provision another repository or a Kubernetes cluster.
Environment lifecycle and secret delivery belong to the private operations
checkout; ceremony scripts consume explicit endpoints and credential paths.
