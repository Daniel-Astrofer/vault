# Operational scripts

- `ceremony/`: ceremony preparation, certificate rotation, audit keys and
  transcript verification.
- `lab/`: explicitly non-production DKG, E2E, pentest and smoke helpers.
- `staging/`: staging provisioning and ceremony exercises.
- `security/`: host-security maintenance and audit-signature utilities.
- `lib/`: shell helpers shared by the scripts above.

Generated output belongs under `var/` and is ignored by Git. It can contain
shares, nonces, certificates, private keys and transcripts; it is never a test
fixture or source artifact.
