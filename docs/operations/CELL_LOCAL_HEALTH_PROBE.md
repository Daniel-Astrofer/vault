# Authenticated local Cell health probe

The application binary accepts exactly `--health-probe`. This branch executes
before `VaultConfig::from_env` and `VaultRuntime::build`: no second runtime,
storage initialization, workers or signer is created. Additional probe arguments
exit 2; probe failures exit 1 with a generic message; success exits 0 silently.

Required external inputs:

- `VAULT_HEALTH_PROBE_URL`: HTTPS URL with the certificate's hostname, explicit
  service port as needed, and exactly `/v1/health`; no credentials/query/fragment.
- `VAULT_TLS_CLIENT_CERT_PATH`, `VAULT_TLS_CLIENT_KEY_PATH` and
  `VAULT_TLS_CLIENT_CA_PATH`: absolute paths to existing mounted PEM files.

Each PEM read is capped at 64 KiB. The client uses only the specified CA bundle,
retains hostname verification, disables proxy/redirect use, and resolves the URL
hostname to IPv4 loopback. It cannot probe a remote host; the hostname is retained
for TLS identity verification. Connect timeout is two seconds, request timeout
four seconds, and collected response bytes are capped at 4096. Only HTTP 200
with boolean `local_ready: true` succeeds.
Duplicate `local_ready` fields and concatenated JSON responses are rejected,
including duplicate fields whose values agree; missing/string readiness fails.
`financial_ready` does not authorize
anything here and is not required for local Kubernetes bootstrap readiness.

Do not put certificate values, private keys or passwords into argv or logs.
The local probe uses the existing outbound client identity; issuance/rotation
remains an explicit external ceremony. No TLS bypass is available.

## Qualification remaining

Three unit tests validate URL restrictions, local-vs-financial readiness and
duplicate readiness rejection. After building the application binary, run
`python3 scripts/lab/cell_health_probe_test.py` for actual executable/mTLS checks.
The loopback server requires a client certificate; independently generated
synthetic CAs/leaves verify success and rejection of wrong CA, hostname/client,
false/duplicate readiness, oversized responses and redirects. A server that
sends headers but stalls the body is rejected by the four-second request timeout.
Temporary test
keys are deleted with the private fixture directory; none enter Git.
This does not start a Vault runtime or qualify its actual health endpoint, OCI
image or Kubernetes exec probe. Full runtime/OCI behavior still
require qualification before changing production probes. The health endpoint may
perform peer liveness checks; this command does not change server behavior.
No manifests have been switched and no signer or live Vault was started.
