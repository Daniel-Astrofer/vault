# Vault mesh mTLS — SPIFFE-like layout (Gate)

Lab ≠ go-live. Materials under `var/lab-certs/` are for **visualize / staging**;
`var/ceremony-certs/` is the **SPIRE-equivalent ceremony CA** profile (unique SPIFFE
per vault + kfe, short-lived leaves). A real SPIRE agent is **not** required —
paths and URI SANs mirror the SPIFFE SVID layout so production can drop in an
agent later without changing trust-domain IDs.

## Trust domain & SPIFFE IDs

| Identity | SPIFFE ID | Role |
| --- | --- | --- |
| Trust domain (lab) | `kerosene.lab` | Lab / staging visualize |
| Trust domain (ceremony) | `kerosene.ceremony` (override `VAULT_MTLS_TRUST_DOMAIN`) | Ceremony Gate CA |
| Vault server (**unique per node**) | `spiffe://{td}/vault/{VAULT_NODE_ID}` | rustls server + outbound peer client |
| Shared lab alias (optional) | `spiffe://{td}/vault/server` | Legacy compose when `VAULT_MTLS_SHARED_SPIFFE=1` |
| kfe client | `spiffe://{td}/kfe` | Client cert to vault (`clientAuth`) |

**Ceremony / Gate rule:** each vault and kfe must have a **unique** SPIFFE URI.
Outbound peer verify accepts an **allowlist** of vault SPIFFE IDs (local + seed
peers), via `VAULT_TLS_PEER_SPIFFE_ID` (comma-separated) or auto-derived from
`VAULT_MTLS_TRUST_DOMAIN` + seed peers.

### App-layer principal (Critical #3)

Verified mTLS leaf SPIFFE URI (and DNS SAN for legacy `…/vault/server`) binds to a mesh principal:

- **Role `kfe`**: settlement / sign / Intent / PSBT.
- **Role `vault`**: DKG, day vote, peer prepare, FROST co-sign.
- Shared ops (`/v1/day/advance`, current day, reshare) allow either role.

A CA-valid leaf alone is not full power. DKG `sender_node_id` must equal the TLS vault peer identity (Critical #4). Lab `static_token` remains omnipotent for visualize only.

## On-disk layout

### Lab visualize (`gen_lab_mtls_certs.sh`)

Default: unique SPIFFE per node under `var/lab-certs/nodes/{id}/` + flat aliases for
compose. Legacy shared alias: `VAULT_MTLS_SHARED_SPIFFE=1`.

```text
var/lab-certs/
  ca.crt / ca.key
  vault-server.crt / .key          # alias → nodes/vault-1/server.*
  vault-client.crt / .key          # kfe
  nodes/vault-1|2|3/server|client.*
  spiffe/trust-bundle.pem
  spiffe/vault/{node_id}/svid.pem
  spiffe/kfe/svid.pem
  rotation.json
```

### Ceremony CA (`scripts/ceremony/gen_mtls_certs.sh`)

SPIRE-equivalent Gate profile (short TTL, unique IDs, trust domain
`kerosene.ceremony` by default):

```bash
./scripts/ceremony/gen_mtls_certs.sh
VAULT_CEREMONY_MTLS_TTL_HOURS=24 \
  ./scripts/ceremony/rotate_mtls_certs.sh
```

```text
var/ceremony-certs/
  ca.crt / ca.key
  nodes/vault-1/server.crt|.key  client.crt|.key   # SPIFFE …/vault/vault-1
  nodes/vault-2/…
  nodes/vault-3/…
  kfe/client.crt|.key                              # SPIFFE …/kfe
  vault-client.pkcs8.key / kfe-client.p12 / truststore.p12
  spiffe/…                                         # agent-compatible mirror
  rotation.json
  audit/                                           # F8 audit keys (separate)
```

Compose / vault continue to use **flat** `VAULT_TLS_*` paths when mounting a
single node dir, e.g.:

```bash
VAULT_TLS_CERT_PATH=…/nodes/vault-2/server.crt
VAULT_TLS_KEY_PATH=…/nodes/vault-2/server.key
VAULT_TLS_CLIENT_CERT_PATH=…/nodes/vault-2/client.crt
VAULT_TLS_CLIENT_KEY_PATH=…/nodes/vault-2/client.key
VAULT_TLS_CLIENT_CA_PATH=…/ca.crt
VAULT_TLS_PEER_SPIFFE_ID=spiffe://kerosene.ceremony/vault/vault-1,spiffe://kerosene.ceremony/vault/vault-2,spiffe://kerosene.ceremony/vault/vault-3
```

Infra wrapper: `infra/scripts/gen-ceremony-mtls.sh`.

## Short-lived rotation

```bash
# Lab first materialization
./scripts/lab/gen_mtls_certs.sh
VAULT_LAB_MTLS_TTL_HOURS=24 ./scripts/lab/rotate_mtls_certs.sh

# Ceremony CA (preferred before genesis)
./scripts/ceremony/gen_mtls_certs.sh
VAULT_CEREMONY_MTLS_TTL_HOURS=24 \
  ./scripts/ceremony/rotate_mtls_certs.sh

# Optional post-rotate hook
VAULT_MTLS_ROTATE_HOOK=/path/to/hook.sh \
  ./scripts/ceremony/rotate_mtls_certs.sh
```

Hook receives env: `VAULT_LAB_MTLS_OUT` / `VAULT_CEREMONY_MTLS_OUT`,
`VAULT_TLS_*`, `KFE_CLIENT_P12`, `ROTATION_JSON`.

Production Gate requires operational cert rotation (**SPIRE or equivalent** —
this openssl ceremony CA counts as equivalent when identities are unique and
TTL is short). Drop-in SPIRE: point workload SVID paths at `spiffe/` and keep
the same URI SANs.

## Audit keys ≠ mTLS (F8)

mTLS SVIDs authenticate workloads. **Audit** signing keys are separate Ed25519
material — see [`AUDIT_KEYS.md`](AUDIT_KEYS.md). Do not reuse ceremony CA leaves
or FROST shares for audit signatures.

## Tor / onion peers

When `VAULT_TRANSPORT=tor`, outbound mTLS defaults to
`VAULT_TLS_VERIFY_MODE=onion_or_spiffe` (**AND** semantics):

1. Verify the leaf chains to `VAULT_TLS_CLIENT_CA_PATH`.
2. Require URI SAN ∈ allowlisted vault SPIFFE IDs (`VAULT_TLS_PEER_SPIFFE_ID` or auto).
3. When the peer host is `.onion`, **also** require a DNS SAN equal to that onion.

Hostname-only match without SPIFFE is refused. Env name stays `onion_or_spiffe` for compat.

Mint onion DNS SANs after HS discovery:

```bash
VAULT_LAB_MTLS_ONION_SANS=a.onion,b.onion,c.onion \
  ./scripts/gen_ceremony_mtls_certs.sh
```

`VAULT_AUTH_MODE=mtls ./scripts/lab_dkg_wire_tor.sh` does this automatically.
See `docs/CEREMONY_TOR.md`. Staging/production ceremony modes refuse `static_token`.

## kfe TLS properties

When vaults run `VAULT_AUTH_MODE=mtls`, kfe must present a client cert and **must not**
send `X-Vault-Token` (vault refuses static tokens in mTLS mode).

```properties
kfe.vaultmesh.base-url=https://127.0.0.1:7801
kfe.vaultmesh.api-token=
kfe.vaultmesh.tls.enabled=true
kfe.vaultmesh.tls.cert-path=/certs/vault-client.crt
kfe.vaultmesh.tls.key-path=/certs/vault-client.pkcs8.key
kfe.vaultmesh.tls.ca-path=/certs/ca.crt
```

See `kfe-service-vaultmesh-go-live.properties` and staging compose comments.
