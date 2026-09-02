# Genesis ceremony over private Tor mesh

Minimum-viable **real Tor** path for vault↔vault (and operator→vault) traffic.
Same FROST `VAULT_DKG_MODE=distributed_wire` binary path as lab/production — not `dealer_lab`.

## What deploy.sh / ensure-vault-mesh does

| Path | Compose | Transport | DKG | Auth |
| --- | --- | --- | --- | --- |
| Default `bash infra/deploy.sh` / `ensure-vault-mesh-lab.sh` | `vault-mesh-lab.compose.yaml` | Clearnet host ports `:7701–7703` | default `dealer_lab` | `static_token` |
| `KEROSENE_VAULT_MESH_PROFILE=staging` | `vault-mesh-staging.compose.yaml` | Clearnet published ports | `distributed_wire` | mTLS |
| `KEROSENE_VAULT_MESH_PROFILE=tor` | `vault-mesh-tor.compose.yaml` | Real Tor HS + SOCKS; **no vault host ports** | `distributed_wire` | lab smoke: `static_token`; **ceremony: mTLS + onion/SPIFFE** |

Lab clearnet remains the local-full / kfe visualize default. Opt into Tor mesh without leaving deploy:

```bash
KEROSENE_VAULT_MESH_PROFILE=tor bash infra/deploy.sh --wait
# or only the mesh helper:
KEROSENE_VAULT_MESH_PROFILE=tor bash infra/kubernetes/scripts/ensure-vault-mesh-lab.sh
```

Tor profile does **not** publish `:7701–7703` on the host, so the local-full kfe Endpoints bridge is for lab/staging only. **Production genesis ceremony must use Tor** (`VAULT_TRANSPORT=tor`) **and mTLS** (`VAULT_AUTH_MODE=mtls`). Staging/production binary hygiene **refuses** `static_token`.

## Operator: Tor lab smoke (token) vs ceremony mTLS

```bash
# Lab variability only (static_token; expects Tor latency/retries)
./scripts/lab_dkg_wire_tor.sh

# Ceremony-shaped path: mTLS over onions (SPIFFE URI and/or .onion DNS SAN)
VAULT_AUTH_MODE=mtls ./scripts/lab_dkg_wire_tor.sh
```

What the script does:

1. Starts 3 Tor daemons (onion HS → vault:7701, SOCKS on `127.0.0.1:19051–19053`).
2. Waits for `.onion` hostnames (Tor bootstrap — expect tens of seconds).
3. **mTLS mode:** mints/rotates lab certs with SPIFFE URI + onion DNS SANs (`VAULT_LAB_MTLS_ONION_SANS`).
4. Starts 3 vaults on a private Docker network with `VAULT_SEED_PEERS=…onion…` and `VAULT_SOCKS_PROXY=socks5h://tor-N:9050`.
5. Runs over-wire DKG rounds via `curl --socks5-hostname` with retries/jitter (and `--cert` under mTLS).

Expect slower rounds, occasional retries on circuit drops — that is intentional. Tor HTTP defaults remain 180s / 5 retries with jitter.

## mTLS verify over Tor (SPIFFE-like)

Patterned on `docs/MTLS_SPIFFE_LAYOUT.md`:

| Knob | Meaning |
| --- | --- |
| `VAULT_TLS_VERIFY_MODE=onion_or_spiffe` | **Tor default.** Chain to CA, then accept **hostname match** (including `.onion` DNS SAN) **or** URI SAN = expected SPIFFE ID |
| `VAULT_TLS_VERIFY_MODE=spiffe` | Chain + URI SAN must equal `VAULT_TLS_PEER_SPIFFE_ID` (ignore DNS) |
| `VAULT_TLS_VERIFY_MODE=hostname` | Clearnet default — strict webpki DNS/IP |
| `VAULT_TLS_PEER_SPIFFE_ID` | Default `spiffe://kerosene.lab/vault/server` (or `VAULT_MTLS_SPIFFE_VAULT`) |

Outbound wire DKG and anti-nonce prepare use the same rustls client config (client cert + verify policy + SOCKS). Peer URLs are upgraded `http://` → `https://` under mTLS.

Lab cert gen:

```bash
VAULT_LAB_MTLS_ONION_SANS=a.onion,b.onion,c.onion \
  ./scripts/gen_lab_mtls_certs.sh
```

SPIFFE URI is always on the server leaf — so verify works even if onions change and certs are not immediately rotated (prefer rotating leaves after onion discovery for dual coverage).

## Production ceremony checklist extras

`genesis_ceremony_checklist.sh` (production mode) requires:

- `VAULT_TRANSPORT=tor`
- `VAULT_SOCKS_PROXY` set (e.g. `socks5h://127.0.0.1:9050`)
- Onion `VAULT_SEED_PEERS`
- `VAULT_CLEARNET_PUBLISH` unset / not `1`
- `VAULT_AUTH_MODE=mtls` (static_token refused)
- `VAULT_TLS_VERIFY_MODE` is `onion_or_spiffe` or `spiffe` (not bare hostname-only for Tor)
- TLS paths + peer SPIFFE ID present
- Existing Gate: `distributed_wire`, honest attestation tiers (domestic / SEV seating unchanged)

Binary hygiene also refuses production clearnet transport, clearnet publish, and staging/production static_token.

## Config knobs

| Env | Meaning |
| --- | --- |
| `VAULT_TRANSPORT=tor\|clearnet` | Mesh transport; production defaults to `tor` |
| `VAULT_SOCKS_PROXY` | `socks5h://host:9050` (hostname via Tor — required for `.onion`) |
| `VAULT_HTTP_TIMEOUT_SECS` | Default 180 on Tor / 30 clearnet |
| `VAULT_HTTP_MAX_RETRIES` | Default 5 on Tor / 1 clearnet |
| `VAULT_HTTP_RETRY_BASE_MS` / `_JITTER_MS` | Backoff with jitter |
| `VAULT_CLEARNET_PUBLISH=1` | Forbidden in production ceremony |
| `VAULT_AUTH_MODE` / `VAULT_TLS_*` / `VAULT_TLS_VERIFY_MODE` | Ceremony mTLS + onion/SPIFFE verify |

## Remaining work (honest gaps)

Shipped: SOCKS outbound + onion listeners + wire DKG + Tor timeouts/retries + **mTLS over Tor with `.onion` SAN / SPIFFE verify** + compose/script + hygiene/checklist gates.

Still open:

1. **Client-auth onion (authorized_clients)** — HS is v3 public onion; optional restricted discovery later. Script `scripts/gen_tor_auth_clients.sh` generates X25519 key pairs. Runtime mounts belong to `kerosene-deploy`. Set `VAULT_TOR_AUTH_CLIENTS=true` in your environment to gate-on enable.
2. **deploy.sh does not switch** to Tor mesh — intentional (local-full still clearnet lab).
3. **Host Tor instead of sidecar** — supported via env (`VAULT_SOCKS_PROXY=socks5h://127.0.0.1:9050`) but not automated.
4. **Anti-nonce / day-advance under Tor** — uses same SOCKS + mTLS client settings; long-run soak not automated in CI.
5. **No HashiCorp / mpc-sidecar** — do not revive; cutover remains mesh-only.

### Authorized Clients (Stealth) Procedure

1. Generate X25519 keys offline on each operator machine:
   ```bash
   ./scripts/gen_tor_auth_clients.sh --client-count 3
   ```
   This creates `infra/runtime/tor/authorized_clients/kerosene_service/client-N/` with `.auth` + `.x25519.key`.

2. Copy `.auth` files to each Tor daemon's HS `authorized_clients/` directory (already mounted via compose).

3. In `torrc` add (or ensure it's there):
   ```
   HiddenServiceAuthorizeClient stealth kerosene_service
   ```

4. Restart Tor daemons. The HS will only accept connections from authorized clients.

5. Distribute the operator's `.x25519.key` to each operator securely. This private key is used by the operator's Tor client (`ClientOnionAuthDir`).

## Domestic + SEV seating

Unchanged: `VAULT_NODE_TIER` / `VAULT_PEER_TIERS` / genesis seating from domestic-first + SEV priority. Tor is transport only.
