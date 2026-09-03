# Production-native genesis ceremony (short runbook)

Same binary and FROST over-wire rounds as lab (`VAULT_DKG_MODE=distributed_wire`).
Only config / attestation / auth differ. Dealer and `ATTESTATION_MODE=sim` are refused.

## Attestation honesty (software ≠ TEE)

`ATTESTATION_MODE=software` is a **software measurement MAC** (shared pin / lab root),
**not** a hardware TEE quote. Health must report `tee_available=false` for domestic
nodes. Do **not** advertise software as SEV/SGX.

Optional stronger pin: set `VAULT_MEASUREMENT_PIN=<64-hex SHA-256>` on every node so
quotes bind to a known binary/constitution measurement (still not HW attestation).

Elevated `VAULT_PEER_TIERS=…=sev|sgx` require `VAULT_PEER_TIER_QUOTES=id=<hex>`
outside lab (`VAULT_PEER_TIER_REQUIRE_QUOTE` defaults on for staging/production);
without a quote, seating treats the peer as `domestic`.

## All-domestic (Ryzen-class / home PC)

1. On each of N hosts (example N=3):
   - `VAULT_CEREMONY_MODE=production` (or `KEROSENE_ENV=production`)
   - `VAULT_NODE_TIER=domestic` (or `auto` with no `/dev/sev-guest`)
   - `ATTESTATION_MODE=software`
   - `VAULT_SHARE_STORE=aead_disk`
   - Optional TPM seal (disk-at-rest; **not** SEV): `VAULT_SHARE_TPM_SEAL=1` + real TPM, or lab mock `VAULT_SHARE_TPM_STUB=1`. Fail-closed without TPM unless lab `VAULT_SHARE_TPM_CLEAR_FALLBACK=1`.
   - `VAULT_DKG_MODE=distributed_wire`
   - `VAULT_AUTH_MODE=mtls` + TLS paths (unique SPIFFE: `./scripts/ceremony/gen_mtls_certs.sh`)
   - Mesh audit keys (F8): `./scripts/ceremony/gen_audit_keys.sh` + `source var/ceremony-certs/audit/env.hint`
   - `VAULT_GENESIS_N=3` + reciprocal `VAULT_SEED_PEERS`
   - **Do not** set `ATTESTATION_STAGING_STUB` or `LAB_TIMELOCK_SCALE`
2. Gate: `./scripts/ceremony/checklist.sh`
3. Bring up peers (compose reference: `infra/docker/compose/vault-mesh-ceremony.compose.yaml`).
4. Confirm `GET /health` (auth): `node_tier=domestic`, `attestation_mode=software`, `tee_available=false`, `genesis_roster` lists N ids. Public `GET /v1/health` returns status only (no roster).
5. Run `./scripts/ceremony/dkg_wire.sh` (mTLS client certs).
6. Cutover kfe: mesh enabled, `kfe.mpc.signing-enabled=false` — do not revive HashiCorp/mpc for treasury.

## Mixed SEV-priority

1. Same as above for domestic members; SEV hosts set `VAULT_NODE_TIER=sev`, `ATTESTATION_MODE=sev`, `VAULT_SHARE_STORE=tee_seal`, and real `/dev/sev-guest` (no stub).
2. Publish peer tiers on every node: `VAULT_PEER_TIERS=vault-epyc=sev,...`
   and quote proofs: `VAULT_PEER_TIER_QUOTES=vault-epyc=<attestation-hex>`
   (required outside lab; otherwise SEV/SGX claims seat as domestic).
3. Boot seating fills `VAULT_GENESIS_N` preferring SEV > SGX > domestic; authenticated `/health` `genesis_roster` shows the seated set.
4. Run the **same** `scripts/ceremony/dkg_wire.sh` — roster must match seating (enforced in production).

## Lab vs production

| | Lab | Production ceremony |
| --- | --- | --- |
| Binary | same crate | `--features production` preferred |
| DKG | `distributed_wire` (or dealer_lab visualize) | **only** `distributed_wire` |
| Transport | clearnet lab **or** Tor lab (`vault-mesh-tor`) | **`VAULT_TRANSPORT=tor`** + onion peers + SOCKS (required) |
| Attestation | `sim` OK | `software` / `sev` / `sgx` honest |
| Auth | static token OK | mTLS |
| Seating | same algorithm | same algorithm |

**Tor runbook:** `docs/CEREMONY_TOR.md`. Deploy default is clearnet `vault-mesh-lab`; opt into Tor with `KEROSENE_VAULT_MESH_PROFILE=tor`.

See `VAULT_MESH_PLAN.md` §3.1.

### Optional TPM seal (domestic AEAD)

| Var | Meaning |
| --- | --- |
| `VAULT_SHARE_TPM_SEAL=1` | Seal AEAD passphrase before `AeadDiskShareStore` (off by default) |
| `VAULT_SHARE_TPM_STUB=1` | Lab/mock TPM envelope (no HW); refused in production ceremony |
| `VAULT_SHARE_TPM_CLEAR_FALLBACK=1` | Lab only: clear passphrase if TPM unavailable; refused when hardened |

TPM binds disk-at-rest to the machine; it does **not** isolate share RAM after unseal (unlike SEV-SNP).

## Gaps (planned — do not claim shipped)

| Gap | Notes |
| --- | --- |
| **Full SNP VCEK verification** | HW path **fail-closed** without real `/dev/sev-guest` + VCEK chain; staging stub is lab-only (`ATTESTATION_STAGING_STUB`). Not production-complete. |
| **CHANNELS → LND inject** | landed (on-chain fund): Decision-gate non-mutating; soft-reserve CHANNELS → CHANNELS Taproot PSBT to LND funding address (key ≠ USERS omnibus) → `openChannel` → commit; pending-channels refuse; durable Intent id + phase resume; commit-retry reconciler. Fail-closed without mesh fund txid. |
| **Deposit xpub vs `tb1p`** | Ceremony yields stable mesh `tb1p` deposit (`tr()`); user-visible xpub / HD from group VK is not implemented; product `bitcoin.platform.master-xpub` ≠ mesh deposit |
| **Economy / release durability (#18)** | `PersistedEconomy` / `PersistedReleaseMesh` under `VAULT_DATA_DIR` (process-local atomic snapshot) — **not** authenticated mesh BFT ledger; residual: quorum-replicated economy/release |
| **Supply-chain audit (#38)** | Historical evidence recorded an audit with no HIGH/CRITICAL advisories. Re-run `cargo audit` for the current checkout before relying on this gate. |
| **Side-channel analysis (#39)** | Improved FROST round nonce zeroization on error paths in `frost_sign.rs` and `frost_wire_cosign.rs`. Residual: this is not a proof of side-channel freedom. |
| **mTLS pin / CRL (#36)** | Ceremony CA + short-lived rotation (`gen_ceremony_mtls_certs` / `rotate_ceremony_mtls_certs`); runtime pin/CRL not enforced |
| **Audit keys ≠ release (#F8)** | `docs/AUDIT_KEYS.md` + `gen_mesh_audit_keys.sh`; production hygiene requires allowlist; full audit ledger pipeline follow-up |
| **Legacy HTTP surface (#37)** | Path traversal blocked; large legacy route surface remains behind auth |

Go-live kfe: `kfe-service-vaultmesh-go-live.properties` sets `mesh-only` + `require-mtls` (refuses `api-token`). Vault hygiene refuses `static_token` / `ATTESTATION_MODE=sim` / clearnet under staging/production; production ceremony requires `VAULT_TRANSPORT=tor` + mTLS.
