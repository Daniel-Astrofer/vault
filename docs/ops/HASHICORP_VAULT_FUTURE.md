# HashiCorp Vault Post-Mesh Decision

> **Historical decision record.** This document describes an earlier
> operational-secrets evaluation. It is not a Vault Mesh runbook and does not
> expand this repository beyond custody and signing. Current deployment-secret
> decisions belong to `kerosene-deploy`.

Analysis of current HashiCorp Vault usage and migration options once the vault mesh is operational.

## Current Usage

HashiCorp Vault currently serves as the secrets backend for `kfe-service` and infrastructure:

| Secret Type | Current Store | Mesh Capable? |
|---|---|---|
| API keys (exchange, node, webhook) | HashiCorp Vault | Yes |
| JWT signing keys | HashiCorp Vault | Yes |
| Auth tokens | HashiCorp Vault | Yes |
| DB credentials | HashiCorp Vault | Yes |
| FROST shares | NEVER in HashiCorp Vault | N/A |
| ML-DSA/ML-KEM keys | NEVER in HashiCorp Vault | N/A |
| Taproot key material | NEVER in HashiCorp Vault | N/A |

**Critical invariant**: HashiCorp Vault has NEVER had access to FROST shares, custody keys, or PQ identity keys. Those live exclusively in vault mesh (`share_tee`, `share_tpm`, `share_aead`).

## Options

### Option A: Keep HashiCorp Vault
**Pros**: Mature, audited, enterprise-grade. Existing integrations (K8s auth, auto-renew, audit logs). Separate failure domain from mesh.
**Cons**: Additional cost (HCP or self-hosted infra). Operational complexity (another control plane). Not self-custody aligned.

### Option B: Migrate to Kubernetes Secrets
**Pros**: Zero additional infrastructure. Native K8s RBAC. Secrets encrypted at rest (etcd encryption). Simpler CI/CD.
**Cons**: No dynamic secrets. No built-in rotation. Less audit granularity. Cluster admin has root access.

### Option C: Migrate to Vault Mesh Self-Custody
**Pros**: Aligned with self-custody philosophy. Single control plane. PQ-hybrid auth envelope for all secrets. No external dependency.
**Cons**: Immature for secrets ops (mesh designed for FROST, not arbitrary secrets). Operational risk concentration. Audit gap vs HashiCorp Vault. Not designed for high-frequency secret rotation.

## Isolation Requirement

```
[ KFE-SERVICE ] ---- API keys, DB creds ----> [ HashiCorp Vault (or future) ]
[ KFE-SERVICE ] ---- Settlement Intents ------> [ Vault Mesh (FROST, custody) ]
                                              [ Vault Mesh: NEVER exposes shares to HashiCorp ]
```

The custody plane and the secrets ops plane MUST remain on different trust domains. HashiCorp Vault never gets FROST shares. Vault mesh (currently) never stores infra secrets.

## Recommendation

**Phase 1 (Go-Live): Keep HashiCorp Vault**
- Mature, trusted, separate failure domain
- Focus vault mesh exclusively on custody (FROST, signing, attestation)
- Don't expand mesh scope to secrets ops during F0/F1

**Phase 2 (Post-Go-Live): Evaluate Kubernetes Secrets**
- If infra secrets are static (keys, tokens) and can tolerate lower audit granularity
- Simplifies operations significantly
- Requires K8s etcd encryption + RBAC audit

**Phase 3 (Long-Term): Re-evaluate mesh self-custody**
- Only after mesh has proven operational for 12+ months
- Evaluate audit, rotation, and access control maturity
- May implement `VaultSecretsPort` trait backed by `share_tee` if audit/rotation is solved

## Operational Isolation Checklist
- [ ] Segregate service accounts: KFE-service CANNOT call vault mesh secret endpoints beyond Intent settlement
- [ ] Network segmentation: HashiCorp Vault and vault mesh on separate CIDRs/namespaces
- [ ] Audit: log all HashiCorp Vault access separately from mesh audit
- [ ] Rotation: API keys and DB creds rotate via HashiCorp Vault (or K8s) — never via mesh
