# Mesh audit keys (F8) — ≠ release ≠ settlement

**Requirement (F8 go-live):** monitoring / mesh audit signing keys must be
**disjoint** from release cosign materials and from settlement (FROST shares /
Intent–PSBT path).

| Plane | Key material | Used for |
| --- | --- | --- |
| **Settlement** | FROST threshold shares on vault nodes | Intent authorize, PSBT / Taproot cosign |
| **Release** | Council / cosign path (`/release/*`, allowlisted `Hb`) | Binary/source release activation |
| **Audit** | Ed25519 ops keys under `var/ceremony-certs/audit/` | Log / event integrity verify hooks |

Reusing a release cosign identity or a settlement share for audit signing is a
Gate failure. mTLS SVIDs (`spiffe://…/vault/…`, `…/kfe`) authenticate the mesh
plane — they are **not** audit signing keys.

## Generate

```bash
./scripts/ceremony/gen_audit_keys.sh
# → var/ceremony-certs/audit/operators/*.key|*.pub
# → var/ceremony-certs/audit/allowlist.txt
# → var/ceremony-certs/audit/env.hint
```

Source the hint before vault boot / checklist:

```bash
set -a && source var/ceremony-certs/audit/env.hint && set +a
# VAULT_AUDIT_PUBKEY_ALLOWLIST=… VAULT_AUDIT_PUBKEYS_PATH=…
```

## Verify hook (ops)

```bash
# Sign an audit event payload
./scripts/security/verify_audit_signature.sh sign \
  --key var/ceremony-certs/audit/operators/audit-ops-1.key \
  --message event.json --sig event.sig

# Verify: refuses keys not on the mesh audit allowlist
./scripts/security/verify_audit_signature.sh verify \
  --allowlist var/ceremony-certs/audit/allowlist.txt \
  --pub var/ceremony-certs/audit/operators/audit-ops-1.pub \
  --message event.json --sig event.sig
```

## Runtime

Vault loads `MeshAuditKeyAllowlist` from:

- `VAULT_AUDIT_PUBKEY_ALLOWLIST` (comma-separated hex), and/or
- `VAULT_AUDIT_PUBKEYS_PATH` (lines: `name hex`)

Production ceremony hygiene **refuses boot** when the allowlist is empty
(unless `VAULT_SKIP_AUDIT_KEYS_CHECK=1` for pre-keygen dry-run — not for go-live).

Membership check: `MeshAuditKeyAllowlist::require_allowlisted` (full append-only
audit pipeline remains a follow-up; this Gate slice separates key material).

## Checklist

`genesis_ceremony_checklist.sh` under `VAULT_CEREMONY_MODE=production` expects
audit allowlist env or `var/ceremony-certs/audit/allowlist.txt` present.
