# Vault production gates — release evidence

The versioned authenticated operator source-archive ingestion and release
compatibility read are implemented with local immutable content-addressed
storage, bounded inert bundles, identity/version/production/freshness checks,
and explicit fail-closed unknown results. Existing `/admin/compatibility`
remains a capabilities response.

Production release acceptance remains blocked: independent artifact/build
verification, authenticated governance approval, and monotonic release sequence
authorization are unavailable. Legacy lab release labels do not close these
gates. Compatibility v1 reports `compatible: false` and `signerActivation: false`.

Production rejects dealer support at compile time. No custody/FROST gate is
opened by archival, compatibility reads, or CI publishing evidence. Production
deployment and signer admission/activation still require independent approval.
The archive is local durable storage, not immutable against a privileged disk
owner and not a release consensus ledger or verified Git history.

API details: [release evidence v1](reference/RELEASE_EVIDENCE_V1.md).
Threats and approval boundaries: [threat model](security/RELEASE_EVIDENCE_THREAT_MODEL.md).
