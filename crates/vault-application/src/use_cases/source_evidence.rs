//! Archival and compatibility observations never invoke release activation or signing.

use std::collections::BTreeMap;
use std::sync::Arc;

use vault_domain::{ContentHash, DomainError, SourceArchiveReceiptV1, SourceBundleV1};

use crate::ports::{ClockPort, SourceArchiveStorePort};

pub struct IngestSourceArchive {
    archives: Arc<dyn SourceArchiveStorePort>,
    clock: Arc<dyn ClockPort>,
}

impl IngestSourceArchive {
    pub fn new(archives: Arc<dyn SourceArchiveStorePort>, clock: Arc<dyn ClockPort>) -> Self {
        Self { archives, clock }
    }

    pub fn execute(&self, body: &[u8]) -> Result<SourceArchiveReceiptV1, DomainError> {
        let bundle = SourceBundleV1::parse(body)?;
        let canonical = bundle.canonical_bytes()?;
        let receipt = SourceArchiveReceiptV1 {
            format_version: 1,
            release_id: bundle.release_id,
            canonical_digest: ContentHash::from_bytes(&canonical).as_str().to_string(),
            target_sequence: bundle.target_sequence,
            archived_at_secs: self.clock.unix_now_secs(),
        };
        if receipt.archived_at_secs == 0 {
            return Err(DomainError::InvalidRelease("archive clock unavailable".into()));
        }
        self.archives.put_source_archive(receipt, &canonical)
    }
}

/// Versions are supplied from the actual runtime format constants, not request claims.
#[derive(Debug, Clone)]
pub struct ReleaseCompatibilityContext {
    pub protocol_version: u16,
    pub storage_version: u16,
    pub share_storage_version: u16,
    pub production_safe: bool,
    pub features: Vec<String>,
    pub observed_at_secs: u64,
}

pub struct GetReleaseCompatibility {
    archives: Arc<dyn SourceArchiveStorePort>,
}

impl GetReleaseCompatibility {
    pub fn new(archives: Arc<dyn SourceArchiveStorePort>) -> Self {
        Self { archives }
    }

    pub fn execute(
        &self,
        release_id: &str,
        requested_digest: &ContentHash,
        target_sequence: u64,
        context: &ReleaseCompatibilityContext,
    ) -> Result<serde_json::Value, DomainError> {
        let (receipt, bytes) = self.archives.get_source_archive(release_id)?;
        let raw = bytes
            .strip_prefix(b"vault-source-bundle-v1\n")
            .ok_or_else(|| DomainError::InvalidRelease("invalid canonical source archive".into()))?;
        let bundle = SourceBundleV1::parse(raw)?;
        let canonical = bundle.canonical_bytes()?;
        if canonical != bytes
            || receipt.format_version != 1
            || receipt.release_id != release_id
            || bundle.release_id != release_id
            || receipt.target_sequence != bundle.target_sequence
            || receipt.canonical_digest != ContentHash::from_bytes(&bytes).as_str()
        {
            return Err(DomainError::InvalidRelease("source archive integrity failure".into()));
        }
        if receipt.canonical_digest != requested_digest.as_str() || receipt.target_sequence != target_sequence {
            return Err(DomainError::ReleasePredicate("requested release binding mismatch".into()));
        }

        let mut checks = BTreeMap::new();
        let status = |ok| if ok { "passed" } else { "failed" };
        checks.insert("archiveIntegrity", "passed");
        checks.insert("releaseBinding", "passed");
        checks.insert(
            "protocolVersion",
            if context.protocol_version == 0 {
                "unknown"
            } else {
                status(bundle.protocol_version == context.protocol_version)
            },
        );
        checks.insert("storageVersion", status(bundle.storage_version == context.storage_version));
        checks.insert(
            "productionPolicy",
            status(
                bundle.production
                    && context.production_safe
                    && bundle.features.contains("production")
                    && !bundle
                        .features
                        .iter()
                        .any(|f| f.to_ascii_lowercase().contains("lab") || f.to_ascii_lowercase().contains("dealer")),
            ),
        );
        checks.insert("featureSupport", status(bundle.features.iter().all(|f| context.features.contains(f))));
        let expires = context.observed_at_secs.checked_add(300);
        checks.insert(
            "freshness",
            status(
                context.observed_at_secs != 0
                    && receipt.archived_at_secs != 0
                    && receipt.archived_at_secs <= context.observed_at_secs
                    && expires.is_some(),
            ),
        );
        // Source declarations and lab mesh labels cannot prove these properties.
        checks.insert("independentBuildVerification", "unknown");
        checks.insert("authenticatedReleaseApproval", "unknown");
        checks.insert("targetSequenceAuthorization", "unknown");
        let compatible = checks.values().all(|s| *s == "passed");
        Ok(serde_json::json!({
            "evidenceVersion": 1,
            "releaseId": receipt.release_id,
            "canonicalDigest": receipt.canonical_digest,
            "targetSequence": receipt.target_sequence,
            "currentProtocolVersion": if context.protocol_version == 0 { None } else { Some(context.protocol_version) },
            "currentHybridEnvelopeVersion": vault_domain::HybridEnvelope::CURRENT_FORMAT_VERSION,
            "currentStorageVersion": context.storage_version,
            "currentShareEnvelopeVersion": if context.share_storage_version == 0 { None } else { Some(context.share_storage_version) },
            "observedAtSecs": context.observed_at_secs,
            "expiresAtSecs": expires,
            "maxAgeSecs": 300,
            "archivedAtSecs": receipt.archived_at_secs,
            "checks": checks,
            "compatible": compatible,
            "signerActivation": false,
            "gitHistory": "unavailable",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use vault_domain::SourceFileV1;

    #[derive(Default)]
    struct Archive(Mutex<Option<(SourceArchiveReceiptV1, Vec<u8>)>>);
    impl SourceArchiveStorePort for Archive {
        fn put_source_archive(
            &self,
            r: SourceArchiveReceiptV1,
            b: &[u8],
        ) -> Result<SourceArchiveReceiptV1, DomainError> {
            *self.0.lock().unwrap() = Some((r.clone(), b.to_vec()));
            Ok(r)
        }
        fn get_source_archive(&self, _: &str) -> Result<(SourceArchiveReceiptV1, Vec<u8>), DomainError> {
            self.0.lock().unwrap().clone().ok_or_else(|| DomainError::UnknownRelease("missing".into()))
        }
    }
    struct Clock;
    impl ClockPort for Clock {
        fn unix_now_secs(&self) -> u64 {
            100
        }
    }

    #[test]
    fn unknown_is_incompatible_and_binding_versions_policy_and_freshness_are_checked() {
        let store = Arc::new(Archive::default());
        let mut bundle = SourceBundleV1 {
            format_version: 1,
            release_id: "r1".into(),
            target_sequence: 7,
            protocol_version: 1,
            storage_version: 1,
            production: true,
            features: ["production".into()].into(),
            files: vec![SourceFileV1 { path: "build.sh".into(), content_hex: hex::encode(b"exit 99") }],
        };
        let ingest = IngestSourceArchive::new(store.clone(), Arc::new(Clock));
        let get = GetReleaseCompatibility::new(store.clone());
        let context = ReleaseCompatibilityContext {
            protocol_version: 1,
            storage_version: 1,
            share_storage_version: 1,
            production_safe: true,
            features: vec!["production".into()],
            observed_at_secs: 101,
        };
        let receipt = ingest.execute(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let digest = ContentHash::parse(&receipt.canonical_digest).unwrap();
        let report = get.execute("r1", &digest, 7, &context).unwrap();
        assert_eq!(report["compatible"], false);
        assert_eq!(report["signerActivation"], false);
        assert_eq!(report["checks"]["independentBuildVerification"], "unknown");
        assert_eq!(report["checks"]["freshness"], "passed");
        assert_eq!(report["expiresAtSecs"], 401);
        assert!(get.execute("r1", &digest, 8, &context).is_err());
        assert!(get.execute("r1", &ContentHash::from_bytes(b"hash text"), 7, &context).is_err());
        let report = get
            .execute("r1", &digest, 7, &ReleaseCompatibilityContext { production_safe: false, ..context.clone() })
            .unwrap();
        assert_eq!(report["checks"]["productionPolicy"], "failed");
        let report = get
            .execute("r1", &digest, 7, &ReleaseCompatibilityContext { protocol_version: 0, ..context.clone() })
            .unwrap();
        assert_eq!(report["checks"]["protocolVersion"], "unknown");
        assert!(report["currentProtocolVersion"].is_null());
        for now in [0, 99, u64::MAX] {
            let report = get
                .execute("r1", &digest, 7, &ReleaseCompatibilityContext { observed_at_secs: now, ..context.clone() })
                .unwrap();
            assert_eq!(report["checks"]["freshness"], "failed");
        }
        bundle.production = false;
        let r = ingest.execute(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let report = get.execute("r1", &ContentHash::parse(r.canonical_digest).unwrap(), 7, &context).unwrap();
        assert_eq!(report["checks"]["productionPolicy"], "failed");
        bundle.production = true;
        bundle.features.insert("dealer_lab".into());
        bundle.protocol_version = 2;
        bundle.storage_version = 2;
        let r = ingest.execute(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let report = get.execute("r1", &ContentHash::parse(r.canonical_digest).unwrap(), 7, &context).unwrap();
        for check in ["productionPolicy", "protocolVersion", "storageVersion", "featureSupport"] {
            assert_eq!(report["checks"][check], "failed", "{check}");
        }
        store.0.lock().unwrap().as_mut().unwrap().1.push(b' ');
        assert!(get.execute("r1", &digest, 7, &context).is_err());
    }
}
