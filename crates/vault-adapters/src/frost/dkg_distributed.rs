//! Distributed FROST DKG (no dealer) — Production Gate.
//!
//! Trail of Bits (2024): malicious participants in naive/dealer DKG can silently
//! raise the threshold. This adapter uses `frost-secp256k1` multi-round DKG
//! (`part1`/`part2`/`part3`) and asserts `min_signers` matches the constitution
//! after part3.
//!
//! - `VAULT_DKG_MODE=distributed` — in-process multi-party simulation (single process).
//! - `VAULT_DKG_MODE=distributed_wire` — over-wire HTTP(S) round exchange (`dkg_wire` +
//!   `/v1/dkg/round{1,2,3}`); peer auth via `X-Vault-Token` or mTLS; each vault holds
//!   only its own share after protocol. ToB: frozen roster/threshold + transcript binding.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;

use crate::application::{DkgPort, ShareStorePort};
use crate::domain::DomainError;

/// Result of an in-process N-party FROST DKG (each logical participant holds
/// only its own key package; group secret never assembled).
pub struct FrostDistributedBundle {
    /// Secret signing package for each logical participant identifier.
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    /// Shared public package and group verifying key.
    pub pubkey_package: PublicKeyPackage,
    /// Total logical participant count used for this DKG.
    pub max_signers: u16,
    /// Threshold required for signatures from this DKG.
    pub min_signers: u16,
}

/// Adapter for dealerless FROST DKG operations and share persistence.
pub struct DistributedDkgAdapter;

impl DistributedDkgAdapter {
    /// Creates the stateless distributed DKG adapter.
    pub fn new() -> Self {
        Self
    }

    /// Always rejects a request to use single-party dealer key generation.
    pub fn refuse_dealer_attempt() -> Result<(), DomainError> {
        Err(DomainError::DealerForbidden("distributed DKG only; dealer single-process is lab-only (ToB 2024)".into()))
    }

    /// Runs a dealerless DKG simulation for `max_signers` logical participants.
    ///
    /// This executes all logical participants inside one process; it does not
    /// assemble the group secret or call dealer key generation. Use the wire
    /// adapter to run participants in separate vault processes.
    ///
    /// After part3, verifies every `KeyPackage.min_signers()` and the group
    /// `PublicKeyPackage` threshold equal `min_signers` (ToB threshold inflation
    /// regression: constitution `t` must stick).
    pub fn run_in_process(max_signers: u16, min_signers: u16) -> Result<FrostDistributedBundle, DomainError> {
        if max_signers < 2 || min_signers < 2 || min_signers > max_signers {
            return Err(DomainError::ThresholdError(format!(
                "bad frost DKG params: max={max_signers} min={min_signers}"
            )));
        }

        let identifiers: Vec<Identifier> = (1..=max_signers)
            .map(|i| {
                Identifier::try_from(i).map_err(|e| DomainError::ThresholdError(format!("frost identifier {i}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // --- Round 1: each participant produces secret + broadcast package ---
        let mut round1_secrets = BTreeMap::new();
        let mut round1_packages = BTreeMap::new();
        for id in &identifiers {
            let (secret, package) = frost::keys::dkg::part1(*id, max_signers, min_signers, OsRng)
                .map_err(|e| DomainError::ThresholdError(format!("frost dkg part1: {e}")))?;
            round1_secrets.insert(*id, secret);
            round1_packages.insert(*id, package);
        }

        // --- Round 2: each participant consumes others' round1 packages ---
        let mut round2_secrets = BTreeMap::new();
        // receiver -> (sender -> package)
        let mut round2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
            BTreeMap::new();
        for id in &identifiers {
            let mut received = round1_packages.clone();
            received.remove(id);
            let secret =
                round1_secrets.remove(id).ok_or_else(|| DomainError::ThresholdError("missing round1 secret".into()))?;
            let (r2_secret, outbound) = frost::keys::dkg::part2(secret, &received)
                .map_err(|e| DomainError::ThresholdError(format!("frost dkg part2: {e}")))?;
            round2_secrets.insert(*id, r2_secret);
            for (receiver, package) in outbound {
                round2_inbox.entry(receiver).or_default().insert(*id, package);
            }
        }

        // --- Round 3: finalize key packages; assert threshold constitution ---
        let mut key_packages = BTreeMap::new();
        let mut pubkey_package: Option<PublicKeyPackage> = None;
        for id in &identifiers {
            let mut r1_received = round1_packages.clone();
            r1_received.remove(id);
            let r2_received = round2_inbox
                .get(id)
                .ok_or_else(|| DomainError::ThresholdError(format!("missing round2 inbox for {id:?}")))?;
            let r2_secret =
                round2_secrets.get(id).ok_or_else(|| DomainError::ThresholdError("missing round2 secret".into()))?;
            let (kp, pk) = frost::keys::dkg::part3(r2_secret, &r1_received, r2_received)
                .map_err(|e| DomainError::ThresholdError(format!("frost dkg part3: {e}")))?;

            // ToB 2024: reject silent threshold inflation / deflation.
            if *kp.min_signers() != min_signers {
                return Err(DomainError::ThresholdError(format!(
                    "DKG threshold mismatch (ToB): key_package.min_signers={} expected={min_signers}",
                    kp.min_signers()
                )));
            }
            if let Some(pk_min) = pk.min_signers() {
                if pk_min != min_signers {
                    return Err(DomainError::ThresholdError(format!(
                        "DKG threshold mismatch (ToB): pubkey.min_signers={pk_min} expected={min_signers}"
                    )));
                }
            }
            if pk.max_signers() != max_signers {
                return Err(DomainError::ThresholdError(format!(
                    "DKG n mismatch: pubkey.max_signers={} expected={max_signers}",
                    pk.max_signers()
                )));
            }

            if let Some(ref existing) = pubkey_package {
                if existing.verifying_key() != pk.verifying_key() {
                    return Err(DomainError::ThresholdError("DKG participants disagree on group verifying key".into()));
                }
            } else {
                pubkey_package = Some(pk);
            }
            key_packages.insert(*id, kp);
        }

        Ok(FrostDistributedBundle {
            key_packages,
            pubkey_package: pubkey_package.ok_or_else(|| DomainError::ThresholdError("empty DKG result".into()))?,
            max_signers,
            min_signers,
        })
    }

    /// Persists each participant package and the common public package.
    ///
    /// Key packages are written under identifier-specific IDs and the public
    /// package under a fixed ID. The share store must provide appropriate
    /// sealing/access policy; an error may occur after earlier packages were
    /// already written.
    pub fn persist_shares(
        bundle: &FrostDistributedBundle,
        share_store: &dyn ShareStorePort,
    ) -> Result<(), DomainError> {
        for (id, kp) in &bundle.key_packages {
            let bytes =
                kp.serialize().map_err(|e| DomainError::ThresholdError(format!("key package serialize: {e}")))?;
            let share_id = format!("frost-dkg-id-{}", hex::encode(id.serialize()));
            share_store.put_share(&share_id, &bytes)?;
        }
        let pk_bytes = bundle
            .pubkey_package
            .serialize()
            .map_err(|e| DomainError::ThresholdError(format!("pubkey package serialize: {e}")))?;
        share_store.put_share("frost-dkg-pubkey", &pk_bytes)?;
        Ok(())
    }
}

impl Default for DistributedDkgAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DkgPort for DistributedDkgAdapter {
    /// Returns the application-facing DKG mode identifier.
    fn mode_name(&self) -> &'static str {
        "distributed"
    }

    /// Reports that this adapter does not use dealer key generation.
    fn is_dealer(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        AeadDiskShareStore, FrostSignOrchestrator, LedgerDayEpochStub, PersistedAntiNonce, SystemClock,
    };
    use std::sync::Arc;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-dkg-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn distributed_dkg_n3_t2_threshold_matches_and_signs() {
        let bundle = DistributedDkgAdapter::run_in_process(3, 2).unwrap();
        assert_eq!(bundle.max_signers, 3);
        assert_eq!(bundle.min_signers, 2);
        assert_eq!(bundle.key_packages.len(), 3);
        for kp in bundle.key_packages.values() {
            assert_eq!(*kp.min_signers(), 2);
        }
        assert_eq!(bundle.pubkey_package.min_signers(), Some(2));
        assert_eq!(bundle.pubkey_package.max_signers(), 3);

        let tmp = TempDir::new("sign");
        let store = AeadDiskShareStore::new(tmp.0.join("shares"), "lab-dkg-pass");
        DistributedDkgAdapter::persist_shares(&bundle, &store).unwrap();
        // Round-trip one share
        let first_id = *bundle.key_packages.keys().next().unwrap();
        let share_id = format!("frost-dkg-id-{}", hex::encode(first_id.serialize()));
        let loaded = store.get_share(&share_id).unwrap();
        let restored = KeyPackage::deserialize(&loaded).unwrap();
        assert_eq!(*restored.min_signers(), 2);

        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation = LedgerDayEpochStub::new(Arc::new(SystemClock));
        let orch = FrostSignOrchestrator::new(
            bundle.key_packages,
            bundle.pubkey_package,
            2,
            Box::new(anti),
            Arc::new(rotation),
        );
        let r = orch.sign_lab_quorum("dkg-sess-1", b"distributed-dkg-msg").unwrap();
        assert_eq!(r.participants, 2);
        assert!(!r.signature_hex.is_empty());
    }

    #[test]
    fn distributed_path_never_uses_dealer_flag() {
        let adapter = DistributedDkgAdapter::new();
        assert!(!adapter.is_dealer());
        assert_eq!(adapter.mode_name(), "distributed");
        assert!(DistributedDkgAdapter::refuse_dealer_attempt().is_err());
    }
}
