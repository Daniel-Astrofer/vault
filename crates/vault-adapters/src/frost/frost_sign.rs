//! FROST round1 / round2 / aggregate with anti-nonce + day_epoch binding + zeroize.

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_secp256k1 as frost;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::round2::SignatureShare;
use frost_secp256k1::{Identifier, Signature, SigningPackage};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::application::{AntiNoncePort, DailyRotationPort};
use crate::domain::DomainError;
use crate::{FrostShareSlot, FrostShareState};

#[derive(Debug)]
/// Result metadata for a completed FROST signature operation.
pub struct FrostAggregateResult {
    /// Anti-replay session identifier supplied to the signing operation.
    pub session_id: String,
    /// Ledger day epoch authorized for this signature.
    pub day_epoch: String,
    /// Serialized FROST signature encoded as lowercase hexadecimal.
    pub signature_hex: String,
    /// Number of local signing shares included in the aggregate.
    pub participants: usize,
}

/// Coordinates anti-replay, epoch validation, and in-process FROST signing.
///
/// This orchestrator assembles local shares and is intended for lab workflows;
/// distributed production signing uses the wire signing implementation.
pub struct FrostSignOrchestrator {
    shares: Arc<FrostShareSlot>,
    anti_nonce: Box<dyn AntiNoncePort>,
    rotation: Arc<dyn DailyRotationPort>,
}

impl FrostSignOrchestrator {
    /// Creates an orchestrator with a newly initialized slot containing the given shares.
    pub fn new(
        key_packages: BTreeMap<Identifier, KeyPackage>,
        pubkey_package: PublicKeyPackage,
        min_signers: usize,
        anti_nonce: Box<dyn AntiNoncePort>,
        rotation: Arc<dyn DailyRotationPort>,
    ) -> Self {
        let shares = Arc::new(FrostShareSlot::new());
        shares.install(FrostShareState { key_packages, pubkey_package, min_signers });
        Self { shares, anti_nonce, rotation }
    }

    /// Creates an orchestrator that reads its key material from a shared slot.
    pub fn from_share_slot(
        shares: Arc<FrostShareSlot>,
        anti_nonce: Box<dyn AntiNoncePort>,
        rotation: Arc<dyn DailyRotationPort>,
    ) -> Self {
        Self { shares, anti_nonce, rotation }
    }

    /// Returns a shared handle to the installed FROST material slot.
    pub fn share_slot(&self) -> Arc<FrostShareSlot> {
        self.shares.clone()
    }

    /// Signs a message using `min_signers` locally available shares.
    ///
    /// The message is bound to the session ID and current day epoch before
    /// signing. The session is claimed before subsequent validation, so any
    /// failure after the claim consumes that anti-replay ID. This in-process
    /// operation is for lab use; distributed nodes must use wire signing.
    pub fn sign_lab_quorum(&self, session_id: &str, message: &[u8]) -> Result<FrostAggregateResult, DomainError> {
        self.anti_nonce.claim_session(session_id)?;
        let day_epoch = self.rotation.current_day_epoch()?;
        self.rotation.require_epoch(&day_epoch)?;
        let mut bound_message = bind_message(message, session_id, day_epoch.as_str());

        let snap = self.shares.snapshot()?;
        let key_packages = &snap.key_packages;
        let pubkey_package = &snap.pubkey_package;
        let min_signers = snap.min_signers;

        let mut rng = OsRng;
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        let identifiers: Vec<Identifier> = key_packages.keys().copied().collect();
        if identifiers.len() < min_signers {
            return Err(DomainError::FailStop { online: identifiers.len(), need: min_signers });
        }

        for id in identifiers.iter().take(min_signers) {
            let kp = key_packages.get(id).ok_or_else(|| DomainError::ThresholdError("missing key package".into()))?;
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let signing_package = SigningPackage::new(commitments_map, &bound_message);
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for id in nonces_map.keys().copied().collect::<Vec<_>>() {
            let kp = &key_packages[&id];
            let nonces = &nonces_map[&id];
            let share = match frost::round2::sign(&signing_package, nonces, kp) {
                Ok(share) => share,
                Err(e) => {
                    // Zeroize ephemeral round nonces on failure (side-channel hygiene).
                    for n in nonces_map.values_mut() {
                        n.zeroize();
                    }
                    return Err(DomainError::ThresholdError(format!("frost round2: {e}")));
                }
            };
            signature_shares.insert(id, share);
        }

        for (_, mut n) in nonces_map {
            n.zeroize();
        }

        let signature: Signature = frost::aggregate(&signing_package, &signature_shares, pubkey_package)
            .map_err(|e| DomainError::ThresholdError(format!("frost aggregate: {e}")))?;

        pubkey_package
            .verifying_key()
            .verify(&bound_message, &signature)
            .map_err(|e| DomainError::ThresholdError(format!("frost verify: {e}")))?;

        bound_message.zeroize();

        let sig_bytes =
            signature.serialize().map_err(|e| DomainError::ThresholdError(format!("sig serialize: {e}")))?;

        Ok(FrostAggregateResult {
            session_id: session_id.to_string(),
            day_epoch: day_epoch.as_str().to_string(),
            signature_hex: hex::encode(sig_bytes),
            participants: signature_shares.len(),
        })
    }

    /// Serializes an aggregate result with the `frost-secp256k1-v3` scheme tag.
    pub fn to_json(result: &FrostAggregateResult) -> String {
        format!(
            r#"{{"session_id":"{}","day_epoch":"{}","signature":"{}","participants":{},"scheme":"frost-secp256k1-v3"}}"#,
            result.session_id, result.day_epoch, result.signature_hex, result.participants
        )
    }
}

fn bind_message(message: &[u8], session_id: &str, day_epoch: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + session_id.len() + day_epoch.len() + 32);
    out.extend_from_slice(b"kerosene-frost-v1|");
    out.extend_from_slice(day_epoch.as_bytes());
    out.push(b'|');
    out.extend_from_slice(session_id.as_bytes());
    out.push(b'|');
    out.extend_from_slice(message);
    out
}

#[cfg(all(test, feature = "dealer_lab"))]
mod tests {
    use super::*;
    use crate::adapters::{
        DealerLabAdapter, LedgerDayEpochStub, PersistedAntiNonce, QuorumDailyRotation, RecordingReshareHook,
        SystemClock,
    };
    use crate::application::ClockPort;
    use crate::domain::DomainError;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempProbe(std::path::PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-frost-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FakeClock(AtomicU64);
    impl ClockPort for FakeClock {
        fn unix_now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn frost_sign_and_reject_session_reuse() {
        let bundle = DealerLabAdapter::generate(3, 2).unwrap();
        let tmp = TempProbe::new("sign");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> = Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let orch = FrostSignOrchestrator::new(bundle.key_packages, bundle.pubkey_package, 2, Box::new(anti), rotation);
        let r = orch.sign_lab_quorum("sess-a", b"hello").unwrap();
        assert_eq!(r.participants, 2);
        assert!(!r.signature_hex.is_empty());
        let err = orch.sign_lab_quorum("sess-a", b"hello2").unwrap_err();
        assert!(matches!(err, DomainError::NonceReuse(_)));
    }

    #[test]
    fn frost_sign_rejects_stale_day_epoch() {
        let bundle = DealerLabAdapter::generate(3, 2).unwrap();
        let tmp = TempProbe::new("stale");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200)));
        let rotation: Arc<dyn DailyRotationPort> =
            Arc::new(QuorumDailyRotation::new(clock.clone(), 1, "local", Arc::new(RecordingReshareHook::new())));
        let orch = FrostSignOrchestrator::new(bundle.key_packages, bundle.pubkey_package, 2, Box::new(anti), rotation);
        orch.sign_lab_quorum("sess-ok", b"hello").unwrap();
        clock.0.store(1_704_067_200 + 86_400, Ordering::SeqCst);
        let err = orch.sign_lab_quorum("sess-stale", b"hello").unwrap_err();
        assert!(matches!(err, DomainError::DayEpochStale { .. }));
    }
}
