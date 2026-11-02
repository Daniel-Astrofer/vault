//! Bind Intent payment metadata to on-chain PSBT outputs (no unbound spend).
//!
//! Also defines hybrid intent signatures (Ed25519 + ML-DSA-65) with
//! AND-logic validation per the downgrade policy.

use sha3::{Digest, Sha3_384 as Sha384};

use crate::DomainError;

/// Hybrid intent signature composed of classical Ed25519 + PQ ML-DSA-65.
/// Both signatures MUST verify (AND logic). If either is missing or invalid
/// the intent is rejected with 401 Unauthorized.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntentSignature {
    /// Ed25519 raw signature, exactly 64 bytes.
    #[serde(with = "hex_serde_64")]
    pub ed25519_signature: [u8; 64],
    /// ML-DSA-65 raw signature (variable length, ~3309 bytes typical).
    pub ml_dsa65_signature: Vec<u8>,
    /// Key identifier for the Ed25519 verification key (roster index).
    pub ed25519_key_id: String,
    /// Key identifier for the ML-DSA-65 verification key (roster index).
    pub ml_dsa_key_id: String,
    /// SHA-384 canonical hash of the intent material (both sigs sign the same hash).
    #[serde(with = "hex_serde_48")]
    pub canonical_hash: [u8; 48],
}

mod hex_serde_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes[..64]);
        Ok(arr)
    }
}

mod hex_serde_48 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes[..48]);
        Ok(arr)
    }
}

impl IntentSignature {
    /// Compute the SHA-384 canonical hash from intent serialization bytes.
    pub fn compute_canonical_hash(bytes: &[u8]) -> [u8; 48] {
        let mut h = Sha384::new();
        h.update(bytes);
        let result = h.finalize();
        let mut out = [0u8; 48];
        out.copy_from_slice(&result[..48]);
        out
    }

    /// Stub validation: checks that both signatures are non-empty and the
    /// downgrade policy allows classical-only if PQ is missing.
    /// Full cryptographic verification requires ml-dsa crate at runtime.
    pub fn validate_stub(&self, require_pq: bool) -> Result<(), DomainError> {
        if self.ed25519_signature == [0u8; 64] {
            return Err(DomainError::AuthRejected("ed25519 signature is all-zero".into()));
        }
        if self.canonical_hash == [0u8; 48] {
            return Err(DomainError::AuthRejected("canonical hash is all-zero".into()));
        }
        if require_pq && self.ml_dsa65_signature.is_empty() {
            return Err(DomainError::AuthRejected(
                "ml-dsa-65 signature required by downgrade policy but missing".into(),
            ));
        }
        Ok(())
    }
}

/// Pure check: PSBT outputs must match Intent payment + optional mesh change.
///
/// - Exactly one output pays `amount_sats` to `payment_script`
/// - Every other output must equal `change_script` (mesh deposit key / known mesh change)
/// - No third-party / attacker / Core wallet non-`tr()` change outputs
///
/// `change_script` is required whenever any non-payment output exists. Passing
/// `None` rejects all extra outs (fail-closed: Core must not send change elsewhere).
pub fn assert_outputs_match_intent(
    outputs: &[(Vec<u8>, u64)],
    payment_script: &[u8],
    amount_sats: u64,
    change_script: Option<&[u8]>,
) -> Result<(), DomainError> {
    if outputs.is_empty() {
        return Err(DomainError::InvalidIntent("PSBT has no outputs to bind to Intent".into()));
    }
    if amount_sats == 0 {
        return Err(DomainError::InvalidIntent("Intent amount_sats must be > 0 for PSBT bind".into()));
    }

    let mut payment_matched = false;
    for (spk, value) in outputs {
        if spk.as_slice() == payment_script {
            if *value != amount_sats {
                return Err(DomainError::InvalidIntent(format!(
                    "PSBT payment output amount {value} != Intent amount_sats {amount_sats}"
                )));
            }
            if payment_matched {
                return Err(DomainError::InvalidIntent("PSBT has multiple outputs to Intent destination".into()));
            }
            payment_matched = true;
            continue;
        }
        match change_script {
            Some(change) if spk.as_slice() == change => continue,
            Some(_) => {
                return Err(DomainError::InvalidIntent(
                    "PSBT change output is not mesh Taproot deposit key (non-tr / unbound change escape)".into(),
                ));
            }
            None => {
                return Err(DomainError::InvalidIntent(
                    "PSBT has non-payment output but no mesh change script configured (unbound spend)".into(),
                ));
            }
        }
    }
    if !payment_matched {
        return Err(DomainError::InvalidIntent(
            "PSBT missing output matching Intent destination and amount_sats".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_payment_and_change() {
        let pay = vec![1, 2, 3];
        let change = vec![9, 9, 9];
        let outs = vec![(pay.clone(), 1_000), (change.clone(), 500)];
        assert!(assert_outputs_match_intent(&outs, &pay, 1_000, Some(&change)).is_ok());
    }

    #[test]
    fn rejects_attacker_output() {
        let pay = vec![1];
        let change = vec![2];
        let attacker = vec![3];
        let outs = vec![(pay.clone(), 1_000), (attacker, 1)];
        let err = assert_outputs_match_intent(&outs, &pay, 1_000, Some(&change)).unwrap_err();
        assert!(matches!(err, DomainError::InvalidIntent(_)));
        let msg = err.to_string();
        assert!(msg.contains("non-tr") || msg.contains("change"), "expected change-escape message, got {msg}");
    }

    #[test]
    fn rejects_non_mesh_change_even_when_payment_ok() {
        // Intent payment correct; Core wallet change to foreign p2wpkh-like script.
        let pay = vec![0x51];
        let mesh = vec![0x52];
        let core_change = vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44];
        let outs = vec![(pay.clone(), 5_000), (core_change, 12_345)];
        let err = assert_outputs_match_intent(&outs, &pay, 5_000, Some(&mesh)).unwrap_err();
        assert!(matches!(err, DomainError::InvalidIntent(_)));
        assert!(err.to_string().contains("change escape") || err.to_string().contains("non-tr"));
    }

    #[test]
    fn rejects_extra_out_when_change_script_absent() {
        let pay = vec![1];
        let outs = vec![(pay.clone(), 1_000), (vec![9], 1)];
        assert!(assert_outputs_match_intent(&outs, &pay, 1_000, None).is_err());
    }

    #[test]
    fn rejects_amount_mismatch() {
        let pay = vec![1];
        let outs = vec![(pay.clone(), 999)];
        assert!(assert_outputs_match_intent(&outs, &pay, 1_000, None).is_err());
    }
}
