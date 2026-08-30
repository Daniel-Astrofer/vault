//! Key refresh boundary for FROST signing.
//!
//! frost-secp256k1 v3 provides a share-refresh protocol for an unchanged
//! participant set. Membership-changing reshare requires a separate, complete
//! wire protocol and intentionally fails closed in this crate.

use std::collections::BTreeSet;

use frost_secp256k1 as frost;
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::signer::SignerError;

/// A single reshare message exchanged between participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareMessage {
    pub round: u8,
    pub sender: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Configuration for a reshare operation.
#[derive(Debug, Clone)]
pub struct ReshareConfig {
    /// Current set of participant identifiers.
    pub current_participants: Vec<Identifier>,
    /// New set of participant identifiers (may differ from current).
    pub new_participants: Vec<Identifier>,
    /// New threshold value.
    pub new_min_signers: u16,
}

/// Key reshare state machine.
///
/// Refreshes shares for an unchanged FROST signing group.
///
/// Membership and threshold changes are rejected until the complete
/// authenticated reshare wire protocol is available.
pub struct KeyReshare {
    /// Our current key package.
    current_key_package: frost::keys::KeyPackage,
    /// Reshare configuration.
    config: ReshareConfig,
}

/// First-round output for a same-membership distributed share refresh.
pub struct ReshareRound1Output {
    /// Secret state retained locally and consumed by round 2.
    pub secret_package: frost::keys::dkg::round1::SecretPackage,
    /// Public package broadcast over an authenticated consistent channel.
    pub package: frost::keys::dkg::round1::Package,
}

impl KeyReshare {
    /// Create a new reshare operation.
    pub fn new(current_key_package: frost::keys::KeyPackage, config: ReshareConfig) -> Result<Self, SignerError> {
        Ok(Self { current_key_package, config })
    }

    /// Execute round 1 of a same-membership distributed share refresh.
    ///
    /// Membership or threshold changes are not approximated with a fresh DKG:
    /// doing so would silently change the group key. They fail closed until the
    /// authenticated wire reshare protocol is implemented.
    pub fn round1(&self) -> Result<ReshareRound1Output, SignerError> {
        let current: BTreeSet<_> = self.config.current_participants.iter().copied().collect();
        let new: BTreeSet<_> = self.config.new_participants.iter().copied().collect();
        if current.len() != self.config.current_participants.len() || new.len() != self.config.new_participants.len() {
            return Err(SignerError::InvalidSessionConfiguration(
                "refresh participant identifiers must be unique".into(),
            ));
        }
        if current != new {
            return Err(SignerError::UnsupportedOperation(
                "membership-changing FROST reshare requires the wire protocol".into(),
            ));
        }
        if !current.contains(self.current_key_package.identifier()) {
            return Err(SignerError::InvalidSessionConfiguration(
                "local key package is not present in the refresh roster".into(),
            ));
        }

        let mut rng = OsRng;
        let new_n = self.config.new_participants.len() as u16;
        let new_t = self.config.new_min_signers;
        if new_n == 0 || new_t == 0 || new_t > new_n {
            return Err(SignerError::InvalidSessionConfiguration(format!(
                "invalid refresh threshold t={new_t}, n={new_n}"
            )));
        }
        if *self.current_key_package.min_signers() != new_t {
            return Err(SignerError::UnsupportedOperation(
                "threshold-changing FROST reshare requires the wire protocol".into(),
            ));
        }

        let (secret_package, package) =
            frost::keys::refresh::refresh_dkg_part1(*self.current_key_package.identifier(), new_n, new_t, &mut rng)
                .map_err(|e| SignerError::RoundError(format!("refresh round1: {e}")))?;

        Ok(ReshareRound1Output { secret_package, package })
    }

    /// Verify that the reshare produces a valid key package.
    ///
    /// In a real deployment, this would involve multiple rounds of communication
    /// between participants. For now, this is a simplified in-process version.
    pub fn verify_new_key(
        new_key_package: &frost::keys::KeyPackage,
        pubkey_package: &frost::keys::PublicKeyPackage,
        old_pubkey_package: &frost::keys::PublicKeyPackage,
    ) -> Result<bool, SignerError> {
        // Both the participant package and the reconstructed public package
        // must remain bound to the original group verifying key.
        Ok(new_key_package.verifying_key() == old_pubkey_package.verifying_key()
            && pubkey_package.verifying_key() == old_pubkey_package.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::keys::{generate_with_dealer, IdentifierList, KeyPackage};

    #[test]
    fn reshare_preserves_group_public_key() {
        let mut rng = OsRng;

        // Generate original keys with dealer.
        let (shares, old_pubkey) = generate_with_dealer(5, 3, IdentifierList::Default, &mut rng).unwrap();
        let old_key_package = KeyPackage::try_from(shares.into_values().next().unwrap()).unwrap();

        assert!(KeyReshare::verify_new_key(&old_key_package, &old_pubkey, &old_pubkey).unwrap());

        // A fresh dealer run changes the group key and must be rejected rather
        // than presented as a successful reshare.
        let (new_shares, new_pubkey) = generate_with_dealer(5, 3, IdentifierList::Default, &mut rng).unwrap();
        let new_key_package = KeyPackage::try_from(new_shares.into_values().next().unwrap()).unwrap();
        assert!(!KeyReshare::verify_new_key(&new_key_package, &new_pubkey, &old_pubkey).unwrap());
    }

    #[test]
    fn membership_change_fails_closed() {
        let mut rng = OsRng;
        let (mut shares, _) = generate_with_dealer(3, 2, IdentifierList::Default, &mut rng).unwrap();
        let ids = shares.keys().copied().collect::<Vec<_>>();
        let config = ReshareConfig {
            current_participants: ids.clone(),
            new_participants: ids[..2].to_vec(),
            new_min_signers: 2,
        };
        let key_package = KeyPackage::try_from(shares.remove(&ids[0]).unwrap()).unwrap();
        let reshare = KeyReshare::new(key_package, config).unwrap();

        assert!(matches!(reshare.round1(), Err(SignerError::UnsupportedOperation(_))));
    }

    #[test]
    fn refresh_roster_is_a_unique_set() {
        let mut rng = OsRng;
        let (mut shares, _) = generate_with_dealer(3, 2, IdentifierList::Default, &mut rng).unwrap();
        let ids = shares.keys().copied().collect::<Vec<_>>();
        let key_package = KeyPackage::try_from(shares.remove(&ids[0]).unwrap()).unwrap();

        let reordered = ReshareConfig {
            current_participants: ids.clone(),
            new_participants: ids.iter().rev().copied().collect(),
            new_min_signers: 2,
        };
        assert!(KeyReshare::new(key_package.clone(), reordered).unwrap().round1().is_ok());

        let duplicated = ReshareConfig {
            current_participants: ids.clone(),
            new_participants: vec![ids[0], ids[0], ids[2]],
            new_min_signers: 2,
        };
        assert!(matches!(
            KeyReshare::new(key_package, duplicated).unwrap().round1(),
            Err(SignerError::InvalidSessionConfiguration(_))
        ));
    }
}
