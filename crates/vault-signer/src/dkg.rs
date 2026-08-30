//! Distributed Key Generation (DKG) for FROST signing.
//!
//! Implements the FROST DKG protocol for generating keys without a trusted dealer.
//! This is the foundation for the vault mesh's distributed signing capability.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::signer::SignerError;

/// DKG round 1 output for a single participant.
pub struct DkgRound1Output {
    pub package: frost::keys::dkg::round1::Package,
}

/// DKG round 2 output for a single participant.
pub struct DkgRound2Output {
    pub secret_package: frost::keys::dkg::round2::SecretPackage,
    /// Recipient-specific packages. Each value is confidential and must only
    /// be delivered to the participant identified by its key.
    pub packages: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
}

/// Result of a completed DKG: key package and public key package.
pub struct DkgResult {
    pub key_package: frost::keys::KeyPackage,
    pub pubkey_package: frost::keys::PublicKeyPackage,
}

/// Serialized DKG message for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgMessage {
    pub round: u8,
    pub sender: Vec<u8>,
    pub payload: Vec<u8>,
}

/// State for a single DKG participant.
pub struct DkgParticipant {
    identifier: Identifier,
    min_signers: u16,
    max_signers: u16,
    round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
}

impl DkgParticipant {
    /// Create a new DKG participant.
    pub fn new(identifier: Identifier, min_signers: u16, max_signers: u16) -> Self {
        Self { identifier, min_signers, max_signers, round1_secret: None }
    }

    /// Execute DKG round 1.
    pub fn round1(&mut self) -> Result<DkgRound1Output, SignerError> {
        let mut rng = OsRng;
        let (secret, package) = frost::keys::dkg::part1(self.identifier, self.max_signers, self.min_signers, &mut rng)
            .map_err(|e| SignerError::RoundError(format!("dkg round1 part1: {e}")))?;

        self.round1_secret = Some(secret);

        Ok(DkgRound1Output { package })
    }

    /// Execute DKG round 2.
    pub fn round2(
        &mut self,
        received_round1_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    ) -> Result<DkgRound2Output, SignerError> {
        let secret = self
            .round1_secret
            .take()
            .ok_or_else(|| SignerError::Internal("round1 not executed or already consumed".into()))?;

        let (round2_secret, packages) = frost::keys::dkg::part2(secret, received_round1_packages)
            .map_err(|e| SignerError::RoundError(format!("dkg round2 part2: {e}")))?;

        Ok(DkgRound2Output { secret_package: round2_secret, packages })
    }

    /// Finalize DKG, producing the key package and public key package.
    pub fn finalize(
        &self,
        round2_secret: &frost::keys::dkg::round2::SecretPackage,
        received_round1_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
        received_round2_packages: &BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
    ) -> Result<DkgResult, SignerError> {
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(round2_secret, received_round1_packages, received_round2_packages)
                .map_err(|e| SignerError::RoundError(format!("dkg finalize part3: {e}")))?;

        Ok(DkgResult { key_package, pubkey_package })
    }
}

/// High-level DKG orchestrator that manages all participants (for in-process testing).
pub struct DistributedKeyGeneration {
    participants: Vec<DkgParticipant>,
}

impl DistributedKeyGeneration {
    /// Initialize DKG with the given number of participants and threshold.
    pub fn new(max_signers: u16, min_signers: u16) -> Result<Self, SignerError> {
        if min_signers > max_signers || min_signers < 2 {
            return Err(SignerError::InvalidKeyPackage(format!("invalid threshold: t={min_signers}, n={max_signers}")));
        }

        let participants: Vec<_> = (1..=max_signers)
            .map(|i| {
                let id = Identifier::try_from(i).expect("valid identifier");
                DkgParticipant::new(id, min_signers, max_signers)
            })
            .collect();

        Ok(Self { participants })
    }

    /// Run the full DKG protocol in-process (all participants local).
    pub fn run_in_process(&mut self) -> Result<Vec<DkgResult>, SignerError> {
        // Round 1: each participant broadcasts one package to every *other*
        // participant. A consistent authenticated broadcast is a deployment
        // requirement; this in-process harness only models the protocol data.
        let mut round1_packages = BTreeMap::new();
        for p in &mut self.participants {
            let output = p.round1()?;
            round1_packages.insert(p.identifier, output.package);
        }

        let mut received_round1 = BTreeMap::new();
        for receiver in &self.participants {
            let packages = round1_packages
                .iter()
                .filter(|(sender, _)| **sender != receiver.identifier)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect();
            received_round1.insert(receiver.identifier, packages);
        }

        // Round 2: each participant consumes its round-1 secret and creates a
        // distinct confidential package for every other participant.
        let mut round2_outputs = Vec::new();
        for p in &mut self.participants {
            let output = p.round2(&received_round1[&p.identifier])?;
            round2_outputs.push(output);
        }

        let mut received_round2: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
            BTreeMap::new();
        for (sender, output) in self.participants.iter().zip(&round2_outputs) {
            for (receiver, package) in &output.packages {
                received_round2.entry(*receiver).or_default().insert(sender.identifier, package.clone());
            }
        }

        // Finalize: each participant produces their key package
        let mut results = Vec::new();
        for (i, p) in self.participants.iter().enumerate() {
            let result = p.finalize(
                &round2_outputs[i].secret_package,
                &received_round1[&p.identifier],
                &received_round2[&p.identifier],
            )?;
            results.push(result);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1 as frost;

    #[test]
    fn dkg_3_of_5_produces_valid_keys() {
        let mut dkg = DistributedKeyGeneration::new(5, 3).unwrap();
        let results = dkg.run_in_process().unwrap();
        assert_eq!(results.len(), 5);

        for result in &results {
            assert!(result.key_package.identifier() >= &Identifier::try_from(1u16).unwrap());
        }

        let pubkey = &results[0].pubkey_package;
        let message = b"dkg test message";

        let mut rng = OsRng;
        let mut commitments = BTreeMap::new();
        let mut nonces_list = Vec::new();

        for i in 0..3 {
            let (nonces, comm) = frost::round1::commit(results[i].key_package.signing_share(), &mut rng);
            commitments.insert(*results[i].key_package.identifier(), comm);
            nonces_list.push((*results[i].key_package.identifier(), nonces));
        }

        let signing_package = frost::SigningPackage::new(commitments, message);
        let mut shares = BTreeMap::new();
        for (i, (id, nonces)) in nonces_list.iter().enumerate() {
            let share = frost::round2::sign(&signing_package, nonces, &results[i].key_package).unwrap();
            shares.insert(*id, share);
        }

        let signature = frost::aggregate(&signing_package, &shares, pubkey).unwrap();
        assert!(pubkey.verifying_key().verify(message, &signature).is_ok());
    }
}
