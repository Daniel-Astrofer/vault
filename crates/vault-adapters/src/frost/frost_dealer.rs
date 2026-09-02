//! FROST trusted-dealer keygen — **lab only** (`dealer_lab` feature).
//!
//! Trail of Bits (2024): malicious participant in naive/dealer DKG can silently
//! raise the threshold. This path is for local visualization only.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;

use crate::application::DkgPort;
use crate::domain::DomainError;

/// Printed once when dealer DKG runs.
pub fn dealer_fatal_banner() {
    eprintln!(
        "================================================================================\n\
         FATAL RISK BANNER — dealer DKG enabled (feature=dealer_lab)\n\
         Trail of Bits 2024: a malicious participant can silently increase the threshold\n\
         in dealer / naive Pedersen-style DKG. This binary path is LAB VISUALIZE ONLY.\n\
         Production Gate requires distributed multi-round DKG without a dealer.\n\
         MODE=lab-visualize — NOT production-ready custody.\n\
         ================================================================================"
    );
}

pub struct FrostDealerBundle {
    pub shares: BTreeMap<Identifier, SecretShare>,
    pub pubkey_package: PublicKeyPackage,
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub max_signers: u16,
    pub min_signers: u16,
}

pub struct DealerLabAdapter;

impl DealerLabAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Trusted dealer keygen (single-process). Emits FATAL banner.
    pub fn generate(max_signers: u16, min_signers: u16) -> Result<FrostDealerBundle, DomainError> {
        dealer_fatal_banner();
        let mut rng = OsRng;
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(max_signers, min_signers, frost::keys::IdentifierList::Default, &mut rng)
                .map_err(|e| DomainError::ThresholdError(format!("frost dealer: {e}")))?;

        let mut key_packages = BTreeMap::new();
        for (identifier, secret_share) in &shares {
            let kp = KeyPackage::try_from(secret_share.clone())
                .map_err(|e| DomainError::ThresholdError(format!("key package: {e}")))?;
            key_packages.insert(*identifier, kp);
        }

        Ok(FrostDealerBundle { shares, pubkey_package, key_packages, max_signers, min_signers })
    }
}

impl Default for DealerLabAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DkgPort for DealerLabAdapter {
    fn mode_name(&self) -> &'static str {
        "dealer_lab"
    }

    fn is_dealer(&self) -> bool {
        true
    }
}
