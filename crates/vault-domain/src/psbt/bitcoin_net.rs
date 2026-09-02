//! Settlement network labels and domain-level destination invariants.
//!
//! Parsing addresses and building scripts are adapter responsibilities.

use crate::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Testnet3,
}

impl BitcoinNetwork {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "testnet3" | "testnet" | "test" => Some(Self::Testnet3),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        "testnet3"
    }
}

/// Rejects empty destinations and explicit mainnet labels. The Bitcoin adapter
/// performs checksum validation before any on-chain operation.
pub fn validate_destination(network: BitcoinNetwork, destination: &str) -> Result<(), DomainError> {
    let destination = destination.trim();
    if destination.is_empty() {
        return Err(DomainError::InvalidIntent("empty destination".into()));
    }
    if network == BitcoinNetwork::Testnet3 && (destination.starts_with("bc1") || destination.starts_with("BC1")) {
        return Err(DomainError::BitcoinNetworkMismatch(
            "mainnet bc1 address rejected on BITCOIN_NETWORK=testnet3".into(),
        ));
    }
    Ok(())
}
