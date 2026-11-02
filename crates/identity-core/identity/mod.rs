//! Identity scheme implementations.
//!
//! The crate root keeps the public compatibility facade; implementations are
//! grouped here by cryptographic capability.

pub mod ed25519_identity;
pub mod hybrid_identity;
pub mod ml_dsa_identity;
