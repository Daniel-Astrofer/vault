//! vault-signer — FROST signing daemon library.
//!
//! Provides a FROST (Flexible Round-Optimized Schnorr Threshold) signing
//! state machine with distributed key generation (DKG), key reshare,
//! and session management. Communicates via Unix socket IPC only — no
//! TCP or network dependencies.

mod protocol;
#[path = "session/mod.rs"]
mod session_state;
mod signing;
mod transport;

/// Compatibility module for the pre-organized DKG path.
pub mod dkg {
    pub use crate::protocol::dkg::*;
}

/// Compatibility module for the pre-organized IPC path.
pub mod ipc {
    pub use crate::transport::ipc::*;
}

/// Compatibility module for the pre-organized reshare path.
pub mod reshare {
    pub use crate::protocol::reshare::*;
}

/// Compatibility module for the pre-organized session path.
pub mod session {
    pub use crate::session_state::session::*;
}

/// Compatibility module for the pre-organized signing path.
pub mod signer {
    pub use crate::signing::signer::*;
}

pub use dkg::DistributedKeyGeneration;
pub use ipc::SignerIpc;
pub use reshare::KeyReshare;
pub use session::SigningSessionManager;
pub use signer::FrostSigner;
