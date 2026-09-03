//! Re-export `vault_core` for backward compatibility with existing tests
//! and the executable in `apps/kerosene-vault`.
//!
//! All implementation code now lives in `crates/vault-core/`.

pub use vault_core::*;
