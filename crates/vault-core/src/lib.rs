//! Kerosene vault mesh node — Core Library.
//!
//! Layering (Clean Architecture — see `VAULT_MESH_PLAN.md` §2.1):
//! - `domain` — pure types and rules (no I/O)
//! - `application` — use cases + ports (traits)
//! - `adapters` — Tor/TEE/store implementations (later); lab doubles here
//! - `bootstrap` — config, DI, process entry wiring

/// Deprecated compatibility facade for outer technology implementations.
pub mod adapters {
    pub use vault_adapters::*;
    pub use vault_api::{
        build_admin_router, build_router, spawn_admin_tcp, spawn_admin_unix_socket, validate_admin_request_path,
    };
}
/// Compatibility re-export for existing callers during the migration.
pub use vault_application as application;
pub use vault_bootstrap as bootstrap;
/// Compatibility re-export for existing callers during the migration.
pub use vault_domain as domain;
