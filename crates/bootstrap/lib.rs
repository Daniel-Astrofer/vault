//! Process bootstrap for the sole supported production runtime.

pub use vault_adapters as adapters;
pub use vault_application as application;
pub use vault_domain as domain;

mod config;
mod runtime;
mod security {
    mod production_gate;
}

pub use config::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig};
pub use runtime::VaultRuntime;
