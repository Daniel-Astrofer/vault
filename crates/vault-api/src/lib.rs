//! HTTP and local-admin translation layer.

#[cfg(all(feature = "production", feature = "dealer_lab"))]
compile_error!("production API must never compile dealer_lab support");

pub use vault_adapters as adapters;
pub use vault_application as application;
pub use vault_bootstrap as bootstrap;
pub use vault_domain as domain;

mod routes;
mod services;

pub use routes::{
    build_admin_router, build_router, spawn_admin_tcp, spawn_admin_unix_socket, validate_admin_request_path, AppState,
};
pub use services::{admin_error, resolve_request_id, AdminService};
