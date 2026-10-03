//! Thin binary wrapper — delegates all logic to `vault_core`.
//!
//! The full vault implementation now lives in `crates/vault-core/`.
//! This entry point calls `vault_core::bootstrap::VaultRuntime::build()`
//! and starts the Axum HTTP server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsAcceptor;
use vault_core::adapters::{build_mtls_server_config, build_router, PeerCertAcceptor};
use vault_core::bootstrap::{VaultConfig, VaultRuntime};
mod health_probe;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg.starts_with("--health-probe")) {
        let code = if args == ["--health-probe"] {
            match health_probe::run().await {
                Ok(()) => 0,
                Err(()) => { eprintln!("Vault authenticated local health probe failed"); 1 }
            }
        } else { 2 };
        std::process::exit(code);
    }
    let config = match VaultConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    let listen_addr = config.listen_addr.clone();
    let runtime = match VaultRuntime::build(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime error: {e}");
            std::process::exit(1);
        }
    };
    let runtime = Arc::new(runtime);

    let group = runtime.threshold.group();
    eprintln!(
        "kerosene-vault node={} listen={} tier={} tee_available={} attestation={} ceremony={} stub={} n={} t={} online={} timelock_scale={} hardened={} open_economy={} bitcoin={} auth={}",
        runtime.config.node_id,
        runtime.config.listen_addr,
        runtime.config.node_tier.as_str(),
        runtime.config.tee_available,
        runtime.config.attestation_mode.as_str(),
        runtime.config.ceremony_mode.as_str(),
        runtime.config.attestation_staging_stub,
        group.n,
        group.t,
        runtime.online.online_count(),
        runtime.config.effective_lab_timelock_scale(),
        runtime.config.hardened,
        runtime.config.open_economy,
        runtime.config.bitcoin_network.as_str(),
        runtime.config.auth_mode.as_str()
    );

    let app = build_router(runtime.clone());
    let (cert, key, ca) = match runtime.config.require_mtls_paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    let server_config = match build_mtls_server_config(Path::new(cert), Path::new(key), Path::new(ca)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mTLS config error: {e}");
            std::process::exit(1);
        }
    };
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let acceptor = PeerCertAcceptor::new(RustlsAcceptor::new(rustls_config));
    let addr: SocketAddr = match listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bind address error: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("tls=mtls (client certificate and SPIFFE route authorization required)");
    if let Err(e) = axum_server::bind(addr).acceptor(acceptor).serve(app.into_make_service()).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
