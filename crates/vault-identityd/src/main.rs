//! vault-identityd — vault identity daemon entry point.
//!
//! Manages vault cryptographic identity including Ed25519 + ML-DSA-65 keypairs,
//! SPIFFE SVID issuance, and mTLS certificate lifecycle.
//!
//! # Usage
//!
//! ```text
//! vault-identityd serve
//! vault-identityd generate-identity --node-id <ID> --store-path <PATH>
//! vault-identityd rotate-identity --node-id <ID> --store-path <PATH>
//! vault-identityd status --socket <PATH>
//! ```

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use vault_identity_core::VaultIdentity;

use vault_identityd::{IdentityDaemon, IdentityServer};

/// Vault identity daemon — manages Ed25519 + ML-DSA-65 identity lifecycle.
#[derive(Parser, Debug)]
#[command(name = "vault-identityd", about, version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the identity daemon server.
    Serve {
        /// Path to the Unix domain socket for IPC.
        #[arg(long, env = "VAULT_IDENTITY_UNIX_SOCKET", default_value = "/run/kerosene/identityd.sock")]
        socket: String,

        /// Path to persistent key store directory.
        #[arg(long, env = "VAULT_IDENTITY_STORE_PATH", default_value = "/var/lib/kerosene/identity")]
        store_path: String,

        /// Internal auth token for IPC (shared secret between daemons).
        #[arg(long, env = "VAULT_IDENTITY_AUTH_TOKEN")]
        auth_token: Option<String>,

        /// Node identifier.
        #[arg(long, env = "VAULT_NODE_ID", default_value = "vault-local-1")]
        node_id: String,
    },
    /// Generate a new identity keypair and persist to disk.
    GenerateIdentity {
        /// Node identifier.
        #[arg(long, env = "VAULT_NODE_ID", default_value = "vault-local-1")]
        node_id: String,

        /// Path to persistent key store directory.
        #[arg(long, env = "VAULT_IDENTITY_STORE_PATH", default_value = "/var/lib/kerosene/identity")]
        store_path: String,
    },
    /// Rotate the identity keypair (generates new keys, keeps same node id).
    RotateIdentity {
        /// Node identifier.
        #[arg(long, env = "VAULT_NODE_ID", default_value = "vault-local-1")]
        node_id: String,

        /// Path to persistent key store directory.
        #[arg(long, env = "VAULT_IDENTITY_STORE_PATH", default_value = "/var/lib/kerosene/identity")]
        store_path: String,
    },
    /// Query daemon status via IPC.
    Status {
        /// Path to the Unix domain socket.
        #[arg(long, env = "VAULT_IDENTITY_UNIX_SOCKET", default_value = "/run/kerosene/identityd.sock")]
        socket: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing with env-filter (default: info)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Serve { socket, store_path, auth_token, node_id } => {
            let daemon =
                IdentityDaemon::new(&node_id, &store_path).await.expect("failed to initialize identity daemon");
            let server = IdentityServer::new(daemon, &socket, auth_token.as_deref());
            tracing::info!("starting vault-identityd on unix socket: {socket}");
            if let Err(e) = server.run().await {
                tracing::error!("identity daemon exited with error: {e}");
                std::process::exit(1);
            }
        }
        Command::GenerateIdentity { node_id, store_path } => {
            let mut daemon =
                IdentityDaemon::new(&node_id, &store_path).await.expect("failed to initialize identity daemon");
            match daemon.load_or_generate_identity().await {
                Ok(id) => {
                    println!("Identity generated for node: {}", id.node_id);
                    println!("Ed25519 public key: {}", hex::encode(id.ed25519.verifying_key_bytes()));
                    println!("ML-DSA-65 public key: {}", hex::encode(id.ml_dsa65.public_key()));
                }
                Err(e) => {
                    eprintln!("Failed to generate identity: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::RotateIdentity { node_id, store_path } => {
            let mut daemon =
                IdentityDaemon::new(&node_id, &store_path).await.expect("failed to initialize identity daemon");
            match daemon.rotate_identity().await {
                Ok(id) => {
                    println!("Identity rotated for node: {}", id.node_id);
                    println!("New Ed25519 public key: {}", hex::encode(id.ed25519.verifying_key_bytes()));
                    println!("New ML-DSA-65 public key: {}", hex::encode(id.ml_dsa65.public_key()));
                }
                Err(e) => {
                    eprintln!("Failed to rotate identity: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Status { socket } => {
            // Query the running daemon via HTTP GET on the Unix socket
            let client = reqwest::Client::builder().build().expect("failed to build HTTP client");

            let url = "http://localhost/v1/health";
            match client.get(url).send().await {
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    println!("Daemon status: {body}");
                }
                Err(e) => {
                    eprintln!("Failed to query daemon at {socket}: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
