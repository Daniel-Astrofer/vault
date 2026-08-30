//! vault-signer — FROST signing daemon.
//!
//! A minimal Unix socket-based daemon for FROST threshold signing operations.
//! Has NO network dependencies — communicates only via Unix domain socket IPC
//! with vault-identityd and other local daemons.
//!
//! # Security
//! - No TCP listener or network I/O
//! - The Unix socket is created with owner-only permissions
//! - Existing regular files and symlinks are never replaced by the socket
//! - Session IDs are correlation values, not authentication credentials
//! - The public group package is the only material persisted by this daemon
//! - Real FROST signature aggregation (no placeholder responses)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use frost_secp256k1::round1::SigningCommitments;
use frost_secp256k1::round2::SignatureShare;
use frost_secp256k1::Identifier;
use vault_signer::ipc::{SignerIpc, SignerRequest, SignerResponse};
use vault_signer::session::SigningSessionManager;
use vault_signer::signer::{FrostSigner, SignerError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = args.get(1).cloned().unwrap_or_else(|| "/run/kerosene/signer.sock".to_string());

    let store_path = args.get(2).cloned().unwrap_or_else(|| "/var/lib/kerosene/signer".to_string());

    eprintln!("vault-signer starting");
    eprintln!("  socket: {socket_path}");
    eprintln!("  store:  {store_path}");

    // Ensure store directory exists
    let store = PathBuf::from(&store_path);
    std::fs::create_dir_all(&store).expect("failed to create store directory");

    // Initialize session manager and key state
    let session_manager = std::sync::Mutex::new(SigningSessionManager::new(64));

    // Key store for FROST key packages (pubkey package needed for aggregation)
    let key_store = {
        let mut ks = KeyStore::new(&store);
        let _ = ks.load_from_disk();
        std::sync::Mutex::new(ks)
    };

    // IPC handler
    let handler =
        move |request: SignerRequest| -> SignerResponse { handle_request(request, &session_manager, &key_store) };

    let ipc = SignerIpc::new(&socket_path);
    if let Err(e) = ipc.serve_blocking(handler) {
        eprintln!("vault-signer error: {e}");
        std::process::exit(1);
    }
}

/// In-memory + disk key store for FROST key packages.
struct KeyStore {
    path: PathBuf,
    /// Public key package needed for signature aggregation.
    pubkey_package: Option<frost_secp256k1::keys::PublicKeyPackage>,
}

impl KeyStore {
    fn new(path: &PathBuf) -> Self {
        Self { path: path.clone(), pubkey_package: None }
    }

    fn load_from_disk(&mut self) -> Result<(), SignerError> {
        let pk_path = self.path.join("pubkey_package.json");
        if pk_path.exists() {
            let data =
                std::fs::read_to_string(&pk_path).map_err(|e| SignerError::Internal(format!("read pubkey: {e}")))?;
            let pk: frost_secp256k1::keys::PublicKeyPackage =
                serde_json::from_str(&data).map_err(|e| SignerError::Internal(format!("deserialize pubkey: {e}")))?;
            self.pubkey_package = Some(pk);
            eprintln!("  loaded pubkey package from disk");
        } else {
            eprintln!("  no pubkey package on disk (needs InstallKeyPackages)");
        }
        Ok(())
    }

    fn save_to_disk(&self) -> Result<(), SignerError> {
        if let Some(ref pk) = self.pubkey_package {
            let data = serde_json::to_string_pretty(pk)
                .map_err(|e| SignerError::Internal(format!("serialize pubkey: {e}")))?;
            let pk_path = self.path.join("pubkey_package.json");
            std::fs::write(&pk_path, &data).map_err(|e| SignerError::Internal(format!("write pubkey: {e}")))?;
        }
        Ok(())
    }
}

fn handle_request(
    request: SignerRequest,
    session_manager: &Mutex<SigningSessionManager>,
    key_store: &Mutex<KeyStore>,
) -> SignerResponse {
    match request {
        SignerRequest::Health => {
            let sessions = session_manager.lock().unwrap().active_count();
            SignerResponse::Health { status: "ok".into(), active_sessions: sessions }
        }
        SignerRequest::InstallKeyPackages { pubkey_package } => {
            // Deserialize the public key package
            let pk: frost_secp256k1::keys::PublicKeyPackage = match serde_json::from_value(pubkey_package) {
                Ok(pk) => pk,
                Err(e) => return SignerResponse::Error { message: format!("invalid pubkey package: {e}") },
            };

            let mut ks = key_store.lock().unwrap();
            ks.pubkey_package = Some(pk);
            if let Err(e) = ks.save_to_disk() {
                eprintln!("warning: failed to persist pubkey package: {e}");
            }
            eprintln!("  key packages installed successfully");

            SignerResponse::KeyPackagesInstalled
        }
        SignerRequest::CreateSession { message, participants, min_signers } => {
            let msg_bytes = match hex::decode(&message) {
                Ok(m) => m,
                Err(e) => return SignerResponse::Error { message: format!("invalid hex: {e}") },
            };

            let identifiers: Result<Vec<_>, _> = participants
                .iter()
                .map(|b| {
                    let raw = match b.as_slice() {
                        [value] => u16::from(*value),
                        [high, low] => u16::from_be_bytes([*high, *low]),
                        _ => return Err("identifier must contain one or two bytes".to_string()),
                    };
                    Identifier::try_from(raw).map_err(|e| e.to_string())
                })
                .collect();

            let identifiers = match identifiers {
                Ok(v) => v,
                Err(e) => return SignerResponse::Error { message: format!("invalid identifier: {e}") },
            };

            let mut mgr = session_manager.lock().unwrap();
            match mgr.create_session(msg_bytes, identifiers, min_signers as usize) {
                Ok(session_id) => SignerResponse::SessionCreated { session_id: session_id.0 },
                Err(e) => SignerResponse::Error { message: e.to_string() },
            }
        }
        SignerRequest::SubmitCommitments { session_id, commitments } => {
            let mut mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session_mut(&vault_signer::session::SessionId(session_id.clone())) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            // Deserialize commitments from JSON value.
            // Expected format: JSON object mapping identifier (as string) to SigningCommitments.
            // Example: {"1": {"hiding": [...], "binding": [...]}, "2": {...}}
            let parsed: BTreeMap<u16, SigningCommitments> = match serde_json::from_value(commitments) {
                Ok(map) => map,
                Err(e) => return SignerResponse::Error { message: format!("invalid commitments format: {e}") },
            };

            if parsed.is_empty() {
                return SignerResponse::Error { message: "no commitments provided".into() };
            }

            for (id_val, comm) in &parsed {
                let identifier = match Identifier::try_from(*id_val) {
                    Ok(id) => id,
                    Err(e) => return SignerResponse::Error { message: format!("invalid identifier {id_val}: {e}") },
                };
                if let Err(e) = session.add_commitments(identifier, comm.clone()) {
                    return SignerResponse::Error { message: format!("add commitment: {e}") };
                }
            }

            SignerResponse::CommitmentsAccepted
        }
        SignerRequest::SubmitSignatureShare { session_id, share } => {
            let mut mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session_mut(&vault_signer::session::SessionId(session_id.clone())) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            // Deserialize share from JSON value.
            // Expected format: {"identifier": <u16>, "share": <SignatureShare>}
            #[derive(serde::Deserialize)]
            struct SharePayload {
                identifier: u16,
                share: SignatureShare,
            }

            let parsed: SharePayload = match serde_json::from_value(share) {
                Ok(p) => p,
                Err(e) => return SignerResponse::Error { message: format!("invalid share format: {e}") },
            };

            let identifier = match Identifier::try_from(parsed.identifier) {
                Ok(id) => id,
                Err(e) => {
                    return SignerResponse::Error { message: format!("invalid identifier {}: {e}", parsed.identifier) }
                }
            };

            if let Err(e) = session.add_signature_share(identifier, parsed.share) {
                return SignerResponse::Error { message: format!("add signature share: {e}") };
            }

            SignerResponse::SignatureShareAccepted
        }
        SignerRequest::GetSignature { session_id } => {
            let mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session(&vault_signer::session::SessionId(session_id)) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            if session.state != vault_signer::session::SessionState::Complete {
                return SignerResponse::Error { message: "session not yet complete".into() };
            }

            // Get the pubkey package from the key store
            let ks = key_store.lock().unwrap();
            let pubkey_package = match &ks.pubkey_package {
                Some(pk) => pk,
                None => return SignerResponse::Error { message: "key packages not installed".into() },
            };

            // Validate that we have enough commitments and shares
            if session.commitments.len() < session.min_signers {
                return SignerResponse::Error {
                    message: format!(
                        "insufficient commitments: have {}, need {}",
                        session.commitments.len(),
                        session.min_signers
                    ),
                };
            }
            if session.signature_shares.len() < session.min_signers {
                return SignerResponse::Error {
                    message: format!(
                        "insufficient signature shares: have {}, need {}",
                        session.signature_shares.len(),
                        session.min_signers
                    ),
                };
            }

            // Aggregate signature shares using real FROST aggregation
            match FrostSigner::aggregate(
                &session.commitments,
                &session.signature_shares,
                pubkey_package,
                &session.message,
            ) {
                Ok(signature) => {
                    // Serialize the signature to bytes
                    let sig_bytes = match serde_json::to_vec(&signature) {
                        Ok(b) => b,
                        Err(e) => {
                            return SignerResponse::Error { message: format!("signature serialization failed: {e}") }
                        }
                    };
                    SignerResponse::Signature { signature: sig_bytes }
                }
                Err(e) => SignerResponse::Error { message: format!("aggregation failed: {e}") },
            }
        }
        SignerRequest::SessionStatus { session_id } => {
            let mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session(&vault_signer::session::SessionId(session_id)) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            let state_str = match &session.state {
                vault_signer::session::SessionState::AwaitingCommitments => "awaiting_commitments",
                vault_signer::session::SessionState::AwaitingSignatureShares => "awaiting_signature_shares",
                vault_signer::session::SessionState::Complete => "complete",
                vault_signer::session::SessionState::Failed(_) => "failed",
            };

            SignerResponse::SessionStatus {
                state: state_str.into(),
                commitments_count: session.commitments.len(),
                shares_count: session.signature_shares.len(),
                min_signers: session.min_signers,
            }
        }
    }
}
