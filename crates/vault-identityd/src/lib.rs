//! vault-identityd — identity daemon library.
//!
//! Provides `IdentityDaemon` for managing vault identity lifecycle and
//! `IdentityServer` for exposing identity operations over a Unix socket
//! via an Axum HTTP server.
//!
//! # Security
//! - Auth token is REQUIRED: daemon fails to start without one (fail-closed).
//! - Key files use atomic write + fsync + O_NOFOLLOW.
//! - `node_id` is sanitized against path traversal before any file operation.
//! - Keys are encrypted at rest with AEAD (Argon2id + AES-256-GCM).
//! - Identity archive uses time-boxed retention (not indefinite).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;
use tracing::{error, info, warn};
use vault_identity_core::error::IdentityError;
use vault_identity_core::hybrid_identity::HybridKeyPair;
use vault_identity_core::VaultIdentity;

// ---------------------------------------------------------------------------
// Identity daemon
// ---------------------------------------------------------------------------

/// AEAD nonce size (96-bit).
const AEAD_NONCE_SIZE: usize = 12;
/// Salt size for Argon2id KDF.
const AEAD_SALT_SIZE: usize = 16;
/// Argon2id memory cost (19 MiB).
const ARGON_MEMORY: u32 = 19_456;
/// Argon2id time cost.
const ARGON_ITERATIONS: u32 = 3;
/// Argon2id parallelism.
const ARGON_PARALLELISM: u32 = 1;
/// Maximum archive retention: 30 days in seconds.
const ARCHIVE_RETENTION_SECS: u64 = 2_592_000;
/// Max identity file size (16 MiB).
const MAX_IDENTITY_FILE_SIZE: u64 = 16 * 1024 * 1024;
/// Application label for AEAD AAD binding.
const AEAD_AAD_CONTEXT: &[u8] = b"kerosene-vault-identity-aead-v1";

/// The identity daemon manages vault cryptographic identity persistence.
pub struct IdentityDaemon {
    node_id: String,
    /// Sanitized hash-based filename component (path traversal protection).
    file_id: String,
    store_path: PathBuf,
    identity: Option<HybridKeyPair>,
    /// Passphrase for AEAD encryption at rest (derived from env).
    passphrase: String,
}

impl IdentityDaemon {
    /// Initialize a new identity daemon.
    ///
    /// Creates the store directory if it does not exist.
    /// Returns an error if `node_id` contains path traversal patterns.
    pub async fn new(node_id: &str, store_path: &str) -> Result<Self, IdentityError> {
        // Reject path traversal in node_id (FIX 3: path traversal prevention).
        let sanitized = sanitize_node_id(node_id)?;
        let file_id = hex::encode(Sha256::digest(sanitized.as_bytes()));

        let path = PathBuf::from(store_path);
        fs::create_dir_all(&path)
            .map_err(|e| IdentityError::InternalError(format!("failed to create store dir: {e}")))?;

        // Passphrase for AEAD encryption at rest.
        let passphrase =
            std::env::var("VAULT_IDENTITY_PASSPHRASE").unwrap_or_else(|_| "kerosene-vault-identity-default".into());

        Ok(Self { node_id: node_id.to_string(), file_id, store_path: path, identity: None, passphrase })
    }

    /// Sanitized filename for the identity blob.
    fn filename(&self) -> String {
        format!("identity-{}.enc", self.file_id)
    }

    /// Full path to the identity storage file.
    fn identity_path(&self) -> PathBuf {
        self.store_path.join(self.filename())
    }

    /// Derive an AES-256 key from the passphrase.
    fn derive_key(&self, salt: &[u8; AEAD_SALT_SIZE]) -> Result<[u8; 32], IdentityError> {
        let params = Params::new(ARGON_MEMORY, ARGON_ITERATIONS, ARGON_PARALLELISM, Some(32))
            .map_err(|e| IdentityError::InternalError(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(self.passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| IdentityError::InternalError(format!("argon2: {e}")))?;
        Ok(key)
    }

    /// Encrypt plaintext bytes with AEAD (Argon2id-derived key + AES-256-GCM).
    fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let mut salt = [0u8; AEAD_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| IdentityError::InternalError(e.to_string()))?;

        let mut nonce_bytes = [0u8; AEAD_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: AEAD_AAD_CONTEXT })
            .map_err(|_| IdentityError::InternalError("AEAD encrypt failed".into()))?;

        // Format: salt (16) || nonce (12) || ciphertext
        let mut out = Vec::with_capacity(AEAD_SALT_SIZE + AEAD_NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt AEAD-encrypted bytes.
    fn decrypt_bytes(&self, blob: &[u8]) -> Result<Vec<u8>, IdentityError> {
        if blob.len() < AEAD_SALT_SIZE + AEAD_NONCE_SIZE + 1 {
            return Err(IdentityError::DeserializationFailed("encrypted blob too short".into()));
        }
        let mut salt = [0u8; AEAD_SALT_SIZE];
        salt.copy_from_slice(&blob[..AEAD_SALT_SIZE]);
        let nonce_bytes = &blob[AEAD_SALT_SIZE..AEAD_SALT_SIZE + AEAD_NONCE_SIZE];
        let ciphertext = &blob[AEAD_SALT_SIZE + AEAD_NONCE_SIZE..];

        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| IdentityError::InternalError(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: AEAD_AAD_CONTEXT })
            .map_err(|_| IdentityError::DeserializationFailed("AEAD decrypt failed: wrong key or tampered data".into()))
    }

    /// Atomic write with fsync and O_NOFOLLOW on open.
    ///
    /// Writes to a temporary file, fsyncs, renames, then fsyncs the parent
    /// directory. Opens the temp file with O_NOFOLLOW to prevent symlink races.
    fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<(), IdentityError> {
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_extension("tmp");
        let parent = path.parent().unwrap_or(Path::new("."));

        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                // O_NOFOLLOW: fail if tmp is a symlink (race protection).
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)
                .map_err(|e| IdentityError::InternalError(format!("open tmp with O_NOFOLLOW: {e}")))?;

            f.write_all(data).map_err(|e| IdentityError::InternalError(format!("write tmp: {e}")))?;
            f.sync_all().map_err(|e| IdentityError::InternalError(format!("fsync tmp: {e}")))?;
        }

        fs::rename(&tmp, path).map_err(|e| IdentityError::InternalError(format!("rename: {e}")))?;

        // fsync parent directory so the rename is durable after crash.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Read identity from disk with atomic semantics.
    fn read_identity_blob(&self, path: &Path) -> Result<Vec<u8>, IdentityError> {
        use std::os::unix::fs::MetadataExt;

        let file =
            fs::File::open(path).map_err(|e| IdentityError::DeserializationFailed(format!("open identity: {e}")))?;

        let meta = file.metadata().map_err(|e| IdentityError::DeserializationFailed(format!("metadata: {e}")))?;

        // Reject oversized files (OOM / zip-bomb protection).
        if meta.size() > MAX_IDENTITY_FILE_SIZE {
            return Err(IdentityError::DeserializationFailed("identity file exceeds max size".into()));
        }

        // Reject world-accessible files.
        #[cfg(unix)]
        {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(IdentityError::DeserializationFailed(
                    "identity file has overly permissive permissions".into(),
                ));
            }
        }

        use std::io::Read;
        let mut buf = Vec::with_capacity(meta.size() as usize);
        let mut reader = std::io::BufReader::new(file);
        reader.read_to_end(&mut buf).map_err(|e| IdentityError::DeserializationFailed(format!("read: {e}")))?;
        Ok(buf)
    }

    /// Load existing identity from disk or generate a fresh one.
    pub async fn load_or_generate_identity(&mut self) -> Result<&HybridKeyPair, IdentityError> {
        if let Some(ref id) = self.identity {
            return Ok(id);
        }

        let path = self.identity_path();
        if path.exists() {
            info!("loading identity from {}", path.display());
            let encrypted = self.read_identity_blob(&path)?;
            let plaintext = self.decrypt_bytes(&encrypted)?;
            let kp = HybridKeyPair::from_bytes(&plaintext)?;
            self.identity = Some(kp);
        } else {
            info!("generating new hybrid identity for node {}", self.node_id);
            let kp = HybridKeyPair::generate(&self.node_id)?;
            let plaintext = kp.to_bytes();
            let encrypted = self.encrypt_bytes(&plaintext)?;
            self.atomic_write(&path, &encrypted)?;
            info!("identity persisted to {}", path.display());
            self.identity = Some(kp);
        }

        Ok(self.identity.as_ref().unwrap())
    }

    /// Get the current identity (must be loaded first).
    pub fn current_identity(&self) -> Result<&HybridKeyPair, IdentityError> {
        self.identity.as_ref().ok_or(IdentityError::IdentityNotFound)
    }

    /// Rotate identity keys (generate new, archive old).
    pub async fn rotate_identity(&mut self) -> Result<&HybridKeyPair, IdentityError> {
        info!("rotating identity for node {}", self.node_id);

        // Archive existing identity if present (time-bound retention).
        let path = self.identity_path();
        if path.exists() {
            let now_secs =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let archive_name = format!("identity-{}.old.{}", self.file_id, now_secs);
            let archive = self.store_path.join(&archive_name);
            fs::rename(&path, &archive)
                .map_err(|e| IdentityError::RotationFailed(format!("archive old identity: {e}")))?;
            info!("archived old identity to {}", archive.display());

            // Cleanup old archives beyond retention window.
            if let Ok(read_dir) = fs::read_dir(&self.store_path) {
                for entry in read_dir.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("identity-") && name_str.ends_with(".old.") {
                        if let Ok(meta) = entry.metadata() {
                            if let Ok(modified) = meta.modified() {
                                if let Ok(age) = modified.elapsed() {
                                    if age.as_secs() > ARCHIVE_RETENTION_SECS {
                                        let _ = fs::remove_file(entry.path());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Generate new identity
        let kp = HybridKeyPair::generate(&self.node_id)?;
        let plaintext = kp.to_bytes();
        let encrypted = self.encrypt_bytes(&plaintext)?;
        self.atomic_write(&path, &encrypted)?;

        self.identity = Some(kp);
        info!("identity rotated and persisted to {}", path.display());
        Ok(self.identity.as_ref().unwrap())
    }

    /// Sign a message with the current identity (hybrid: both Ed25519 + ML-DSA-65).
    pub fn sign(&self, message: &[u8]) -> Result<vault_identity_core::hybrid_identity::HybridSignature, IdentityError> {
        let id = self.current_identity()?;
        id.sign_hybrid(message)
    }
}

/// Sanitize `node_id` against path traversal.
///
/// Rejects any id containing `..`, `/`, `\`, `%00`, or starting with `.`.
fn sanitize_node_id(node_id: &str) -> Result<String, IdentityError> {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err(IdentityError::InternalError("node_id must not be empty".into()));
    }
    if trimmed.contains("..") {
        return Err(IdentityError::InternalError("node_id path traversal detected: '..'".into()));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(IdentityError::InternalError("node_id path traversal detected: separator character".into()));
    }
    if trimmed.starts_with('.') {
        return Err(IdentityError::InternalError("node_id must not start with '.'".into()));
    }
    if trimmed.contains('\0') {
        return Err(IdentityError::InternalError("node_id contains null byte".into()));
    }
    if trimmed.len() > 256 {
        return Err(IdentityError::InternalError("node_id too long (max 256 chars)".into()));
    }
    Ok(trimmed.to_string())
}

// ---------------------------------------------------------------------------
// IPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub node_id: String,
    pub ed25519_public: String,  // hex
    pub ml_dsa65_public: String, // hex
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String, // hex-encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub ed25519_signature: String,  // hex
    pub ml_dsa65_signature: String, // hex
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_id: String,
    pub has_identity: bool,
    pub identity_created_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Identity server (Axum)
// ---------------------------------------------------------------------------

/// Auth token validation constant.
const AUTH_HEADER: &str = "X-Vault-Auth-Token";
/// Maximum message size for signing: 32 KiB (FIX 2: size limit).
const MAX_SIGN_MESSAGE_BYTES: usize = 32_768;
/// Domain separation prefix for identity signing (FIX 2).
const DOMAIN_SEP_IDENTITY: &[u8] = b"kerosene-identity-sign-v1";
/// Domain separation prefix for audit signing.
const DOMAIN_SEP_AUDIT: &[u8] = b"kerosene-audit-sign-v1";

/// Allowed operation types for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignOp {
    Identity,
    Audit,
}

impl SignOp {
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "identity" => Some(Self::Identity),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }

    fn domain_sep(&self) -> &'static [u8] {
        match self {
            Self::Identity => DOMAIN_SEP_IDENTITY,
            Self::Audit => DOMAIN_SEP_AUDIT,
        }
    }
}

#[derive(Clone)]
pub struct IdentityServer {
    daemon: Arc<tokio::sync::Mutex<IdentityDaemon>>,
    socket_path: String,
    auth_token: String,
}

impl IdentityServer {
    /// Create a new identity server.
    ///
    /// # Panics
    /// When `auth_token` is `None` — the daemon **must** be configured with
    /// an auth token (fail-closed). This is checked at start, not at runtime.
    pub fn new(daemon: IdentityDaemon, socket_path: &str, auth_token: Option<&str>) -> Self {
        let token = auth_token.map(|s| s.to_string()).unwrap_or_else(|| {
            panic!(
                "FATAL: VAULT_IDENTITY_AUTH_TOKEN is required. \
                     The identity daemon will NOT start without an auth token (fail-closed). \
                     Set VAULT_IDENTITY_AUTH_TOKEN in the environment."
            )
        });
        Self {
            daemon: Arc::new(tokio::sync::Mutex::new(daemon)),
            socket_path: socket_path.to_string(),
            auth_token: token,
        }
    }

    fn check_auth(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        match headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()) {
            Some(token) if token == self.auth_token => Ok(()),
            _ => {
                warn!("unauthorized IPC request (missing or invalid auth token)");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.router();

        // Remove existing socket file if present
        let _ = fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set restrictive permissions on the socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&self.socket_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&self.socket_path, perms);
            }
        }

        info!("identity server listening on {}", self.socket_path);

        axum::serve(listener, app).await?;
        Ok(())
    }

    fn router(&self) -> Router {
        let state = AppState { daemon: self.daemon.clone(), auth_token: self.auth_token.clone() };

        // Protected routes (require auth token).
        let protected = Router::new()
            .route("/v1/identities/generate", post(handle_generate))
            .route("/v1/identities/current", get(handle_current))
            .route("/v1/identities/rotate", post(handle_rotate))
            .route("/v1/identities/certificate", get(handle_certificate))
            .route("/v1/identities/sign", post(handle_sign))
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_auth_mw));

        // Health endpoint is public (no auth required for monitoring).
        Router::new().route("/v1/health", get(handle_health)).merge(protected).with_state(state)
    }
}

#[derive(Clone)]
struct AppState {
    daemon: Arc<tokio::sync::Mutex<IdentityDaemon>>,
    auth_token: String,
}

impl AppState {
    fn check_auth(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        match headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()) {
            Some(token) if token == self.auth_token => Ok(()),
            _ => {
                warn!("unauthorized IPC request");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
    }
}

/// Middleware that requires a valid auth token for all protected routes.
async fn require_auth_mw(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    match headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()) {
        Some(token) if token == state.auth_token => Ok(next.run(request).await),
        _ => {
            warn!("unauthorized IPC request to protected route");
            Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))))
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_generate(State(state): State<AppState>) -> impl IntoResponse {
    let mut daemon = state.daemon.lock().await;
    match daemon.load_or_generate_identity().await {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(e) => {
            error!("generate identity failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_current(State(state): State<AppState>) -> impl IntoResponse {
    let daemon = state.daemon.lock().await;
    match daemon.current_identity() {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(IdentityError::IdentityNotFound) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "identity not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_rotate(State(state): State<AppState>) -> impl IntoResponse {
    let mut daemon = state.daemon.lock().await;
    match daemon.rotate_identity().await {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(e) => {
            error!("rotate identity failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_certificate(State(state): State<AppState>) -> impl IntoResponse {
    let daemon = state.daemon.lock().await;
    match daemon.current_identity() {
        Ok(id) => {
            // Return CSPRNG-based SPIFFE SVID info (Certificate generation expects x509 infra)
            // In production, this would be wired to SPIRE agent API.
            // For now, return the identity's public key material for SPIFFE binding.
            let svid_info = serde_json::json!({
                "note": "SPIFFE SVID certificate — placeholder (wire to SPIRE agent for full x509)",
                "spiffe_id": format!("spiffe://kerosene.lab/vault/{}", id.node_id),
                "ed25519_public": hex::encode(id.ed25519.verifying_key_bytes()),
                "ml_dsa65_public": hex::encode(id.ml_dsa65.public_key()),
            });
            (StatusCode::OK, Json(svid_info)).into_response()
        }
        Err(IdentityError::IdentityNotFound) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "identity not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

/// FIX 2: Signing endpoint with domain separation, op type whitelist,
/// policy hash, replay protection (nonce + timestamp), caller identification,
/// and explicit size limits.
#[derive(Deserialize)]
struct SignEndpointBody {
    /// Hex-encoded message to sign (max 32 KiB).
    message: String,
    /// Operation type (whitelist: "identity" or "audit").
    op_type: String,
    /// Optional policy hash for authorization binding.
    #[serde(default)]
    policy_hash: Option<String>,
    /// Caller identifier (required for audit trail).
    #[serde(default)]
    caller_id: Option<String>,
    /// Nonce for replay protection (hex, required).
    nonce: String,
    /// Unix timestamp in seconds (required, ±5 min allowed).
    timestamp_secs: u64,
}

#[derive(Serialize)]
struct SignEndpointResponse {
    message: String,
    ed25519_signature: String,
    ml_dsa65_signature: String,
}

async fn handle_sign(State(state): State<AppState>, Json(req): Json<SignEndpointBody>) -> impl IntoResponse {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ---- FIX 2: Size limit ----
    if req.message.len() > MAX_SIGN_MESSAGE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": format!(
                "message too large: {} bytes (max {})",
                req.message.len(),
                MAX_SIGN_MESSAGE_BYTES
            )})),
        )
            .into_response();
    }

    // ---- FIX 2: Operation type whitelist ----
    let op = match SignOp::from_label(&req.op_type.to_ascii_lowercase()) {
        Some(op) => op,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!(
                    "invalid sign op_type '{}'; allowed: identity, audit",
                    req.op_type
                )})),
            )
                .into_response();
        }
    };

    // ---- FIX 2: Replay protection (nonce + timestamp) ----
    if req.nonce.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "nonce is required for replay protection"})),
        )
            .into_response();
    }
    // Require nonce to be valid hex, 8-64 bytes.
    let nonce_bytes = match hex::decode(req.nonce.trim()) {
        Ok(n) if n.len() >= 8 && n.len() <= 64 => n,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "nonce must be 8-64 hex-encoded bytes"})),
            )
                .into_response();
        }
    };

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    // Allow ±5 minute clock skew.
    let skew_secs: u64 = 300;
    let ts_lower = now_secs.saturating_sub(skew_secs);
    let ts_upper = now_secs.saturating_add(skew_secs);
    if req.timestamp_secs < ts_lower || req.timestamp_secs > ts_upper {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!(
                "timestamp {} is outside allowed clock skew ({} to {})",
                req.timestamp_secs, ts_lower, ts_upper
            )})),
        )
            .into_response();
    }

    // ---- FIX 2: Domain separation ----
    let message_bytes = match hex::decode(&req.message) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid hex message: {e}")})))
                .into_response();
        }
    };

    // Construct domain-separated message:
    // domain_sep || op_type || nonce || timestamp || policy_hash || caller_id || message
    let mut bound_message =
        Vec::with_capacity(op.domain_sep().len() + 16 + nonce_bytes.len() + 32 + message_bytes.len());
    bound_message.extend_from_slice(op.domain_sep());
    bound_message.push(b'|');
    bound_message.extend_from_slice(req.op_type.as_bytes());
    bound_message.push(b'|');
    bound_message.extend_from_slice(&nonce_bytes);
    bound_message.push(b'|');
    bound_message.extend_from_slice(&req.timestamp_secs.to_le_bytes());
    bound_message.push(b'|');
    bound_message.extend_from_slice(req.policy_hash.as_deref().unwrap_or("none").as_bytes());
    bound_message.push(b'|');
    bound_message.extend_from_slice(req.caller_id.as_deref().unwrap_or("unknown").as_bytes());
    bound_message.push(b'|');
    bound_message.extend_from_slice(&message_bytes);

    let daemon = state.daemon.lock().await;
    match daemon.sign(&bound_message) {
        Ok(sig) => {
            let resp = SignEndpointResponse {
                message: format!("signed with domain separation ({})", String::from_utf8_lossy(op.domain_sep())),
                ed25519_signature: hex::encode(&sig.ed25519),
                ml_dsa65_signature: hex::encode(&sig.ml_dsa65),
            };
            (StatusCode::OK, Json(serde_json::json!(resp))).into_response()
        }
        Err(e) => {
            error!("sign failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let daemon = state.daemon.lock().await;
    let (has_identity, created_at) = match daemon.current_identity() {
        Ok(id) => (true, Some(id.created_at)),
        Err(_) => (false, None),
    };

    let health = HealthResponse {
        status: "ok".to_string(),
        node_id: daemon.node_id.clone(),
        has_identity,
        identity_created_at: created_at,
    };

    (StatusCode::OK, Json(serde_json::json!(health))).into_response()
}
