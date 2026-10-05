//! Unix socket IPC protocol for vault-signer.
//!
//! Implements a simple length-prefixed message protocol over Unix domain sockets
//! for communication with other daemons (particularly vault-identityd).
//! Messages are serialized as JSON with a 4-byte length prefix.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::signer::SignerError;

/// Maximum message size: 1 MB.
const MAX_MESSAGE_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// IPC message types
// ---------------------------------------------------------------------------

/// Request message from client to signer daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum SignerRequest {
    /// Create a new signing session.
    CreateSession {
        /// Message to be signed, encoded as hexadecimal.
        message: String,
        /// Participant identifiers encoded as byte vectors.
        participants: Vec<Vec<u8>>,
        /// Minimum number of participants required for the signing session.
        min_signers: u16,
    },
    /// Install key packages (must be sent before signing).
    InstallKeyPackages {
        /// Serialized `PublicKeyPackage` as a JSON value.
        pubkey_package: serde_json::Value,
    },
    /// Submit round 1 commitments.
    ///
    /// `commitments` is a JSON array of `[identifier, SigningCommitments]` pairs
    /// serialized via serde. The identifier is a u16 encoded as JSON number.
    SubmitCommitments {
        /// Session receiving these round-one commitments.
        session_id: String,
        /// Serialized array of `[identifier, SigningCommitments]` pairs.
        commitments: serde_json::Value,
    },
    /// Submit round 2 signature share.
    ///
    /// `share` is a JSON value representing a `(Identifier, SignatureShare)` pair
    /// serialized via serde.
    SubmitSignatureShare {
        /// Session receiving this round-two signature share.
        session_id: String,
        /// Serialized `(Identifier, SignatureShare)` pair.
        share: serde_json::Value,
    },
    /// Get the current aggregated signature.
    GetSignature {
        /// Session whose aggregated signature is requested.
        session_id: String,
    },
    /// Get session status.
    SessionStatus {
        /// Session whose current protocol state is requested.
        session_id: String,
    },
    /// Health check.
    Health,
}

/// Response message from signer daemon to client.
#[derive(Debug, Serialize, Deserialize)]
pub enum SignerResponse {
    /// Session created successfully.
    SessionCreated {
        /// Identifier assigned to the created session.
        session_id: String,
    },
    /// Commitments accepted.
    CommitmentsAccepted,
    /// Key packages installed successfully.
    KeyPackagesInstalled,
    /// Signature share accepted.
    SignatureShareAccepted,
    /// Aggregated signature ready.
    Signature {
        /// Encoded aggregate signature bytes.
        signature: Vec<u8>,
    },
    /// Session status.
    SessionStatus {
        /// Current signer-session state label.
        state: String,
        /// Number of participants whose commitments have been recorded.
        commitments_count: usize,
        /// Number of signature shares currently accepted.
        shares_count: usize,
        /// Minimum participant threshold configured for the session.
        min_signers: usize,
    },
    /// Health check response.
    Health {
        /// Signer daemon health label.
        status: String,
        /// Number of currently active signing sessions.
        active_sessions: usize,
    },
    /// Error response.
    Error {
        /// Human-readable description of the rejected or failed request.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Wire format: 4-byte big-endian length prefix + JSON body
// ---------------------------------------------------------------------------

/// Serialize a response and prefix its JSON body with a four-byte big-endian length.
fn encode_message(msg: &SignerResponse) -> Result<Vec<u8>, SignerError> {
    let json = serde_json::to_vec(msg).map_err(|e| SignerError::Internal(format!("serialization: {e}")))?;

    if json.len() > MAX_MESSAGE_SIZE {
        return Err(SignerError::Internal("message too large".into()));
    }

    let len = json.len() as u32;
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Serialize a request and prefix its JSON body with a four-byte big-endian length.
fn encode_request(msg: &SignerRequest) -> Result<Vec<u8>, SignerError> {
    let json = serde_json::to_vec(msg).map_err(|e| SignerError::Internal(format!("serialization: {e}")))?;
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(SignerError::Internal("request too large".into()));
    }
    let len = json.len() as u32;
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// IPC server
// ---------------------------------------------------------------------------

/// IPC server that listens on a Unix domain socket.
pub struct SignerIpc {
    /// Filesystem path bound as the Unix domain socket.
    socket_path: String,
}

impl SignerIpc {
    /// Create a new IPC server at the given socket path.
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }

    /// Start listening for connections (blocking).
    ///
    /// In production, this would be run in a dedicated thread/task.
    pub fn serve_blocking<F>(&self, handler: F) -> Result<(), SignerError>
    where
        F: Fn(SignerRequest) -> SignerResponse,
    {
        // Remove existing socket
        let _ = std::fs::remove_file(&self.socket_path);

        let listener =
            UnixListener::bind(&self.socket_path).map_err(|e| SignerError::Internal(format!("bind: {e}")))?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&self.socket_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&self.socket_path, perms);
            }
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let response = Self::handle_connection(stream, &handler);
                    if let Err(e) = response {
                        eprintln!("IPC handler error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("IPC accept error: {e}");
                }
            }
        }

        Ok(())
    }

    /// Read one length-prefixed request, invoke the handler, and write its response frame.
    fn handle_connection<F>(mut stream: UnixStream, handler: &F) -> Result<(), SignerError>
    where
        F: Fn(SignerRequest) -> SignerResponse,
    {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(|e| SignerError::Internal(format!("read length: {e}")))?;

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MESSAGE_SIZE || msg_len == 0 {
            let response = encode_message(&SignerResponse::Error { message: "invalid message length".into() })?;
            stream.write_all(&response).ok();
            return Err(SignerError::Internal("invalid message length".into()));
        }

        // Read message body
        let mut body = vec![0u8; msg_len];
        stream.read_exact(&mut body).map_err(|e| SignerError::Internal(format!("read body: {e}")))?;

        // Decode and handle
        let request: SignerRequest =
            serde_json::from_slice(&body).map_err(|e| SignerError::Internal(format!("deserialize: {e}")))?;

        let response = handler(request);
        let encoded = encode_message(&response)?;
        stream.write_all(&encoded).map_err(|e| SignerError::Internal(format!("write response: {e}")))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IPC client
// ---------------------------------------------------------------------------

/// IPC client for connecting to the signer daemon.
pub struct SignerClient {
    /// Filesystem path of the signer Unix domain socket.
    socket_path: String,
}

impl SignerClient {
    /// Create a new client connected to the given socket.
    pub fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }

    /// Send a request and receive the response.
    pub fn send_request(&self, request: &SignerRequest) -> Result<SignerResponse, SignerError> {
        let mut stream = UnixStream::connect(Path::new(&self.socket_path))
            .map_err(|e| SignerError::Internal(format!("connect: {e}")))?;

        let encoded = encode_request(request)?;
        stream.write_all(&encoded).map_err(|e| SignerError::Internal(format!("write: {e}")))?;

        // Read response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(|e| SignerError::Internal(format!("read response length: {e}")))?;

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MESSAGE_SIZE || msg_len == 0 {
            return Err(SignerError::Internal("invalid response length".into()));
        }

        let mut body = vec![0u8; msg_len];
        stream.read_exact(&mut body).map_err(|e| SignerError::Internal(format!("read response body: {e}")))?;

        serde_json::from_slice(&body).map_err(|e| SignerError::Internal(format!("deserialize response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn ipc_roundtrip_health_check() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("signer-ipc-test.sock");
        let socket_str = socket.to_str().unwrap().to_string();

        // Start server in a thread
        let server_socket = socket_str.clone();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let ipc = SignerIpc::new(&server_socket);
            let handler = |req: SignerRequest| -> SignerResponse {
                match req {
                    SignerRequest::Health => SignerResponse::Health { status: "ok".into(), active_sessions: 0 },
                    _ => SignerResponse::Error { message: "unexpected".into() },
                }
            };
            tx.send(()).unwrap();
            let _ = ipc.serve_blocking(handler);
        });

        // Wait for server to start
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // Client sends health check
        let client = SignerClient::new(&socket_str);
        let response = client.send_request(&SignerRequest::Health).unwrap();
        match response {
            SignerResponse::Health { status, active_sessions } => {
                assert_eq!(status, "ok");
                assert_eq!(active_sessions, 0);
            }
            _ => panic!("unexpected response"),
        }
    }
}
