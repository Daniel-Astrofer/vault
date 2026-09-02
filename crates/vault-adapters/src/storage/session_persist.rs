//! Durable anti-nonce session ledger with quorum replication across vault peers.
//!
//! Design (Gate):
//! - Append-only local `session_id` log (fsync) survives restart.
//! - `claim_session` refuses if the id is already local **or** any peer reports
//!   `already_seen` (≥1 honest peer).
//! - Sign path also refuses until a 2/3 quorum of durable prepares succeed
//!   (self + peer HTTP ACKs). Fail-closed if quorum is unmet.
//! - Peer prepare uses HTTP + `X-Vault-Token` (lab) or no token header when mTLS
//!   auth is active (identity is the transport).

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::application::AntiNoncePort;
use crate::domain::{quorum_two_thirds, DomainError};
use crate::{build_mtls_rustls_client_config, PeerHttpSettings, TlsPeerVerifyPolicy};

/// Soft HTTP prepare TTL (High #8) — expires unless promoted by claim_session.
const PREPARE_TTL: Duration = Duration::from_secs(120);

pub struct PersistedAntiNonce {
    path: PathBuf,
    inner: Mutex<HashSet<String>>,
    soft: Mutex<HashMap<String, Instant>>,
}

impl PersistedAntiNonce {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DomainError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| DomainError::ThresholdError(format!("anti-nonce mkdir: {e}")))?;
        }
        let mut set = HashSet::new();
        if path.exists() {
            load_ids_into(&path, &mut set)?;
        }
        Ok(Self { path, inner: Mutex::new(set), soft: Mutex::new(HashMap::new()) })
    }

    fn append_id(&self, session_id: &str) -> Result<(), DomainError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce append: {e}")))?;
        writeln!(file, "{session_id}").map_err(|e| DomainError::ThresholdError(format!("anti-nonce write: {e}")))?;
        file.sync_all().map_err(|e| DomainError::ThresholdError(format!("anti-nonce sync: {e}")))?;
        Ok(())
    }

    fn sweep_soft(soft: &mut HashMap<String, Instant>) {
        let now = Instant::now();
        soft.retain(|_, exp| *exp > now);
    }

    /// Durable check-and-insert. Returns `true` if `session_id` was already present.
    pub fn prepare(&self, session_id: &str) -> Result<bool, DomainError> {
        let mut g = self.inner.lock().expect("anti-nonce");
        if g.contains(session_id) {
            return Ok(true);
        }
        self.append_id(session_id)?;
        g.insert(session_id.to_string());
        let mut soft = self.soft.lock().expect("anti-nonce soft");
        soft.remove(session_id);
        Ok(false)
    }

    /// Soft TTL reservation for HTTP prepare (anti-DoS). Returns `true` if blocked.
    pub fn prepare_soft(&self, session_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("anti-nonce");
        if g.contains(session_id) {
            return Ok(true);
        }
        drop(g);
        let mut soft = self.soft.lock().expect("anti-nonce soft");
        Self::sweep_soft(&mut soft);
        if soft.contains_key(session_id) {
            return Ok(true);
        }
        soft.insert(session_id.to_string(), Instant::now() + PREPARE_TTL);
        Ok(false)
    }
}

impl AntiNoncePort for PersistedAntiNonce {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError> {
        if self.prepare(session_id)? {
            return Err(DomainError::NonceReuse(format!("session_id already used: {session_id}")));
        }
        Ok(())
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("anti-nonce");
        if g.contains(session_id) {
            return Ok(true);
        }
        drop(g);
        let mut soft = self.soft.lock().expect("anti-nonce soft");
        Self::sweep_soft(&mut soft);
        Ok(soft.contains_key(session_id))
    }

    fn prepare_remote(&self, session_id: &str) -> Result<bool, DomainError> {
        self.prepare_soft(session_id)
    }

    fn prepare_remote_durable(&self, session_id: &str) -> Result<bool, DomainError> {
        self.prepare(session_id)
    }
}

/// Result of a peer durable prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareAck {
    pub already_seen: bool,
}

/// Transport used by [`QuorumAntiNonce`] to collect peer prepares.
pub trait AntiNonceQuorumTransport: Send + Sync {
    fn prepare_on_peers(&self, session_id: &str) -> Result<Vec<PrepareAck>, DomainError>;
}

/// HTTP peer prepare: POST `/v1/anti-nonce/prepare`.
pub struct HttpAntiNonceTransport {
    peer_prepare_urls: Vec<String>,
    auth_token: Option<String>,
    peer_http: PeerHttpSettings,
    /// When set, outbound prepare uses rustls mTLS (Tor onion / SPIFFE verify).
    tls: Option<rustls::ClientConfig>,
}

impl HttpAntiNonceTransport {
    pub fn new(peer_prepare_urls: Vec<String>, auth_token: Option<String>, timeout: Duration) -> Self {
        let mut peer_http = PeerHttpSettings::clearnet_defaults();
        peer_http.timeout = timeout;
        peer_http.connect_timeout = timeout;
        peer_http.max_retries = 1;
        Self::with_peer_http(peer_prepare_urls, auth_token, peer_http)
    }

    pub fn with_peer_http(
        peer_prepare_urls: Vec<String>,
        auth_token: Option<String>,
        peer_http: PeerHttpSettings,
    ) -> Self {
        Self { peer_prepare_urls, auth_token, peer_http, tls: None }
    }

    pub fn with_mtls(
        peer_prepare_urls: Vec<String>,
        peer_http: PeerHttpSettings,
        client_cert_path: &Path,
        client_key_path: &Path,
        ca_path: &Path,
        verify: &TlsPeerVerifyPolicy,
    ) -> Result<Self, DomainError> {
        let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
        Ok(Self { peer_prepare_urls, auth_token: None, peer_http, tls: Some(tls) })
    }

    fn build_blocking_client(&self) -> Result<reqwest::blocking::Client, DomainError> {
        let mut builder = self.peer_http.apply_blocking_builder(reqwest::blocking::Client::builder())?;
        if let Some(tls) = self.tls.clone() {
            builder = builder.use_preconfigured_tls(tls);
        }
        builder.build().map_err(|e| DomainError::ThresholdError(format!("anti-nonce http client: {e}")))
    }
}

impl AntiNonceQuorumTransport for HttpAntiNonceTransport {
    fn prepare_on_peers(&self, session_id: &str) -> Result<Vec<PrepareAck>, DomainError> {
        let mut out = Vec::with_capacity(self.peer_prepare_urls.len());
        if self.peer_prepare_urls.is_empty() {
            return Ok(out);
        }
        let client = self.build_blocking_client()?;
        let body = serde_json::json!({
            "session_id": session_id,
            "intent_id": session_id,
            "durable": true
        })
        .to_string();
        for url in &self.peer_prepare_urls {
            let attempts = self.peer_http.max_retries.max(1);
            let mut ack = None;
            for attempt in 0..attempts {
                let mut req = client.post(url).header("Content-Type", "application/json").body(body.clone());
                if let Some(token) = self.auth_token.as_deref() {
                    req = req.header("X-Vault-Token", token);
                }
                match req.send() {
                    Ok(resp) if resp.status().is_success() => {
                        let text = resp.text().unwrap_or_default();
                        ack = Some(PrepareAck { already_seen: parse_already_seen(&text)? });
                        break;
                    }
                    Ok(resp) => {
                        if !PeerHttpSettings::should_retry_status(resp.status()) || attempt + 1 >= attempts {
                            break;
                        }
                        std::thread::sleep(self.peer_http.backoff_delay(attempt));
                    }
                    Err(_) => {
                        if attempt + 1 >= attempts {
                            break; // unreachable peer — does not count toward quorum
                        }
                        std::thread::sleep(self.peer_http.backoff_delay(attempt));
                    }
                }
            }
            if let Some(a) = ack {
                out.push(a);
            }
        }
        Ok(out)
    }
}

fn parse_already_seen(body: &str) -> Result<bool, DomainError> {
    #[derive(serde::Deserialize)]
    struct PrepResp {
        already_seen: bool,
    }
    serde_json::from_str::<PrepResp>(body)
        .map(|r| r.already_seen)
        .map_err(|_| DomainError::ThresholdError("anti-nonce peer response missing already_seen (fail-closed)".into()))
}

/// In-memory multi-node transport for tests / simulation.
pub struct MemoryAntiNonceTransport {
    peers: Vec<Arc<PersistedAntiNonce>>,
}

impl MemoryAntiNonceTransport {
    pub fn new(peers: Vec<Arc<PersistedAntiNonce>>) -> Self {
        Self { peers }
    }
}

impl AntiNonceQuorumTransport for MemoryAntiNonceTransport {
    fn prepare_on_peers(&self, session_id: &str) -> Result<Vec<PrepareAck>, DomainError> {
        let mut out = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            out.push(PrepareAck { already_seen: peer.prepare(session_id)? });
        }
        Ok(out)
    }
}

/// Quorum-replicated anti-nonce: local append-only log + peer durable prepare ACKs.
///
/// Cluster size `n = 1 + peer_count` (configured peers). Quorum `t = ceil(2n/3)`.
/// Solo (no peers): `t = 1` (local durable claim only).
pub struct QuorumAntiNonce {
    local: Arc<PersistedAntiNonce>,
    transport: Arc<dyn AntiNonceQuorumTransport>,
    peer_count: usize,
    quorum_t: usize,
}

impl QuorumAntiNonce {
    pub fn open(
        local_path: impl Into<PathBuf>,
        transport: Arc<dyn AntiNonceQuorumTransport>,
        peer_count: usize,
    ) -> Result<Self, DomainError> {
        Self::from_local(Arc::new(PersistedAntiNonce::open(local_path)?), transport, peer_count)
    }

    pub fn from_local(
        local: Arc<PersistedAntiNonce>,
        transport: Arc<dyn AntiNonceQuorumTransport>,
        peer_count: usize,
    ) -> Result<Self, DomainError> {
        let n = peer_count.saturating_add(1).max(1);
        let quorum_t = if peer_count == 0 { 1 } else { quorum_two_thirds(n).max(1) };
        Ok(Self { local, transport, peer_count, quorum_t })
    }

    pub fn local_store(&self) -> Arc<PersistedAntiNonce> {
        self.local.clone()
    }

    pub fn quorum_t(&self) -> usize {
        self.quorum_t
    }

    pub fn peer_count(&self) -> usize {
        self.peer_count
    }
}

impl AntiNoncePort for QuorumAntiNonce {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError> {
        // 1) Local durable burn first — crash mid-flight never reuses this id here.
        if self.local.prepare(session_id)? {
            return Err(DomainError::NonceReuse(format!("session_id already used: {session_id}")));
        }

        // 2) Quorum prepare among peers (fail-closed).
        let acks = self.transport.prepare_on_peers(session_id)?;
        if acks.iter().any(|a| a.already_seen) {
            return Err(DomainError::NonceReuse(format!("session_id seen on ≥1 peer: {session_id}")));
        }

        let have = 1 + acks.len(); // self + successful durable peer prepares
        if have < self.quorum_t {
            return Err(DomainError::QuorumNotMet { have, need: self.quorum_t });
        }
        Ok(())
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        self.local.is_consumed(session_id)
    }

    fn prepare_remote(&self, session_id: &str) -> Result<bool, DomainError> {
        self.local.prepare_soft(session_id)
    }

    fn prepare_remote_durable(&self, session_id: &str) -> Result<bool, DomainError> {
        self.local.prepare(session_id)
    }
}

/// Arc wrapper so FROST orchestrator and runtime share one quorum ledger.
pub struct SharedAntiNonce(pub Arc<dyn AntiNoncePort>);

impl AntiNoncePort for SharedAntiNonce {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError> {
        self.0.claim_session(session_id)
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        self.0.is_consumed(session_id)
    }

    fn prepare_remote(&self, session_id: &str) -> Result<bool, DomainError> {
        self.0.prepare_remote(session_id)
    }

    fn prepare_remote_durable(&self, session_id: &str) -> Result<bool, DomainError> {
        self.0.prepare_remote_durable(session_id)
    }
}

fn load_ids_into(path: &Path, set: &mut HashSet<String>) -> Result<(), DomainError> {
    let file = fs::File::open(path)
        .map_err(|e| DomainError::ThresholdError(format!("anti-nonce open {}: {e}", path.display())))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| DomainError::ThresholdError(format!("anti-nonce read: {e}")))?;
        let id = line.trim();
        if !id.is_empty() {
            set.insert(id.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-anti-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Three-node mesh sharing the same in-memory+disk stores via Arc.
    fn mesh3(tmp: &TempDir) -> [Arc<QuorumAntiNonce>; 3] {
        let n1 = Arc::new(PersistedAntiNonce::open(tmp.0.join("n1.log")).unwrap());
        let n2 = Arc::new(PersistedAntiNonce::open(tmp.0.join("n2.log")).unwrap());
        let n3 = Arc::new(PersistedAntiNonce::open(tmp.0.join("n3.log")).unwrap());

        let q1 = QuorumAntiNonce::from_local(
            n1.clone(),
            Arc::new(MemoryAntiNonceTransport::new(vec![n2.clone(), n3.clone()])),
            2,
        )
        .unwrap();
        let q2 = QuorumAntiNonce::from_local(
            n2.clone(),
            Arc::new(MemoryAntiNonceTransport::new(vec![n1.clone(), n3.clone()])),
            2,
        )
        .unwrap();
        let q3 = QuorumAntiNonce::from_local(n3, Arc::new(MemoryAntiNonceTransport::new(vec![n1, n2])), 2).unwrap();
        [Arc::new(q1), Arc::new(q2), Arc::new(q3)]
    }

    #[test]
    fn multi_node_reuse_rejected_after_quorum_claim() {
        let tmp = TempDir::new("quorum-reuse");
        let [a, b, c] = mesh3(&tmp);
        assert_eq!(a.quorum_t(), 2);

        a.claim_session("sess-1").unwrap();
        // Peers already prepared during A's claim → local already_seen on claim.
        assert!(matches!(b.claim_session("sess-1"), Err(DomainError::NonceReuse(_))));
        assert!(matches!(c.claim_session("sess-1"), Err(DomainError::NonceReuse(_))));
        assert!(matches!(a.claim_session("sess-1"), Err(DomainError::NonceReuse(_))));
    }

    #[test]
    fn multi_node_race_both_refuse_when_cross_seen() {
        let tmp = TempDir::new("quorum-race");
        let [a, b, _] = mesh3(&tmp);

        // Partial race: A burned locally before B's quorum round completes.
        assert!(!a.local_store().prepare("race-1").unwrap());
        assert!(matches!(b.claim_session("race-1"), Err(DomainError::NonceReuse(_))));
    }

    #[test]
    fn persists_across_restart() {
        let tmp = TempDir::new("restart");
        let path = tmp.0.join("sess.log");
        {
            let q = QuorumAntiNonce::open(&path, Arc::new(MemoryAntiNonceTransport::new(vec![])), 0).unwrap();
            q.claim_session("sess-persist").unwrap();
        }
        let q2 = QuorumAntiNonce::open(&path, Arc::new(MemoryAntiNonceTransport::new(vec![])), 0).unwrap();
        assert!(q2.is_consumed("sess-persist").unwrap());
        assert!(matches!(q2.claim_session("sess-persist"), Err(DomainError::NonceReuse(_))));
    }

    #[test]
    fn refuses_before_quorum_when_peers_unreachable() {
        let tmp = TempDir::new("no-quorum");
        // peer_count=2 ⇒ t=2, but transport returns no ACKs.
        let q =
            QuorumAntiNonce::open(tmp.0.join("solo.log"), Arc::new(MemoryAntiNonceTransport::new(vec![])), 2).unwrap();
        assert_eq!(q.quorum_t(), 2);
        assert!(matches!(q.claim_session("need-peers"), Err(DomainError::QuorumNotMet { have: 1, need: 2 })));
        // Local burn still happened — session cannot be reused on this node.
        assert!(q.is_consumed("need-peers").unwrap());
    }

    #[test]
    fn prepare_remote_reports_already_seen() {
        let tmp = TempDir::new("prep");
        let p = PersistedAntiNonce::open(tmp.0.join("p.log")).unwrap();
        assert_eq!(p.prepare_remote("x").unwrap(), false);
        assert_eq!(p.prepare_remote("x").unwrap(), true);
    }
}
