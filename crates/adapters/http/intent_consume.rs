//! Mesh-replicated Intent consume: durable local log + quorum peer prepare ACKs.
//!
//! Mirrors [`super::session_persist::QuorumAntiNonce`]:
//! - Append-only local `intent_id` fsync (via [`PersistedBucketLedger`]).
//! - Authorize/sign path refuses until `ceil(2n/3)` durable prepares succeed
//!   (self + peer HTTP ACKs). Fail-closed if quorum unmet / peers unreachable.
//! - Refuse if any peer reports `already_seen` (cross-node double-spend).

use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::Instant;

use super::http_peer::PeerHttpSettings;
use crate::application::ports::BucketLedgerPort;
use crate::domain::{quorum_two_thirds, BucketKind, BucketPolicy, DomainError};
use crate::{build_mtls_rustls_client_config, TlsPeerVerifyPolicy};
use crate::{InMemoryBucketLedger, PersistedBucketLedger};

/// Result of a peer durable Intent consume prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentPrepareAck {
    /// Whether the peer already reserved or consumed this Intent ID.
    pub already_seen: bool,
}

/// Transport used by [`QuorumBucketLedger`] to collect peer consume prepares.
pub trait IntentConsumeQuorumTransport: Send + Sync {
    /// Requests soft-TTL reservations from peers during the reserve phase.
    fn prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError>;
    /// Requests durable consume claims during commit; defaults to soft prepare for lab transports.
    fn durable_prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.prepare_on_peers(intent_id)
    }
}

/// HTTP peer prepare transport for `/v1/intent/consume/prepare`.
pub struct HttpIntentConsumeTransport {
    peer_prepare_urls: Vec<String>,
    auth_token: Option<String>,
    peer_http: PeerHttpSettings,
    tls: Option<rustls::ClientConfig>,
}

impl HttpIntentConsumeTransport {
    /// Creates the transport with peer HTTP policy and optional static-token authentication.
    pub fn with_peer_http(
        peer_prepare_urls: Vec<String>,
        auth_token: Option<String>,
        peer_http: PeerHttpSettings,
    ) -> Self {
        Self { peer_prepare_urls, auth_token, peer_http, tls: None }
    }

    /// Creates the transport with mTLS client credentials and peer verification policy.
    ///
    /// Static-token authentication is disabled for this configuration.
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
        builder.build().map_err(|e| DomainError::ThresholdError(format!("intent-consume http client: {e}")))
    }
}

impl IntentConsumeQuorumTransport for HttpIntentConsumeTransport {
    /// Collects soft reservations from the configured peers.
    fn prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.post_prepare(intent_id, false)
    }

    /// Collects durable consume claims from the configured peers.
    fn durable_prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.post_prepare(intent_id, true)
    }
}

impl HttpIntentConsumeTransport {
    fn post_prepare(&self, intent_id: &str, durable: bool) -> Result<Vec<IntentPrepareAck>, DomainError> {
        if self.peer_prepare_urls.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.build_blocking_client()?;
        let body = serde_json::json!({ "intent_id": intent_id, "durable": durable }).to_string();
        let peer_count = self.peer_prepare_urls.len();
        let required = quorum_two_thirds(peer_count + 1).saturating_sub(1);
        let (sender, receiver) = mpsc::channel();
        for url in self.peer_prepare_urls.iter().cloned() {
            let sender = sender.clone();
            let client = client.clone();
            let body = body.clone();
            let token = self.auth_token.clone();
            let settings = self.peer_http.clone();
            std::thread::spawn(move || {
                let result = post_intent_prepare(&client, &settings, &url, token.as_deref(), &body);
                let _ = sender.send((url, result));
            });
        }
        drop(sender);

        let deadline = Instant::now() + self.peer_http.timeout;
        let mut received = 0usize;
        let mut out = Vec::with_capacity(required);
        while received < peer_count && out.len() < required {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            match receiver.recv_timeout(remaining) {
                Ok((_, Ok(Some(ack)))) => {
                    received += 1;
                    if ack.already_seen {
                        return Ok(vec![ack]);
                    }
                    out.push(ack);
                }
                Ok((_, Ok(None))) => received += 1,
                Ok((url, Err(error))) => {
                    received += 1;
                    eprintln!("intent-consume peer {url} unavailable: {error}");
                }
                Err(_) => break,
            }
        }
        Ok(out)
    }
}

fn post_intent_prepare(
    client: &reqwest::blocking::Client,
    settings: &PeerHttpSettings,
    url: &str,
    auth_token: Option<&str>,
    body: &str,
) -> Result<Option<IntentPrepareAck>, DomainError> {
    let attempts = settings.max_retries.max(1);
    for attempt in 0..attempts {
        let mut req = client.post(url).header("Content-Type", "application/json").body(body.to_owned());
        if let Some(token) = auth_token {
            req = req.header("X-Vault-Token", token);
        }
        match req.send() {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().unwrap_or_default();
                return Ok(Some(IntentPrepareAck { already_seen: parse_already_seen(&text)? }));
            }
            Ok(resp) => {
                if !PeerHttpSettings::should_retry_status(resp.status()) || attempt + 1 >= attempts {
                    return Ok(None);
                }
            }
            Err(_) if attempt + 1 >= attempts => return Ok(None),
            Err(_) => {}
        }
        std::thread::sleep(settings.backoff_delay(attempt));
    }
    Ok(None)
}

fn parse_already_seen(body: &str) -> Result<bool, DomainError> {
    #[derive(serde::Deserialize)]
    struct PrepResp {
        already_seen: bool,
    }
    serde_json::from_str::<PrepResp>(body).map(|r| r.already_seen).map_err(|_| {
        DomainError::ThresholdError("intent-consume peer response missing already_seen (fail-closed)".into())
    })
}

/// In-memory multi-node transport for tests.
pub struct MemoryIntentConsumeTransport {
    peers: Vec<Arc<PersistedBucketLedger>>,
}

impl MemoryIntentConsumeTransport {
    /// Creates an in-memory transport for the supplied peer ledgers.
    pub fn new(peers: Vec<Arc<PersistedBucketLedger>>) -> Self {
        Self { peers }
    }
}

impl IntentConsumeQuorumTransport for MemoryIntentConsumeTransport {
    fn prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        let mut out = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            out.push(IntentPrepareAck { already_seen: peer.prepare_soft(intent_id)? });
        }
        Ok(out)
    }

    fn durable_prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        let mut out = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            out.push(IntentPrepareAck { already_seen: peer.prepare_consume(intent_id)? });
        }
        Ok(out)
    }
}

/// Quorum-replicated Intent consume ledger.
///
/// Cluster size `n = 1 + peer_count`. Quorum `t = ceil(2n/3)`. Solo: `t = 1`.
pub struct QuorumBucketLedger {
    local: Arc<PersistedBucketLedger>,
    transport: Arc<dyn IntentConsumeQuorumTransport>,
    peer_count: usize,
    quorum_t: usize,
}

impl QuorumBucketLedger {
    /// Wraps a local durable bucket ledger with remote prepare transport.
    ///
    /// The configured peer count determines the two-thirds quorum and should
    /// match the transport's peer set.
    pub fn from_local(
        local: Arc<PersistedBucketLedger>,
        transport: Arc<dyn IntentConsumeQuorumTransport>,
        peer_count: usize,
    ) -> Self {
        let n = peer_count.saturating_add(1).max(1);
        let quorum_t = if peer_count == 0 { 1 } else { quorum_two_thirds(n).max(1) };
        Self { local, transport, peer_count, quorum_t }
    }

    /// Returns a shared handle to the local persisted bucket ledger.
    pub fn local_store(&self) -> Arc<PersistedBucketLedger> {
        self.local.clone()
    }

    /// Returns the required prepare quorum, including this node.
    pub fn quorum_t(&self) -> usize {
        self.quorum_t
    }

    /// Returns the configured remote peer count, excluding this node.
    pub fn peer_count(&self) -> usize {
        self.peer_count
    }

    /// Persists destination allowlists for the selected bucket kind.
    pub fn admit_destinations(
        &self,
        kind: BucketKind,
        dests: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), DomainError> {
        self.local.admit_destinations(kind, dests)
    }

    /// Creates a local soft reservation for a remotely requested Intent.
    pub fn prepare_remote(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.prepare_soft(intent_id)
    }

    /// Creates a local durable consume claim for a remotely requested Intent.
    pub fn prepare_remote_durable(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.prepare_consume(intent_id)
    }

    /// Local durable burn + quorum peer durable prepare. Fail-closed on unmet quorum /
    /// cross-node already_seen.
    fn claim_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        if self.local.prepare_consume(intent_id)? {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        let acks = self.transport.durable_prepare_on_peers(intent_id)?;
        if acks.iter().any(|a| a.already_seen) {
            return Err(DomainError::IntentReplay(format!("intent seen on ≥1 peer: {intent_id}")));
        }
        let have = 1 + acks.len();
        if have < self.quorum_t {
            return Err(DomainError::QuorumNotMet { have, need: self.quorum_t });
        }
        Ok(())
    }
}

impl BucketLedgerPort for QuorumBucketLedger {
    /// Returns the local policy for a bucket kind.
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError> {
        self.local.policy(kind)
    }

    /// Returns today's recorded spend for a bucket kind.
    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError> {
        self.local.spent_today(kind)
    }

    /// Records a local spend amount for a bucket kind.
    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.local.record_spend(kind, amount_sats)
    }

    /// Checks whether the local ledger has durably consumed an Intent ID.
    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.is_consumed(intent_id)
    }

    /// Consumes an Intent ID using the same quorum claim path as `try_consume`.
    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        self.try_consume(intent_id)
    }

    /// Durably consumes the Intent locally and requires peer quorum.
    fn try_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        self.claim_consume(intent_id)
    }

    /// Reports whether the local ledger currently holds a reservation for an Intent.
    fn has_reservation(&self, intent_id: &str) -> Result<bool, DomainError> {
        Ok(self.local.has_reservation(intent_id))
    }

    /// Validates bucket policy, reserves local spend, and gathers soft peer reservations.
    ///
    /// The local reservation is released when a peer reports replay or quorum
    /// is unmet. A transport error propagates after local reservation creation.
    fn reserve_spend(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        {
            let mut g = self.local.inner.inner.lock().expect("bucket lock");
            InMemoryBucketLedger::sweep_expired(&mut g);
            if g.consumed.contains(intent_id) || g.reserved.contains_key(intent_id) {
                return Err(DomainError::IntentReplay(intent_id.to_string()));
            }
            let policy =
                g.policies.get(&kind).cloned().ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))?;
            let spent = *g.spent_today.get(&kind).unwrap_or(&0);
            validate(&policy, spent)?;
            let e = g.spent_today.entry(kind).or_insert(0);
            *e = e.saturating_add(amount_sats);
            g.reserved.insert(
                intent_id.to_string(),
                (kind, amount_sats, std::time::Instant::now() + std::time::Duration::from_secs(300)),
            );
        }
        let acks = self.transport.prepare_on_peers(intent_id)?;
        if acks.iter().any(|a| a.already_seen) {
            let _ = self.local.release_reservation(intent_id, kind, amount_sats);
            return Err(DomainError::IntentReplay(format!("intent seen on ≥1 peer: {intent_id}")));
        }
        let have = 1 + acks.len();
        if have < self.quorum_t {
            let _ = self.local.release_reservation(intent_id, kind, amount_sats);
            return Err(DomainError::QuorumNotMet { have, need: self.quorum_t });
        }
        Ok(())
    }

    /// Promotes a reservation to a durable consume quorum; repeated local commits are idempotent.
    fn commit_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        if self.local.is_consumed(intent_id)? {
            // Idempotent commit retry (CHANNELS open-ok / commit-fail outbox).
            return Ok(());
        }
        // Durable mesh burn (High #10) — reservation may be local soft or peer soft.
        self.claim_consume(intent_id)
    }

    /// Releases the local reservation and refunds its reserved spend amount.
    fn release_reservation(&self, intent_id: &str, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.local.release_reservation(intent_id, kind, amount_sats)
    }

    /// Reserves spend, validates it, then durably consumes the Intent across the quorum.
    fn authorize_spend_and_consume(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        self.reserve_spend(intent_id, kind, amount_sats, validate)?;
        if let Err(e) = self.commit_consume(intent_id) {
            let _ = self.release_reservation(intent_id, kind, amount_sats);
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-intent-q-{name}-{}", std::process::id()));
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

    fn mesh3(tmp: &TempDir) -> [Arc<QuorumBucketLedger>; 3] {
        let n1 = Arc::new(PersistedBucketLedger::open(tmp.0.join("n1.log"), 1_000, 10_000).unwrap());
        let n2 = Arc::new(PersistedBucketLedger::open(tmp.0.join("n2.log"), 1_000, 10_000).unwrap());
        let n3 = Arc::new(PersistedBucketLedger::open(tmp.0.join("n3.log"), 1_000, 10_000).unwrap());
        let q1 = QuorumBucketLedger::from_local(
            n1.clone(),
            Arc::new(MemoryIntentConsumeTransport::new(vec![n2.clone(), n3.clone()])),
            2,
        );
        let q2 = QuorumBucketLedger::from_local(
            n2.clone(),
            Arc::new(MemoryIntentConsumeTransport::new(vec![n1.clone(), n3.clone()])),
            2,
        );
        let q3 = QuorumBucketLedger::from_local(n3, Arc::new(MemoryIntentConsumeTransport::new(vec![n1, n2])), 2);
        [Arc::new(q1), Arc::new(q2), Arc::new(q3)]
    }

    #[test]
    fn multi_node_double_spend_rejected_after_quorum_consume() {
        let tmp = TempDir::new("cross");
        let [a, b, c] = mesh3(&tmp);
        assert_eq!(a.quorum_t(), 2);
        a.try_consume("intent-1").unwrap();
        assert!(matches!(b.try_consume("intent-1"), Err(DomainError::IntentReplay(_))));
        assert!(matches!(c.try_consume("intent-1"), Err(DomainError::IntentReplay(_))));
    }

    #[test]
    fn refuses_before_quorum_when_peers_unreachable() {
        let tmp = TempDir::new("no-q");
        let local = Arc::new(PersistedBucketLedger::open(tmp.0.join("solo.log"), 1_000, 10_000).unwrap());
        let q = QuorumBucketLedger::from_local(local, Arc::new(MemoryIntentConsumeTransport::new(vec![])), 2);
        assert_eq!(q.quorum_t(), 2);
        assert!(matches!(q.try_consume("need-peers"), Err(DomainError::QuorumNotMet { have: 1, need: 2 })));
        assert!(q.is_consumed("need-peers").unwrap());
    }

    #[test]
    fn authorize_spend_mesh_replay_safe() {
        let tmp = TempDir::new("auth");
        let [a, b, _] = mesh3(&tmp);
        let validate = |_p: &BucketPolicy, _s: u64| Ok(());
        a.authorize_spend_and_consume("i-auth", BucketKind::Users, 10, &validate).unwrap();
        let err = b.authorize_spend_and_consume("i-auth", BucketKind::Users, 10, &validate).unwrap_err();
        assert!(matches!(err, DomainError::IntentReplay(_)));
    }
}
