//! Mesh-replicated Intent consume: durable local log + quorum peer prepare ACKs.
//!
//! Mirrors [`super::session_persist::QuorumAntiNonce`]:
//! - Append-only local `intent_id` fsync (via [`PersistedBucketLedger`]).
//! - Authorize/sign path refuses until `ceil(2n/3)` durable prepares succeed
//!   (self + peer HTTP ACKs). Fail-closed if quorum unmet / peers unreachable.
//! - Refuse if any peer reports `already_seen` (cross-node double-spend).

use std::path::Path;
use std::sync::Arc;

use super::http_peer::PeerHttpSettings;
use crate::application::ports::BucketLedgerPort;
use crate::domain::{quorum_two_thirds, BucketKind, BucketPolicy, DomainError};
use crate::{build_mtls_rustls_client_config, TlsPeerVerifyPolicy};
use crate::{InMemoryBucketLedger, PersistedBucketLedger};

/// Result of a peer durable Intent consume prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentPrepareAck {
    pub already_seen: bool,
}

/// Transport used by [`QuorumBucketLedger`] to collect peer consume prepares.
pub trait IntentConsumeQuorumTransport: Send + Sync {
    /// Soft TTL reservation (reserve phase / HTTP ingest).
    fn prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError>;
    /// Durable burn promote (commit phase). Default: same as soft (lab/tests).
    fn durable_prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.prepare_on_peers(intent_id)
    }
}

/// HTTP peer prepare: POST `/v1/intent/consume/prepare`.
pub struct HttpIntentConsumeTransport {
    peer_prepare_urls: Vec<String>,
    auth_token: Option<String>,
    peer_http: PeerHttpSettings,
    tls: Option<rustls::ClientConfig>,
}

impl HttpIntentConsumeTransport {
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
        builder.build().map_err(|e| DomainError::ThresholdError(format!("intent-consume http client: {e}")))
    }
}

impl IntentConsumeQuorumTransport for HttpIntentConsumeTransport {
    fn prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.post_prepare(intent_id, false)
    }

    fn durable_prepare_on_peers(&self, intent_id: &str) -> Result<Vec<IntentPrepareAck>, DomainError> {
        self.post_prepare(intent_id, true)
    }
}

impl HttpIntentConsumeTransport {
    fn post_prepare(&self, intent_id: &str, durable: bool) -> Result<Vec<IntentPrepareAck>, DomainError> {
        let mut out = Vec::with_capacity(self.peer_prepare_urls.len());
        if self.peer_prepare_urls.is_empty() {
            return Ok(out);
        }
        let client = self.build_blocking_client()?;
        let body = serde_json::json!({ "intent_id": intent_id, "durable": durable }).to_string();
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
                        ack = Some(IntentPrepareAck { already_seen: parse_already_seen(&text)? });
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
                            break;
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
    serde_json::from_str::<PrepResp>(body).map(|r| r.already_seen).map_err(|_| {
        DomainError::ThresholdError("intent-consume peer response missing already_seen (fail-closed)".into())
    })
}

/// In-memory multi-node transport for tests.
pub struct MemoryIntentConsumeTransport {
    peers: Vec<Arc<PersistedBucketLedger>>,
}

impl MemoryIntentConsumeTransport {
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
    pub fn from_local(
        local: Arc<PersistedBucketLedger>,
        transport: Arc<dyn IntentConsumeQuorumTransport>,
        peer_count: usize,
    ) -> Self {
        let n = peer_count.saturating_add(1).max(1);
        let quorum_t = if peer_count == 0 { 1 } else { quorum_two_thirds(n).max(1) };
        Self { local, transport, peer_count, quorum_t }
    }

    pub fn local_store(&self) -> Arc<PersistedBucketLedger> {
        self.local.clone()
    }

    pub fn quorum_t(&self) -> usize {
        self.quorum_t
    }

    pub fn peer_count(&self) -> usize {
        self.peer_count
    }

    pub fn admit_destinations(
        &self,
        kind: BucketKind,
        dests: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), DomainError> {
        self.local.admit_destinations(kind, dests)
    }

    /// Peer prepare path (HTTP ingest). Soft TTL reservation (not durable burn).
    pub fn prepare_remote(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.prepare_soft(intent_id)
    }

    /// Durable peer prepare (commit / claim fan-out).
    pub fn prepare_remote_durable(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.prepare_consume(intent_id)
    }

    /// Soft-reserve locally + soft peer prepare. Fail-closed on unmet quorum.
    fn claim_reserve(&self, intent_id: &str) -> Result<(), DomainError> {
        if self.local.prepare_soft(intent_id)? {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        let acks = self.transport.prepare_on_peers(intent_id)?;
        if acks.iter().any(|a| a.already_seen) {
            return Err(DomainError::IntentReplay(format!("intent seen on ≥1 peer: {intent_id}")));
        }
        let have = 1 + acks.len();
        if have < self.quorum_t {
            // Roll back local soft reserve.
            let _ = self.local.release_reservation(intent_id, BucketKind::Users, 0);
            return Err(DomainError::QuorumNotMet { have, need: self.quorum_t });
        }
        Ok(())
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
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError> {
        self.local.policy(kind)
    }

    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError> {
        self.local.spent_today(kind)
    }

    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.local.record_spend(kind, amount_sats)
    }

    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.local.is_consumed(intent_id)
    }

    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        self.try_consume(intent_id)
    }

    fn try_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        self.claim_consume(intent_id)
    }

    fn has_reservation(&self, intent_id: &str) -> Result<bool, DomainError> {
        Ok(self.local.has_reservation(intent_id))
    }

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

    fn commit_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        if self.local.is_consumed(intent_id)? {
            // Idempotent commit retry (CHANNELS open-ok / commit-fail outbox).
            return Ok(());
        }
        // Durable mesh burn (High #10) — reservation may be local soft or peer soft.
        self.claim_consume(intent_id)
    }

    fn release_reservation(&self, intent_id: &str, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.local.release_reservation(intent_id, kind, amount_sats)
    }

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
