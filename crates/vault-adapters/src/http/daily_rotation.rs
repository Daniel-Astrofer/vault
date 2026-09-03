//! Daily rotation: quorum-gated day_epoch advance + reshare hook (Gate).
//!
//! Lab may still bind signing to the active day. Calendar ahead of the ledger day
//! without a quorum `advance` → stale rejection (no silent auto-roll).
//!
//! `day_epoch` **and** the vote map are persisted under `VAULT_DATA_DIR` so restarts
//! resume the same ledger day and in-flight votes. Cross-node votes: authenticated
//! outbound fan-out over the peer channel (mTLS / token) collects peer self-votes
//! keyed by seed peer id until signing threshold; inbound `/v1/day/vote` binds
//! voter via auth identity hooks.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::http_peer::PeerHttpSettings;
use crate::application::{ClockPort, DailyRotationPort, ReshareHookPort};
use crate::atomic_write_fsync;
use crate::domain::{DayEpoch, DomainError};
use crate::lock_mutex;
use crate::{build_mtls_rustls_client_config, TlsPeerVerifyPolicy};

/// No-op reshare hook (tests / until real reshare policy lands).
pub struct NoopReshareHook;

impl ReshareHookPort for NoopReshareHook {
    fn on_day_advance(
        &self,
        _from: &DayEpoch,
        _to: &DayEpoch,
        _participants: &[crate::domain::NodeId],
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Records day advances for tests / lab observability.
pub struct RecordingReshareHook {
    pub advances: Mutex<Vec<(String, String)>>,
}

impl RecordingReshareHook {
    pub fn new() -> Self {
        Self { advances: Mutex::new(Vec::new()) }
    }
}

impl Default for RecordingReshareHook {
    fn default() -> Self {
        Self::new()
    }
}

impl ReshareHookPort for RecordingReshareHook {
    fn on_day_advance(
        &self,
        from: &DayEpoch,
        to: &DayEpoch,
        _participants: &[crate::domain::NodeId],
    ) -> Result<(), DomainError> {
        self.advances
            .lock()
            .map_err(|_| DomainError::ThresholdError("mutex poisoned: reshare log".into()))?
            .push((from.as_str().to_string(), to.as_str().to_string()));
        Ok(())
    }
}

/// Peer self-vote collected over an authenticated channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDayVote {
    pub voter: String,
    pub day_epoch: DayEpoch,
}

/// Transport for authenticated outbound day-vote fan-out / exchange.
pub trait DayVoteTransport: Send + Sync {
    /// Fan out local vote to peers; each ACK returns that peer's self-vote for `target`
    /// (identity = configured peer id on the authenticated channel — not client body).
    fn exchange_with_peers(&self, local_voter: &str, target: &DayEpoch) -> Result<Vec<PeerDayVote>, DomainError>;
}

/// No peers — solo node.
pub struct NoopDayVoteTransport;

impl DayVoteTransport for NoopDayVoteTransport {
    fn exchange_with_peers(&self, _local_voter: &str, _target: &DayEpoch) -> Result<Vec<PeerDayVote>, DomainError> {
        Ok(vec![])
    }
}

/// HTTP exchange: POST `/v1/day/vote` on each peer with `X-Vault-Node-Id`.
pub struct HttpDayVoteTransport {
    /// (peer_node_id, vote_url)
    peers: Vec<(String, String)>,
    auth_token: Option<String>,
    peer_http: PeerHttpSettings,
    tls: Option<rustls::ClientConfig>,
}

impl HttpDayVoteTransport {
    pub fn with_peer_http(
        peers: Vec<(String, String)>,
        auth_token: Option<String>,
        peer_http: PeerHttpSettings,
    ) -> Self {
        Self { peers, auth_token, peer_http, tls: None }
    }

    pub fn with_mtls(
        peers: Vec<(String, String)>,
        peer_http: PeerHttpSettings,
        client_cert_path: &Path,
        client_key_path: &Path,
        ca_path: &Path,
        verify: &TlsPeerVerifyPolicy,
    ) -> Result<Self, DomainError> {
        let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
        Ok(Self { peers, auth_token: None, peer_http, tls: Some(tls) })
    }

    fn build_blocking_client(&self) -> Result<reqwest::blocking::Client, DomainError> {
        let mut builder = self.peer_http.apply_blocking_builder(reqwest::blocking::Client::builder())?;
        if let Some(tls) = self.tls.clone() {
            builder = builder.use_preconfigured_tls(tls);
        }
        builder.build().map_err(|e| DomainError::ThresholdError(format!("day-vote http client: {e}")))
    }
}

impl DayVoteTransport for HttpDayVoteTransport {
    fn exchange_with_peers(&self, local_voter: &str, target: &DayEpoch) -> Result<Vec<PeerDayVote>, DomainError> {
        let mut out = Vec::with_capacity(self.peers.len());
        if self.peers.is_empty() {
            return Ok(out);
        }
        let client = self.build_blocking_client()?;
        let body = serde_json::json!({
            "day_epoch": target.as_str(),
            "voter": local_voter,
        })
        .to_string();
        for (peer_id, url) in &self.peers {
            let attempts = self.peer_http.max_retries.max(1);
            let mut got = None;
            for attempt in 0..attempts {
                let mut req = client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .header("X-Vault-Node-Id", local_voter)
                    .body(body.clone());
                if let Some(token) = self.auth_token.as_deref() {
                    req = req.header("X-Vault-Token", token);
                }
                match req.send() {
                    Ok(resp) if resp.status().is_success() => {
                        let text = resp.text().unwrap_or_default();
                        // Peer identity is the configured seed id we contacted (auth channel).
                        // Prefer peer's reported self vote from response when present.
                        let peer_day = parse_peer_self_day(&text).unwrap_or_else(|| target.clone());
                        got = Some(PeerDayVote { voter: peer_id.clone(), day_epoch: peer_day });
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
            if let Some(v) = got {
                out.push(v);
            }
        }
        Ok(out)
    }
}

fn parse_peer_self_day(body: &str) -> Option<DayEpoch> {
    #[derive(serde::Deserialize)]
    struct VoteResp {
        #[serde(default)]
        self_day_epoch: Option<String>,
        #[serde(default)]
        day_epoch: Option<String>,
    }
    let r = serde_json::from_str::<VoteResp>(body).ok()?;
    let raw = r.self_day_epoch.or(r.day_epoch)?;
    DayEpoch::parse(raw).ok()
}

/// Quorum-gated daily rotation (Gate path beyond the pure calendar stub).
pub struct QuorumDailyRotation {
    clock: Arc<dyn ClockPort>,
    current: Mutex<DayEpoch>,
    votes: Mutex<HashMap<String, DayEpoch>>,
    quorum_t: usize,
    local_voter: String,
    reshare: Arc<dyn ReshareHookPort>,
    persist_path: Option<PathBuf>,
    transport: Arc<dyn DayVoteTransport>,
}

impl QuorumDailyRotation {
    pub fn new(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
    ) -> Self {
        Self::with_persist_path(clock, quorum_t, local_voter, reshare, None, Arc::new(NoopDayVoteTransport))
    }

    /// Load `day_epoch` from `path` on boot (if present); persist on every advance.
    pub fn with_persist(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
        path: impl Into<PathBuf>,
    ) -> Self {
        Self::with_persist_path(
            clock,
            quorum_t,
            local_voter,
            reshare,
            Some(path.into()),
            Arc::new(NoopDayVoteTransport),
        )
    }

    pub fn with_persist_and_transport(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
        path: impl Into<PathBuf>,
        transport: Arc<dyn DayVoteTransport>,
    ) -> Self {
        Self::with_persist_path(clock, quorum_t, local_voter, reshare, Some(path.into()), transport)
    }

    pub fn with_transport(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
        transport: Arc<dyn DayVoteTransport>,
    ) -> Self {
        Self::with_persist_path(clock, quorum_t, local_voter, reshare, None, transport)
    }

    fn with_persist_path(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
        persist_path: Option<PathBuf>,
        transport: Arc<dyn DayVoteTransport>,
    ) -> Self {
        let from_clock = DayEpoch::from_unix_secs(clock.unix_now_secs());
        let current = match persist_path.as_ref() {
            Some(path) => load_day_epoch(path).unwrap_or(from_clock),
            None => from_clock,
        };
        let votes = match persist_path.as_ref() {
            Some(path) => load_day_votes(&votes_path(path)).unwrap_or_default(),
            None => HashMap::new(),
        };
        Self {
            clock,
            current: Mutex::new(current),
            votes: Mutex::new(votes),
            quorum_t: quorum_t.max(1),
            local_voter: local_voter.into(),
            reshare,
            persist_path,
            transport,
        }
    }

    pub fn quorum_t(&self) -> usize {
        self.quorum_t
    }

    pub fn local_voter(&self) -> &str {
        &self.local_voter
    }

    /// Current in-memory vote map snapshot (tests / observability).
    pub fn vote_count_for(&self, target: &DayEpoch) -> usize {
        lock_mutex(&self.votes, "day votes").map(|votes| votes.values().filter(|e| *e == target).count()).unwrap_or(0)
    }

    fn write_persist(&self, epoch: &DayEpoch) -> Result<(), DomainError> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };
        persist_day_epoch(path, epoch)?;
        let votes = lock_mutex(&self.votes, "day votes")?;
        persist_day_votes(&votes_path(path), &votes)
    }

    fn persist_votes_only(&self) -> Result<(), DomainError> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };
        let votes = lock_mutex(&self.votes, "day votes")?;
        persist_day_votes(&votes_path(path), &votes)
    }
}

fn votes_path(epoch_path: &Path) -> PathBuf {
    epoch_path.with_extension("votes.json")
}

fn load_day_epoch(path: &Path) -> Option<DayEpoch> {
    let raw = fs::read_to_string(path).ok()?;
    DayEpoch::parse(raw.trim()).ok()
}

fn persist_day_epoch(path: &Path, epoch: &DayEpoch) -> Result<(), DomainError> {
    atomic_write_fsync(path, format!("{}\n", epoch.as_str()).as_bytes())
        .map_err(|e| DomainError::ThresholdError(format!("day_epoch persist: {e}")))
}

fn load_day_votes(path: &Path) -> Option<HashMap<String, DayEpoch>> {
    let raw = fs::read_to_string(path).ok()?;
    let map: HashMap<String, String> = serde_json::from_str(&raw).ok()?;
    let mut out = HashMap::new();
    for (voter, epoch) in map {
        let Ok(e) = DayEpoch::parse(epoch) else {
            continue;
        };
        out.insert(voter, e);
    }
    Some(out)
}

fn persist_day_votes(path: &Path, votes: &HashMap<String, DayEpoch>) -> Result<(), DomainError> {
    let serial: HashMap<&str, &str> = votes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let body =
        serde_json::to_vec(&serial).map_err(|e| DomainError::ThresholdError(format!("day votes serialize: {e}")))?;
    atomic_write_fsync(path, &body).map_err(|e| DomainError::ThresholdError(format!("day votes persist: {e}")))
}

impl DailyRotationPort for QuorumDailyRotation {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        let g = lock_mutex(&self.current, "day_epoch")?;
        if live > *g {
            return Err(DomainError::DayEpochStale { have: g.as_str().to_string(), need: live.as_str().to_string() });
        }
        Ok(g.clone())
    }

    fn record_vote(&self, voter: &str, target: &DayEpoch) -> Result<(), DomainError> {
        {
            let mut votes = lock_mutex(&self.votes, "day votes")?;
            votes.insert(voter.to_string(), target.clone());
        }
        self.persist_votes_only()?;
        Ok(())
    }

    fn advance(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        self.record_vote(&self.local_voter, &live)?;

        // Authenticated outbound fan-out: collect peer self-votes (fail-closed toward quorum).
        let peer_votes = self.transport.exchange_with_peers(&self.local_voter, &live)?;
        for pv in &peer_votes {
            self.record_vote(&pv.voter, &pv.day_epoch)?;
        }

        let have = {
            let votes = lock_mutex(&self.votes, "day votes")?;
            votes.values().filter(|e| *e == &live).count()
        };
        if have < self.quorum_t {
            return Err(DomainError::QuorumNotMet { have, need: self.quorum_t });
        }

        let mut g = lock_mutex(&self.current, "day_epoch")?;
        let from = g.clone();
        if live == from {
            // Idempotent: still ensure disk matches (boot without file).
            drop(g);
            self.write_persist(&live)?;
            return Ok(live);
        }
        if live < from {
            return Err(DomainError::DayEpochStale {
                have: live.as_str().to_string(),
                need: from.as_str().to_string(),
            });
        }
        *g = live.clone();
        drop(g);
        self.write_persist(&live)?;
        let participants: Vec<crate::domain::NodeId> = {
            let votes = lock_mutex(&self.votes, "day votes")?;
            votes
                .iter()
                .filter(|(_, e)| *e == &live)
                .filter_map(|(voter, _)| crate::domain::NodeId::new(voter.clone()).ok())
                .collect()
        };
        self.reshare.on_day_advance(&from, &live, &participants)?;
        Ok(live)
    }

    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError> {
        let cur = {
            let g = lock_mutex(&self.current, "day_epoch")?;
            g.clone()
        };
        if bound != &cur {
            return Err(DomainError::DayEpochStale {
                have: bound.as_str().to_string(),
                need: cur.as_str().to_string(),
            });
        }
        // Also reject if calendar has moved past the ledger day (stale session window).
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        if live > cur {
            return Err(DomainError::DayEpochStale { have: cur.as_str().to_string(), need: live.as_str().to_string() });
        }
        Ok(())
    }
}

/// Backward-compatible name: quorum rotation with t=1 (local self-vote advances).
pub struct LedgerDayEpochStub {
    inner: QuorumDailyRotation,
}

impl LedgerDayEpochStub {
    pub fn new(clock: Arc<dyn ClockPort>) -> Self {
        Self { inner: QuorumDailyRotation::new(clock, 1, "local", Arc::new(NoopReshareHook)) }
    }

    pub fn with_reshare(clock: Arc<dyn ClockPort>, reshare: Arc<dyn ReshareHookPort>) -> Self {
        Self { inner: QuorumDailyRotation::new(clock, 1, "local", reshare) }
    }
}

impl DailyRotationPort for LedgerDayEpochStub {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError> {
        self.inner.current_day_epoch()
    }

    fn advance(&self) -> Result<DayEpoch, DomainError> {
        self.inner.advance()
    }

    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError> {
        self.inner.require_epoch(bound)
    }

    fn record_vote(&self, voter: &str, target: &DayEpoch) -> Result<(), DomainError> {
        self.inner.record_vote(voter, target)
    }
}

/// In-memory multi-node day vote exchange for tests.
pub struct MemoryDayVoteTransport {
    /// peer_id → shared rotation so we can record remote votes + peer self-vote.
    peers: Vec<(String, Arc<QuorumDailyRotation>)>,
}

impl MemoryDayVoteTransport {
    pub fn new(peers: Vec<(String, Arc<QuorumDailyRotation>)>) -> Self {
        Self { peers }
    }
}

impl DayVoteTransport for MemoryDayVoteTransport {
    fn exchange_with_peers(&self, local_voter: &str, target: &DayEpoch) -> Result<Vec<PeerDayVote>, DomainError> {
        let mut out = Vec::with_capacity(self.peers.len());
        for (peer_id, rot) in &self.peers {
            // Record our vote on the peer (authenticated channel = known peer map).
            rot.record_vote(local_voter, target)?;
            // Peer auto-records its own self-vote for the live target when exchanging.
            rot.record_vote(peer_id, target)?;
            out.push(PeerDayVote { voter: peer_id.clone(), day_epoch: target.clone() });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ClockPort;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);
    impl ClockPort for FakeClock {
        fn unix_now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct TempProbe(PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-day-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn quorum_advance_invokes_reshare_and_rejects_stale() {
        // 2024-01-01 00:00 UTC
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200)));
        let hook = Arc::new(RecordingReshareHook::new());
        let rot = QuorumDailyRotation::new(clock.clone(), 2, "v1", hook.clone());

        assert_eq!(rot.current_day_epoch().unwrap().as_str(), "2024-01-01");

        // Roll calendar to next day without advance → stale.
        clock.0.store(1_704_067_200 + 86_400, Ordering::SeqCst);
        assert!(matches!(rot.current_day_epoch(), Err(DomainError::DayEpochStale { .. })));

        // One vote insufficient (no peer transport).
        assert!(matches!(rot.advance(), Err(DomainError::QuorumNotMet { have: 1, need: 2 })));

        rot.record_vote("v2", &DayEpoch::from_unix_secs(1_704_067_200 + 86_400)).unwrap();
        let next = rot.advance().unwrap();
        assert_eq!(next.as_str(), "2024-01-02");
        assert_eq!(rot.current_day_epoch().unwrap().as_str(), "2024-01-02");

        let log = hook.advances.lock().unwrap().clone();
        assert_eq!(log, vec![("2024-01-01".into(), "2024-01-02".into())]);

        // Stale bound rejected.
        let stale = DayEpoch::parse("2024-01-01").unwrap();
        assert!(matches!(rot.require_epoch(&stale), Err(DomainError::DayEpochStale { .. })));
    }

    #[test]
    fn day_epoch_persists_across_restart() {
        let tmp = TempProbe::new("persist");
        let path = tmp.0.join("day_epoch");
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200)));
        let hook = Arc::new(RecordingReshareHook::new());
        let rot = QuorumDailyRotation::with_persist(clock.clone(), 1, "v1", hook.clone(), path.clone());
        assert_eq!(rot.current_day_epoch().unwrap().as_str(), "2024-01-01");

        clock.0.store(1_704_067_200 + 86_400, Ordering::SeqCst);
        assert_eq!(rot.advance().unwrap().as_str(), "2024-01-02");
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "2024-01-02");

        // Calendar still on day 2; boot from disk must not roll back to clock-only.
        let rot2 =
            QuorumDailyRotation::with_persist(clock.clone(), 1, "v1", Arc::new(RecordingReshareHook::new()), path);
        assert_eq!(rot2.current_day_epoch().unwrap().as_str(), "2024-01-02");
    }

    #[test]
    fn day_votes_persist_across_restart() {
        let tmp = TempProbe::new("votes");
        let path = tmp.0.join("day_epoch");
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200 + 86_400)));
        let target = DayEpoch::from_unix_secs(1_704_067_200 + 86_400);
        let rot = QuorumDailyRotation::with_persist(
            clock.clone(),
            2,
            "v1",
            Arc::new(RecordingReshareHook::new()),
            path.clone(),
        );
        rot.record_vote("v2", &target).unwrap();
        assert_eq!(rot.vote_count_for(&target), 1);

        let rot2 = QuorumDailyRotation::with_persist(clock, 2, "v1", Arc::new(RecordingReshareHook::new()), path);
        assert_eq!(rot2.vote_count_for(&target), 1);
    }

    #[test]
    fn cross_node_fanout_reaches_signing_threshold() {
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200 + 86_400)));
        let hook = Arc::new(RecordingReshareHook::new());
        // Build peer rotations first (t=2 each), then wire memory transport.
        let v2 = Arc::new(QuorumDailyRotation::new(clock.clone(), 2, "v2", Arc::new(NoopReshareHook)));
        let v3 = Arc::new(QuorumDailyRotation::new(clock.clone(), 2, "v3", Arc::new(NoopReshareHook)));
        let transport =
            Arc::new(MemoryDayVoteTransport::new(vec![("v2".into(), v2.clone()), ("v3".into(), v3.clone())]));
        let v1 = QuorumDailyRotation::with_transport(
            clock.clone(),
            2, // signing threshold for n=3
            "v1",
            hook.clone(),
            transport,
        );
        let next = v1.advance().unwrap();
        assert_eq!(next.as_str(), "2024-01-02");
        assert!(v1.vote_count_for(&next) >= 2);
        // Peers recorded v1's vote via fan-out.
        assert_eq!(v2.vote_count_for(&next), 2); // v1 + v2 self
    }

    #[test]
    fn cross_node_fails_closed_when_peers_unreachable() {
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200 + 86_400)));
        // peer_count implied by t=2 with noop transport → only local vote.
        let rot = QuorumDailyRotation::new(clock, 2, "v1", Arc::new(NoopReshareHook));
        assert!(matches!(rot.advance(), Err(DomainError::QuorumNotMet { have: 1, need: 2 })));
    }
}
