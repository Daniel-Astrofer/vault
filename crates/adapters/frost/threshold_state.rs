use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::application::SigningPort;
use crate::domain::{
    derive_nonce, field_add, field_mul, interpolate_secret, nonce_commitment, CombinedSignature, DomainError, GroupKey,
    KeyShare, PartialSignature, SigningPhase, SigningSession,
};

/// In-memory threshold-signing state used by the lab signing implementation.
///
/// The mutex protects group material, active sessions, nonce commitments, and
/// consumed session IDs as one synchronized state machine.
pub struct ThresholdVaultState {
    inner: Mutex<Inner>,
}

struct Inner {
    group: GroupKey,
    local_share: KeyShare,
    lab_all_shares: Vec<KeyShare>,
    sessions: HashMap<String, SigningSession>,
    used_nonce_commitments: HashSet<String>,
    consumed_sessions: HashSet<String>,
}

impl ThresholdVaultState {
    /// Creates signing state from group parameters, this node's share, and lab shares.
    ///
    /// `lab_all_shares` is used only by the local all-shares collection helper.
    pub fn new(group: GroupKey, local_share: KeyShare, lab_all_shares: Vec<KeyShare>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                group,
                local_share,
                lab_all_shares,
                sessions: HashMap::new(),
                used_nonce_commitments: HashSet::new(),
                consumed_sessions: HashSet::new(),
            }),
        }
    }

    /// Returns a clone of the configured threshold group parameters.
    pub fn group(&self) -> GroupKey {
        self.inner.lock().expect("threshold").group.clone()
    }

    /// Opens a unique signing session and binds this node's nonce commitment.
    ///
    /// The online count must meet the group threshold. Session IDs and derived
    /// nonce commitments cannot be reused, including for sessions already open.
    pub fn begin_session(
        &self,
        session_id: &str,
        message_hash: &str,
        online: usize,
    ) -> Result<SigningSession, DomainError> {
        let mut g = self.inner.lock().expect("threshold");
        if online < g.group.t {
            return Err(DomainError::FailStop { online, need: g.group.t });
        }
        if g.consumed_sessions.contains(session_id) || g.sessions.contains_key(session_id) {
            return Err(DomainError::NonceReuse(format!("session_id already used: {session_id}")));
        }
        let share_value = g.local_share.value;
        let share_index = g.local_share.index.0;
        let nonce = derive_nonce(session_id, message_hash, share_value);
        let commit = nonce_commitment(nonce, share_index);
        if g.used_nonce_commitments.contains(&commit) {
            return Err(DomainError::NonceReuse(commit));
        }
        g.used_nonce_commitments.insert(commit.clone());
        let session = SigningSession {
            session_id: session_id.to_string(),
            message_hash: message_hash.to_string(),
            phase: SigningPhase::NoncesBound,
            bound_nonce_commitments: vec![commit],
            partials: vec![],
        };
        g.sessions.insert(session_id.to_string(), session.clone());
        Ok(session)
    }

    /// Creates and records this node's partial signature for an open session.
    ///
    /// The session must be in `NoncesBound` or `Open`; consumed or unknown
    /// sessions and duplicate share indices are rejected.
    pub fn contribute_local_partial(&self, session_id: &str) -> Result<PartialSignature, DomainError> {
        let mut g = self.inner.lock().expect("threshold");
        if g.consumed_sessions.contains(session_id) {
            return Err(DomainError::SessionConsumed(session_id.to_string()));
        }
        let share_value = g.local_share.value;
        let share_index = g.local_share.index.clone();
        let node_id = g.local_share.node_id.clone();
        let message_hash = g
            .sessions
            .get(session_id)
            .ok_or_else(|| DomainError::UnknownProposal(session_id.to_string()))?
            .message_hash
            .clone();
        let phase = g.sessions.get(session_id).unwrap().phase;
        if phase != SigningPhase::NoncesBound && phase != SigningPhase::Open {
            return Err(DomainError::BadSigningPhase {
                session_id: session_id.to_string(),
                phase: format!("{phase:?}"),
            });
        }
        let nonce = derive_nonce(session_id, &message_hash, share_value);
        let commit = nonce_commitment(nonce, share_index.0);
        let msg_scalar = crate::domain::lab_random_u64(message_hash.as_bytes());
        let partial_value = field_add(field_mul(share_value, nonce), msg_scalar);
        let partial = PartialSignature { index: share_index, node_id, nonce_commitment: commit, partial_value };
        let session = g.sessions.get_mut(session_id).unwrap();
        if session.partials.iter().any(|p| p.index == partial.index) {
            return Err(DomainError::NonceReuse("duplicate partial for share index".into()));
        }
        session.partials.push(partial.clone());
        Ok(partial)
    }

    /// Collects partials from the first `online` shares in the lab-only share list.
    ///
    /// This bypasses remote participant execution and must not be used by a
    /// distributed production signer. It requires an existing session and a
    /// threshold-satisfying online count.
    pub fn lab_collect_partials_from_all(
        &self,
        session_id: &str,
        online: usize,
    ) -> Result<Vec<PartialSignature>, DomainError> {
        let mut g = self.inner.lock().expect("threshold");
        if online < g.group.t {
            return Err(DomainError::FailStop { online, need: g.group.t });
        }
        let message_hash = g
            .sessions
            .get(session_id)
            .ok_or_else(|| DomainError::UnknownProposal(session_id.to_string()))?
            .message_hash
            .clone();
        let take_n = online.min(g.group.n);
        let share_snapshot: Vec<KeyShare> = g.lab_all_shares.iter().take(take_n).cloned().collect();
        let mut out = Vec::new();
        for share in share_snapshot {
            let nonce = derive_nonce(session_id, &message_hash, share.value);
            let commit = nonce_commitment(nonce, share.index.0);
            g.used_nonce_commitments.insert(commit.clone());
            let msg_scalar = crate::domain::lab_random_u64(message_hash.as_bytes());
            let partial_value = field_add(field_mul(share.value, nonce), msg_scalar);
            out.push(PartialSignature {
                index: share.index.clone(),
                node_id: share.node_id.clone(),
                nonce_commitment: commit,
                partial_value,
            });
        }
        let session = g.sessions.get_mut(session_id).unwrap();
        for p in &out {
            if !session.bound_nonce_commitments.contains(&p.nonce_commitment) {
                session.bound_nonce_commitments.push(p.nonce_commitment.clone());
            }
        }
        session.partials = out.clone();
        session.phase = SigningPhase::NoncesBound;
        Ok(out)
    }

    /// Interpolates the first threshold number of session partials and consumes the session.
    ///
    /// Fails when online participants or collected partials do not meet the
    /// group threshold. On success the session is marked consumed and cannot
    /// be combined again.
    pub fn combine(&self, session_id: &str, online: usize) -> Result<CombinedSignature, DomainError> {
        let mut g = self.inner.lock().expect("threshold");
        let need = g.group.t;
        if online < need {
            return Err(DomainError::FailStop { online, need });
        }
        if g.consumed_sessions.contains(session_id) {
            return Err(DomainError::SessionConsumed(session_id.to_string()));
        }
        let partials = g
            .sessions
            .get(session_id)
            .ok_or_else(|| DomainError::UnknownProposal(session_id.to_string()))?
            .partials
            .clone();
        let message_hash = g.sessions.get(session_id).unwrap().message_hash.clone();
        if partials.len() < need {
            return Err(DomainError::QuorumNotMet { have: partials.len(), need });
        }
        let points: Vec<(u8, u64)> = partials.iter().take(need).map(|p| (p.index.0, p.partial_value)).collect();
        let value = interpolate_secret(&points)?;
        let participants: Vec<u8> = points.iter().map(|(i, _)| *i).collect();
        let session = g.sessions.get_mut(session_id).unwrap();
        session.phase = SigningPhase::Consumed;
        session.partials.clear();
        g.consumed_sessions.insert(session_id.to_string());
        Ok(CombinedSignature { session_id: session_id.to_string(), message_hash, value, participants })
    }
}

impl SigningPort for ThresholdVaultState {
    /// Delegates session creation to the in-memory signing state.
    fn begin_session(
        &self,
        session_id: &str,
        message_hash: &str,
        online: usize,
    ) -> Result<SigningSession, DomainError> {
        ThresholdVaultState::begin_session(self, session_id, message_hash, online)
    }

    /// Collects all lab partials, discarding the returned partial list.
    fn collect_lab_partials(&self, session_id: &str, online: usize) -> Result<(), DomainError> {
        self.lab_collect_partials_from_all(session_id, online).map(|_| ())
    }

    /// Delegates aggregation and session consumption to the in-memory state.
    fn combine(&self, session_id: &str, online: usize) -> Result<CombinedSignature, DomainError> {
        ThresholdVaultState::combine(self, session_id, online)
    }
}
