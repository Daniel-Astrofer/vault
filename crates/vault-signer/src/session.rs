//! Signing session management.
//!
//! Manages the lifecycle of individual FROST signing sessions, tracking
//! commitments, signature shares, and session state.

use std::collections::{BTreeMap, BTreeSet};

use frost_secp256k1 as frost;
use frost_secp256k1::Identifier;
use serde::{Deserialize, Serialize};

use crate::signer::SignerError;

/// Unique session identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    /// Create a new random session ID.
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let random: u64 = rand::random();
        Self(format!("session-{ts:x}-{random:x}"))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Current state of a signing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, waiting for commitments.
    AwaitingCommitments,
    /// Commitments received, waiting for signature shares.
    AwaitingSignatureShares,
    /// All shares collected, signature ready.
    Complete,
    /// Session failed or expired.
    Failed(String),
}

/// A signing session tracking all participants' contributions.
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// Unique session identifier.
    pub id: SessionId,
    /// Message to be signed.
    pub message: Vec<u8>,
    /// Current session state.
    pub state: SessionState,
    /// Commitments received from each participant.
    pub commitments: BTreeMap<Identifier, frost::round1::SigningCommitments>,
    /// Signature shares received from each participant.
    pub signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
    /// Identifiers of all expected participants.
    pub expected_participants: Vec<Identifier>,
    /// Minimum signers required (threshold).
    pub min_signers: usize,
    /// Timestamp when session was created (nanos since epoch).
    pub created_at: u128,
}

impl SigningSession {
    /// Create a new signing session.
    fn new(message: Vec<u8>, expected_participants: Vec<Identifier>, min_signers: usize) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);

        Self {
            id: SessionId::new(),
            message,
            state: SessionState::AwaitingCommitments,
            commitments: BTreeMap::new(),
            signature_shares: BTreeMap::new(),
            expected_participants,
            min_signers,
            created_at: ts,
        }
    }

    /// Add a participant's commitments.
    pub fn add_commitments(
        &mut self,
        identifier: Identifier,
        commitments: frost::round1::SigningCommitments,
    ) -> Result<(), SignerError> {
        if self.state != SessionState::AwaitingCommitments {
            return Err(SignerError::SessionAlreadyCompleted);
        }
        if !self.expected_participants.contains(&identifier) {
            return Err(SignerError::UnexpectedParticipant);
        }
        if self.commitments.contains_key(&identifier) {
            return Err(SignerError::DuplicateCommitment);
        }
        self.commitments.insert(identifier, commitments);

        // If we have enough commitments, transition to awaiting signature shares
        if self.commitments.len() >= self.min_signers {
            self.state = SessionState::AwaitingSignatureShares;
        }

        Ok(())
    }

    /// Add a participant's signature share.
    pub fn add_signature_share(
        &mut self,
        identifier: Identifier,
        share: frost::round2::SignatureShare,
    ) -> Result<(), SignerError> {
        if self.state == SessionState::Complete {
            return Err(SignerError::SessionAlreadyCompleted);
        }
        if self.state != SessionState::AwaitingSignatureShares {
            return Err(SignerError::RoundError("session is not accepting signature shares".into()));
        }
        if !self.expected_participants.contains(&identifier) || !self.commitments.contains_key(&identifier) {
            return Err(SignerError::UnexpectedParticipant);
        }
        if self.signature_shares.contains_key(&identifier) {
            return Err(SignerError::DuplicateSignatureShare);
        }
        self.signature_shares.insert(identifier, share);

        // If we have enough shares, mark as complete
        if self.signature_shares.len() >= self.min_signers {
            self.state = SessionState::Complete;
        }

        Ok(())
    }
}

/// Manages multiple signing sessions concurrently.
pub struct SigningSessionManager {
    sessions: BTreeMap<SessionId, SigningSession>,
    /// Maximum number of concurrent sessions.
    max_sessions: usize,
}

impl SigningSessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize) -> Self {
        Self { sessions: BTreeMap::new(), max_sessions }
    }

    /// Create a new signing session.
    pub fn create_session(
        &mut self,
        message: Vec<u8>,
        expected_participants: Vec<Identifier>,
        min_signers: usize,
    ) -> Result<SessionId, SignerError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SignerError::Internal("max concurrent sessions reached".into()));
        }
        if message.is_empty() {
            return Err(SignerError::InvalidSessionConfiguration("message cannot be empty".into()));
        }
        let unique_participants: BTreeSet<_> = expected_participants.iter().copied().collect();
        if unique_participants.len() != expected_participants.len() {
            return Err(SignerError::InvalidSessionConfiguration("participant identifiers must be unique".into()));
        }
        if min_signers == 0 || min_signers > expected_participants.len() {
            return Err(SignerError::InvalidSessionConfiguration(format!(
                "threshold {min_signers} is invalid for {} participants",
                expected_participants.len()
            )));
        }

        let session = SigningSession::new(message, expected_participants, min_signers);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        Ok(id)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: &SessionId) -> Result<&SigningSession, SignerError> {
        self.sessions.get(id).ok_or(SignerError::SessionNotFound)
    }

    /// Get a mutable session by ID.
    pub fn get_session_mut(&mut self, id: &SessionId) -> Result<&mut SigningSession, SignerError> {
        self.sessions.get_mut(id).ok_or(SignerError::SessionNotFound)
    }

    /// Remove a completed or failed session.
    pub fn remove_session(&mut self, id: &SessionId) -> Option<SigningSession> {
        self.sessions.remove(id)
    }

    /// Get the number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Clean up expired sessions (older than the given duration in seconds).
    pub fn cleanup_expired(&mut self, max_age_secs: u64) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);

        self.sessions.retain(|_, session| {
            let age_ns = now.saturating_sub(session.created_at);
            age_ns < (max_age_secs as u128) * 1_000_000_000
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_manage_session() {
        let mut manager = SigningSessionManager::new(10);

        let p1 = Identifier::try_from(1u16).unwrap();
        let p2 = Identifier::try_from(2u16).unwrap();
        let p3 = Identifier::try_from(3u16).unwrap();
        let id1 = manager.create_session(b"message-1".to_vec(), vec![p1, p2], 2).unwrap();

        let session = manager.get_session(&id1).unwrap();
        assert_eq!(session.state, SessionState::AwaitingCommitments);

        let id2 = manager.create_session(b"message-2".to_vec(), vec![p1, p2, p3], 3).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(manager.active_count(), 2);
    }

    #[test]
    fn session_commitments_and_shares() {
        let mut manager = SigningSessionManager::new(10);

        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let participants = vec![id1, id2];

        let session_id = manager.create_session(b"test message".to_vec(), participants.clone(), 2).unwrap();

        // Add commitments
        {
            let session = manager.get_session_mut(&session_id).unwrap();
            let mut rng = rand::rngs::OsRng;
            let (secret_shares, _) =
                frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, &mut rng).unwrap();
            let key_package1 = frost::keys::KeyPackage::try_from(secret_shares[&id1].clone()).unwrap();
            let key_package2 = frost::keys::KeyPackage::try_from(secret_shares[&id2].clone()).unwrap();
            let (_, commitments1) = frost::round1::commit(key_package1.signing_share(), &mut rng);
            let (_, commitments2) = frost::round1::commit(key_package2.signing_share(), &mut rng);

            session.add_commitments(id1, commitments1).unwrap();
            session.add_commitments(id2, commitments2).unwrap();
            assert_eq!(session.state, SessionState::AwaitingSignatureShares);
        }

        // Remove session
        let removed = manager.remove_session(&session_id);
        assert!(removed.is_some());
        assert!(manager.get_session(&session_id).is_err());
    }

    #[test]
    fn invalid_participant_sets_fail_closed() {
        let mut manager = SigningSessionManager::new(10);
        let id1 = Identifier::try_from(1u16).unwrap();

        assert!(matches!(
            manager.create_session(b"message".to_vec(), vec![id1, id1], 2),
            Err(SignerError::InvalidSessionConfiguration(_))
        ));
        assert!(matches!(
            manager.create_session(b"message".to_vec(), vec![id1], 2),
            Err(SignerError::InvalidSessionConfiguration(_))
        ));
    }
}
