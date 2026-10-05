use std::sync::Arc;

use crate::SigningPort;
use vault_domain::{CombinedSignature, DomainError, SigningSession};

/// Reports how many vaults are considered online for fail-stop checks.
pub trait OnlineStatusPort: Send + Sync {
    /// Returns the number of vault participants currently counted as online.
    fn online_count(&self) -> usize;
}

/// Application use case for opening signing sessions and running lab quorum signing.
pub struct SignMessage {
    signer: Arc<dyn SigningPort>,
    online: Arc<dyn OnlineStatusPort>,
}

impl SignMessage {
    /// Creates the use case with a signing port and online-status provider.
    pub fn new(signer: Arc<dyn SigningPort>, online: Arc<dyn OnlineStatusPort>) -> Self {
        Self { signer, online }
    }

    /// Starts a signing session using the online count observed at this call.
    pub fn begin(&self, session_id: &str, message_hash: &str) -> Result<SigningSession, DomainError> {
        self.signer.begin_session(session_id, message_hash, self.online.online_count())
    }

    /// Runs begin, lab partial collection, and combination using one online-count snapshot.
    ///
    /// This convenience workflow is intended for lab signing; production signing
    /// should use the distributed signing protocol rather than local partial collection.
    pub fn run_lab_quorum_sign(&self, session_id: &str, message_hash: &str) -> Result<CombinedSignature, DomainError> {
        let online = self.online.online_count();
        self.signer.begin_session(session_id, message_hash, online)?;
        self.signer.collect_lab_partials(session_id, online)?;
        self.signer.combine(session_id, online)
    }
}

/// Fixed online-vault count for deterministic tests and lab configuration.
pub struct StaticOnlineCount {
    /// Number returned for every online-count query.
    pub count: usize,
}

impl OnlineStatusPort for StaticOnlineCount {
    /// Returns the configured fixed count.
    fn online_count(&self) -> usize {
        self.count
    }
}

/// Lab partition / fail-stop harness: online count can change at runtime.
pub struct MutableOnlineCount {
    count: std::sync::Mutex<usize>,
}

impl MutableOnlineCount {
    /// Creates a mutable counter initialized to `count`.
    pub fn new(count: usize) -> Self {
        Self { count: std::sync::Mutex::new(count) }
    }

    /// Replaces the count used by subsequent queries.
    pub fn set(&self, count: usize) {
        *self.count.lock().expect("online lock") = count;
    }
}

impl OnlineStatusPort for MutableOnlineCount {
    /// Returns the current count under the mutex.
    fn online_count(&self) -> usize {
        *self.count.lock().expect("online lock")
    }
}
