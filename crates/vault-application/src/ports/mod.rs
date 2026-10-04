//! Outbound interfaces used by application use cases to reach infrastructure.
//!
//! Implementations live in adapters; these traits keep orchestration independent
//! from storage, transport, hardware attestation, and cryptographic providers.
use vault_domain::{
    AllowlistEntry, AttestationMode, AttestationQuote, BucketKind, BucketPolicy, CombinedSignature, Constitution,
    ContentHash, DayEpoch, DomainError, EconomyState, Epoch, EpochAdvanceProposal, GovernanceAccrual,
    GovernanceJobKind, GovernanceRewardConfig, HybridContext, HybridEnvelope, LedgerEntry, Measurement, MinerOperator,
    MinerPayoutShare, NodeId, PeerInfo, ProfitSplitAccrual, ProfitSplits, ReleaseCandidate, ReleasePolicy,
    ResharePolicy, SigningSession,
};

/// Mechanism-agnostic boundary for a signing session. FROST, hardware-backed
/// signing, and lab doubles implement this port outside the application layer.
pub trait SigningPort: Send + Sync {
    /// Create or retrieve a session bound to the message digest and available participant count.
    fn begin_session(&self, session_id: &str, message_hash: &str, online: usize)
        -> Result<SigningSession, DomainError>;
    /// Collect lab-mode partials after checking the online participant count.
    fn collect_lab_partials(&self, session_id: &str, online: usize) -> Result<(), DomainError>;
    /// Combine collected partials into the session's threshold signature.
    fn combine(&self, session_id: &str, online: usize) -> Result<CombinedSignature, DomainError>;
}

/// Read, update, and probe the peer directory used by application services.
pub trait PeerDirectoryPort: Send + Sync {
    /// Return the currently registered peer records.
    fn list_peers(&self) -> Result<Vec<PeerInfo>, DomainError>;
    /// Insert or replace a peer record keyed by its node identifier.
    fn upsert_peer(&self, peer: PeerInfo) -> Result<(), DomainError>;
    /// Probe a peer by identifier and report transport or domain failures.
    fn ping(&self, peer_id: &NodeId) -> Result<(), DomainError>;
}

/// Issue and verify platform attestation quotes without binding the use case to a TEE vendor.
pub trait AttestationPort: Send + Sync {
    /// Report the attestation mode implemented by this adapter.
    fn mode(&self) -> AttestationMode;
    /// Produce evidence for the requested software or hardware measurement.
    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError>;
    /// Verify the evidence and its measurement according to adapter policy.
    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError>;
}

/// Supplies wall-clock time as Unix seconds to deterministic application policies.
pub trait ClockPort: Send + Sync {
    /// Return the current Unix timestamp in seconds.
    fn unix_now_secs(&self) -> u64;
}

/// Permissioned append-only governance ledger.
pub trait LedgerPort: Send + Sync {
    /// Load the active security/economic constitution.
    fn constitution(&self) -> Result<Constitution, DomainError>;
    /// Load the current membership epoch.
    fn epoch(&self) -> Result<Epoch, DomainError>;
    /// Persist a new current epoch after governance validation.
    fn set_epoch(&self, epoch: Epoch) -> Result<(), DomainError>;
    /// Return the newest committed entry, or `None` for an empty ledger.
    fn head(&self) -> Result<Option<LedgerEntry>, DomainError>;
    /// Return committed entries in ledger order.
    fn entries(&self) -> Result<Vec<LedgerEntry>, DomainError>;
    /// Append an entry while enforcing the adapter's chain and writer constraints.
    fn append(&self, entry: LedgerEntry) -> Result<(), DomainError>;
    /// Insert a new epoch proposal, rejecting identifier conflicts as appropriate.
    fn put_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError>;
    /// Load a proposal by id or return a domain error when it is absent.
    fn get_proposal(&self, id: &str) -> Result<EpochAdvanceProposal, DomainError>;
    /// Replace the stored state of an existing proposal.
    fn save_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError>;
}

/// Content-addressed blob store for Hs/Hb artifacts.
pub trait BlobStorePort: Send + Sync {
    /// Store bytes under their expected content hash.
    fn put(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError>;
    /// Retrieve bytes by content hash or return an error if they are unavailable.
    fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, DomainError>;
}

/// Release candidate + allowlist state shared across vaults in the lab mesh.
pub trait ReleaseStorePort: Send + Sync {
    /// Load the release quorum and timelock policy.
    fn policy(&self) -> Result<ReleasePolicy, DomainError>;
    /// Insert a new release candidate.
    fn put_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError>;
    /// Load a candidate by id or report that it is unknown.
    fn get_candidate(&self, id: &str) -> Result<ReleaseCandidate, DomainError>;
    /// Persist updates to an existing release candidate.
    fn save_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError>;
    /// Add an activated release to the executable artifact allowlist.
    fn put_allowlist(&self, entry: AllowlistEntry) -> Result<(), DomainError>;
    /// Return all active release allowlist entries.
    fn allowlist(&self) -> Result<Vec<AllowlistEntry>, DomainError>;
    /// Check whether a binary hash is admitted by any release entry.
    fn is_allowlisted_hb(&self, hb: &ContentHash) -> Result<bool, DomainError>;
}

/// Per-bucket spend tracking + destination policies (enclave side).
pub trait BucketLedgerPort: Send + Sync {
    /// Load destination and spend-limit policy for a bucket.
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError>;
    /// Return the amount already charged to a bucket during the current day.
    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError>;
    /// Record an authorized amount against a bucket's daily spend total.
    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError>;
    /// Return whether an intent identifier has already been durably consumed.
    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError>;
    /// Mark an intent identifier consumed to prevent replay.
    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError>;
    /// Atomic check-and-insert. Returns [`DomainError::IntentReplay`] if already consumed.
    fn try_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        if self.is_consumed(intent_id)? {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        self.mark_consumed(intent_id)
    }
    /// Soft-reserve Intent (two-phase): validate + hold caps without durable burn.
    /// Default: same as authorize_spend_and_consume (lab in-memory).
    fn reserve_spend(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        self.authorize_spend_and_consume(intent_id, kind, amount_sats, validate)
    }
    /// Promote soft reservation → durable consume (mesh quorum when available).
    fn commit_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        self.try_consume(intent_id)
    }
    /// Release soft reservation and roll back tentative spend (sign failure path).
    fn release_reservation(&self, intent_id: &str, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        let _ = (intent_id, kind, amount_sats);
        Ok(())
    }
    /// Soft reservation present (not yet committed / released).
    fn has_reservation(&self, intent_id: &str) -> Result<bool, DomainError> {
        let _ = intent_id;
        Ok(false)
    }
    /// Returns count of currently consumed intents.
    fn count_pending_intents(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    /// Validate + record spend + consume under one critical section (TOCTOU-safe).
    /// Prefer [`Self::reserve_spend`] + [`Self::commit_consume`] on sign paths (High #9).
    fn authorize_spend_and_consume(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        if self.is_consumed(intent_id)? {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        let policy = self.policy(kind)?;
        let spent = self.spent_today(kind)?;
        validate(&policy, spent)?;
        self.record_spend(kind, amount_sats)?;
        self.try_consume(intent_id)?;
        Ok(())
    }
}

/// Miner reward pool + eligibility (F9). Vaults never invent payout destinations.
pub trait EconomyPort: Send + Sync {
    /// Return a consistent snapshot of reward pools, operators, and policy.
    fn snapshot(&self) -> Result<EconomyState, DomainError>;
    /// Register or update an operator used in eligibility and payout calculations.
    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError>;
    /// Accrue profit using the legacy miner reward percentage and return the miner allocation.
    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError>;
    /// Allocate profit across all configured child pools and return the accounting result.
    fn accrue_profit_splits(&self, profit_sats: u64, splits: &ProfitSplits) -> Result<ProfitSplitAccrual, DomainError>;
    /// Accrue a governance bounty and credits for eligible participants.
    fn accrue_governance_job(
        &self,
        job: GovernanceJobKind,
        participants: &[NodeId],
        config: &GovernanceRewardConfig,
    ) -> Result<GovernanceAccrual, DomainError>;
    /// Split a requested amount equally among eligible operators for bank-issued intents.
    fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<MinerPayoutShare>, DomainError>;
    /// Debit an already authorized amount from the miner pool.
    fn debit_pool(&self, amount: u64) -> Result<(), DomainError>;
    /// Persist the timestamp and optional epoch for payout-cadence enforcement.
    fn record_miner_payout(&self, at_secs: u64, epoch: Option<u64>) -> Result<(), DomainError>;
}

/// DKG / keygen port. Lab may use dealer behind `dealer_lab`; Gate uses
/// distributed multi-round FROST (`VAULT_DKG_MODE=distributed`, no dealer).
pub trait DkgPort: Send + Sync {
    /// Return the configured key-generation mode identifier.
    fn mode_name(&self) -> &'static str;
    /// Indicate whether this implementation uses a single dealer rather than distributed DKG.
    fn is_dealer(&self) -> bool;
}

/// Persist / load sealed FROST share material.
pub trait ShareStorePort: Send + Sync {
    /// Return the backend identifier describing how shares are sealed at rest.
    fn store_kind(&self) -> &'static str;
    /// Seal and persist plaintext share material under its identifier.
    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError>;
    /// Load and unseal share material by identifier.
    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError>;
}

/// Auth between kfe ↔ vault (lab static token vs prod mTLS).
pub trait VaultAuthPort: Send + Sync {
    /// Return the adapter's authentication mode label, such as token or mTLS.
    fn mode_name(&self) -> &'static str;
    /// Indicate whether this adapter relies on a static bearer token.
    fn is_static_token(&self) -> bool;
    /// Validate the supplied authentication header for ordinary protected operations.
    fn authorize(&self, token_header: Option<&str>) -> Result<(), DomainError>;
    /// Treasury signing (`/v1/sign`, `/v1/bitcoin/sign-*`). Lab static token may sign
    /// only in lab ceremony; staging/prod require mTLS (no signing on lab token).
    fn authorize_treasury_sign(&self) -> Result<(), DomainError> {
        Ok(())
    }
    /// Manual reshare trigger (`POST /v1/reshare/trigger`) — lab or explicit allow (#30).
    fn authorize_reshare_trigger(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Anti-nonce session ledger: one signing_session_id → at most one nonce package, survives restart.
pub trait AntiNoncePort: Send + Sync {
    /// Claim for signing: durable local burn + quorum peer prepare (fail-closed).
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError>;
    /// Check whether a signing session has already been consumed.
    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError>;
    /// Peer / HTTP prepare: soft TTL reservation (High #8). Returns `true` if already present.
    fn prepare_remote(&self, session_id: &str) -> Result<bool, DomainError>;
    /// Durable peer prepare (claim fan-out). Default: same as soft.
    fn prepare_remote_durable(&self, session_id: &str) -> Result<bool, DomainError> {
        self.prepare_remote(session_id)
    }
    /// Soft prepare bound to an Intent id (session must equal intent or `intent:…`).
    fn prepare_remote_bound(&self, session_id: &str, intent_id: &str) -> Result<bool, DomainError> {
        bind_session_to_intent(session_id, intent_id)?;
        self.prepare_remote(session_id)
    }
    /// Legacy alias: durable observe without distinguishing already_seen.
    fn observe_remote(&self, session_id: &str) -> Result<(), DomainError> {
        self.prepare_remote(session_id).map(|_| ())
    }
}

/// Session id must equal intent_id or start with `intent_id:`.
pub fn bind_session_to_intent(session_id: &str, intent_id: &str) -> Result<(), DomainError> {
    let intent_id = intent_id.trim();
    let session_id = session_id.trim();
    if intent_id.is_empty() || session_id.is_empty() {
        return Err(DomainError::NonceReuse("session_id and intent_id required for anti-nonce prepare".into()));
    }
    if session_id == intent_id || session_id.starts_with(&format!("{intent_id}:")) {
        return Ok(());
    }
    Err(DomainError::NonceReuse(format!("session_id {session_id} not bound to intent {intent_id}")))
}

/// Hook invoked after a quorum day_epoch advance (reshare policy).
pub trait ReshareHookPort: Send + Sync {
    /// Return whether key-share refresh is daily or manually triggered.
    fn policy(&self) -> ResharePolicy {
        ResharePolicy::Manual
    }
    /// Called after governance quorum advances the day_epoch.
    /// `participants` are vaults that voted for the target day (eligibility hook).
    fn on_day_advance(&self, from: &DayEpoch, to: &DayEpoch, participants: &[NodeId]) -> Result<(), DomainError>;
    /// Explicit FROST reshare (`VAULT_RESHARE_POLICY=manual` or ops trigger).
    fn trigger_manual(&self, reason: &str) -> Result<(), DomainError> {
        let _ = reason;
        Ok(())
    }
}

/// Daily rotation: advance/bind day_epoch; Gate path uses quorum + reshare hook.
pub trait DailyRotationPort: Send + Sync {
    /// Read the day epoch currently bound to signing and governance state.
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError>;
    /// Advance the day epoch through the implementation's governance flow.
    fn advance(&self) -> Result<DayEpoch, DomainError>;
    /// Reject an operation whose bound day differs from the current epoch.
    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError>;
    /// Record a peer vote to advance toward `target` (governance quorum).
    fn record_vote(&self, _voter: &str, _target: &DayEpoch) -> Result<(), DomainError> {
        Ok(())
    }
}

/// CHANNELS → LND lightning channel management (Item 4.7).
///
/// Real implementation will call LND REST API for channel lifecycle operations.
/// Fail-closed: if the mesh cannot produce a valid funding txid, the Intent is rejected.
pub trait ChannelInjectPort: Send + Sync {
    /// Open a Lightning channel to `lnd_peer_pubkey` with `funding_amount_sats`.
    /// Returns the channel point (txid:vout) on success.
    fn open_channel(
        &self,
        lnd_peer_pubkey: &str,
        funding_amount_sats: u64,
        push_sats: u64,
    ) -> Result<String, DomainError>;

    /// Close a channel specified by `channel_point` (txid:vout).
    /// If `force` is true, force-close the channel.
    /// Returns the closing txid.
    fn close_channel(&self, channel_point: &str, force: bool) -> Result<String, DomainError>;
}

/// Hybrid envelope: X25519 + ML-KEM-768 + AES-256-GCM with HKDF-SHA-384 combiner.
pub trait HybridEnvelopePort: Send + Sync {
    /// Encrypt plaintext into a hybrid envelope bound to the supplied identities and transcript.
    fn seal(&self, plaintext: &[u8], context: &HybridContext) -> Result<HybridEnvelope, DomainError>;
    /// Authenticate and decrypt an envelope only when its context matches the expected peer state.
    fn open(&self, envelope: &HybridEnvelope, context: &HybridContext) -> Result<Vec<u8>, DomainError>;
}

/// Key lifecycle state machine for identity, transport, and audit keys.
pub trait KeyLifecyclePort: Send + Sync {
    /// Create and persist initial identity, transport, and audit keys for a node.
    fn genesis(&self, node_id: &NodeId) -> Result<(), DomainError>;
    /// Replace identity signing keys while preserving lifecycle/audit requirements.
    fn rotate_identity(&self, node_id: &NodeId) -> Result<(), DomainError>;
    /// Replace transport keys used for peer communication.
    fn rotate_transport(&self, node_id: &NodeId) -> Result<(), DomainError>;
    /// Revoke a key identifier belonging to the specified node.
    fn revoke(&self, node_id: &NodeId, key_id: &str) -> Result<(), DomainError>;
    /// Return whether the specified key has passed its expiration time.
    fn is_expired(&self, node_id: &NodeId, key_id: &str) -> Result<bool, DomainError>;
}
