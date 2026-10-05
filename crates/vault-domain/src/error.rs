use std::fmt;

/// Failure reported by a Vault domain operation.
///
/// Variants preserve the domain condition and relevant identifiers or
/// thresholds so application and adapter layers can decide whether to reject,
/// retry, or surface the failure without parsing display text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A node identifier is empty or violates the domain's identifier rules.
    InvalidNodeId,
    /// The requested peer identifier is not present in the active membership.
    PeerNotFound(String),
    /// A simulated attestation mode was requested where production policy forbids it.
    SimAttestationForbidden,
    /// The supplied hardware attestation quote failed validation; contains the reason.
    AttestationRejected(String),
    /// The measured platform state does not match the required attestation policy.
    MeasurementMismatch,
    /// The supplied network constitution violates a required domain invariant.
    InvalidConstitution(String),
    /// A ledger write conflicts with the current state or an existing entry.
    LedgerConflict(String),
    /// The identified principal is not authorized to write to the ledger.
    UnauthorizedWriter(String),
    /// The available participants do not meet the threshold required for an operation.
    QuorumNotMet {
        /// Number of currently available or valid participants.
        have: usize,
        /// Minimum number of participants required by the configured quorum.
        need: usize,
    },
    /// The referenced proposal identifier does not exist.
    UnknownProposal(String),
    /// The operation's epoch differs from the epoch expected by current state.
    EpochMismatch {
        /// Epoch required by the authoritative domain state.
        expected: u64,
        /// Epoch supplied by the caller or observed in the request.
        got: u64,
    },
    /// The proposal has already transitioned to a state that disallows changes.
    ProposalClosed(String),
    /// A threshold-signing share failed validation; contains the validation reason.
    InvalidShare(String),
    /// Threshold arithmetic or protocol processing failed with the given reason.
    ThresholdError(String),
    /// A one-time signing nonce was reused, which could expose key material.
    NonceReuse(String),
    /// Too few signing participants remain to safely continue the protocol.
    FailStop {
        /// Number of participants still online.
        online: usize,
        /// Minimum participants needed to continue safely.
        need: usize,
    },
    /// The signing session has already been consumed and cannot be used again.
    SessionConsumed(String),
    /// A signing operation was attempted in a phase that does not permit it.
    BadSigningPhase {
        /// Identifier of the affected signing session.
        session_id: String,
        /// Current or requested phase that caused rejection.
        phase: String,
    },
    /// Release data failed structural or policy validation.
    InvalidRelease(String),
    /// The requested content-addressed blob is not available.
    UnknownBlob(String),
    /// The requested release identifier is not present in domain state.
    UnknownRelease(String),
    /// A rebuilt artifact differs from the expected value or digest.
    RebuildMismatch {
        /// Expected artifact identity or digest.
        expected: String,
        /// Actual artifact identity or digest produced by rebuilding.
        got: String,
    },
    /// A release precondition evaluated to false; contains the failed predicate.
    ReleasePredicate(String),
    /// The release's required delay has not yet elapsed.
    TimelockNotElapsed {
        /// Elapsed age of the release in seconds.
        age_secs: u64,
        /// Minimum required age in seconds.
        need_secs: u64,
    },
    /// The release is closed and cannot be advanced or consumed.
    ReleaseClosed(String),
    /// The artifact hash is absent from the release allowlist.
    NotAllowlisted(String),
    /// The requested accounting bucket is unknown or invalid.
    InvalidBucket(String),
    /// An intent failed validation; contains the reason for rejection.
    InvalidIntent(String),
    /// The requested amount exceeds the configured cap for its scope.
    CapExceeded {
        /// Amount requested by the intent.
        amount: u64,
        /// Maximum amount allowed by the applicable policy.
        cap: u64,
        /// Name of the policy scope whose cap was exceeded.
        scope: String,
    },
    /// The destination is excluded by the applicable payment policy.
    DestinationNotAllowed(String),
    /// The intent identifier was already processed and is being replayed.
    IntentReplay(String),
    /// Soft Intent / anti-nonce reservation expired or missing before commit.
    ReservationMissing(String),
    /// An operational bucket attempted to debit the protected USERS omnibus.
    UsersOmnibusProtected,
    /// A lab-only feature flag was used in a non-lab execution context.
    LabFlagForbidden(String),
    /// The request failed a domain-level acceptance rule.
    RequestRejected(String),
    /// No registered miner satisfies the payout eligibility rules.
    NoEligibleMiners,
    /// The miner pool balance is below the requested payout total.
    InsufficientMinerPool {
        /// Funds currently available in the miner pool.
        have: u64,
        /// Funds required to satisfy the payout.
        want: u64,
    },
    /// A miner attempted to direct its own payout to a forbidden destination.
    MinerSelfPayForbidden,
    /// Authentication or authorization was rejected; contains the reason.
    AuthRejected(String),
    /// Storing the supplied key share is forbidden by the active storage policy.
    ShareStoreForbidden(String),
    /// The requested dealer or distributed key generation action is forbidden.
    DealerForbidden(String),
    /// A trusted execution environment seal is required but unavailable or invalid.
    TeeRequired(String),
    /// Domestic TPM seal required / unavailable (honest: TPM ≠ SEV).
    TpmRequired(String),
    /// The request's Bitcoin network differs from the configured network.
    BitcoinNetworkMismatch(String),
    /// The supplied day epoch is stale compared with the required current epoch.
    DayEpochStale {
        /// Epoch observed in the supplied request or state.
        have: String,
        /// Minimum/current epoch required by the domain policy.
        need: String,
    },
    /// A production readiness or security gate rejected the operation.
    ProductionGate(String),
}

/// Formats the domain error as a concise diagnostic suitable for logs and API mapping.
impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId => write!(f, "invalid node id"),
            Self::PeerNotFound(id) => write!(f, "peer not found: {id}"),
            Self::SimAttestationForbidden => {
                write!(f, "attestation mode sim is forbidden in production builds")
            }
            Self::AttestationRejected(reason) => write!(f, "attestation quote rejected: {reason}"),
            Self::MeasurementMismatch => write!(f, "measurement mismatch"),
            Self::InvalidConstitution(r) => write!(f, "invalid constitution: {r}"),
            Self::LedgerConflict(r) => write!(f, "ledger conflict: {r}"),
            Self::UnauthorizedWriter(id) => write!(f, "unauthorized ledger writer: {id}"),
            Self::QuorumNotMet { have, need } => {
                write!(f, "quorum not met: have {have}, need {need}")
            }
            Self::UnknownProposal(id) => write!(f, "unknown proposal: {id}"),
            Self::EpochMismatch { expected, got } => {
                write!(f, "epoch mismatch: expected {expected}, got {got}")
            }
            Self::ProposalClosed(id) => write!(f, "proposal already closed: {id}"),
            Self::InvalidShare(r) => write!(f, "invalid share: {r}"),
            Self::ThresholdError(r) => write!(f, "threshold error: {r}"),
            Self::NonceReuse(r) => write!(f, "nonce reuse: {r}"),
            Self::FailStop { online, need } => {
                write!(f, "fail-stop: online {online} < need {need}")
            }
            Self::SessionConsumed(id) => write!(f, "signing session consumed: {id}"),
            Self::BadSigningPhase { session_id, phase } => {
                write!(f, "bad signing phase for {session_id}: {phase}")
            }
            Self::InvalidRelease(r) => write!(f, "invalid release: {r}"),
            Self::UnknownBlob(h) => write!(f, "unknown blob: {h}"),
            Self::UnknownRelease(id) => write!(f, "unknown release: {id}"),
            Self::RebuildMismatch { expected, got } => {
                write!(f, "rebuild mismatch: expected {expected}, got {got}")
            }
            Self::ReleasePredicate(r) => write!(f, "release predicate failed: {r}"),
            Self::TimelockNotElapsed { age_secs, need_secs } => {
                write!(f, "timelock not elapsed: age {age_secs} < need {need_secs}")
            }
            Self::ReleaseClosed(id) => write!(f, "release closed: {id}"),
            Self::NotAllowlisted(h) => write!(f, "artifact not allowlisted: {h}"),
            Self::InvalidBucket(b) => write!(f, "invalid bucket: {b}"),
            Self::InvalidIntent(r) => write!(f, "invalid intent: {r}"),
            Self::CapExceeded { amount, cap, scope } => {
                write!(f, "cap exceeded ({scope}): amount {amount} > cap {cap}")
            }
            Self::DestinationNotAllowed(d) => write!(f, "destination not allowed: {d}"),
            Self::IntentReplay(id) => write!(f, "intent replay: {id}"),
            Self::ReservationMissing(id) => write!(f, "reservation missing or expired: {id}"),
            Self::UsersOmnibusProtected => {
                write!(f, "USERS omnibus protected: operational bucket cannot debit USERS")
            }
            Self::LabFlagForbidden(flag) => {
                write!(f, "lab flag forbidden outside lab: {flag}")
            }
            Self::RequestRejected(r) => write!(f, "request rejected: {r}"),
            Self::NoEligibleMiners => write!(f, "no eligible miners for payout"),
            Self::InsufficientMinerPool { have, want } => {
                write!(f, "insufficient miner pool: have {have}, want {want}")
            }
            Self::MinerSelfPayForbidden => {
                write!(f, "miner payout forbidden: destination not an eligible registered operator (no self-pay)")
            }
            Self::AuthRejected(r) => write!(f, "auth rejected: {r}"),
            Self::ShareStoreForbidden(r) => write!(f, "share store forbidden: {r}"),
            Self::DealerForbidden(r) => write!(f, "dealer DKG forbidden: {r}"),
            Self::TeeRequired(r) => write!(f, "TEE sealing required: {r}"),
            Self::TpmRequired(r) => write!(f, "TPM sealing required: {r}"),
            Self::BitcoinNetworkMismatch(r) => write!(f, "bitcoin network mismatch: {r}"),
            Self::DayEpochStale { have, need } => {
                write!(f, "day_epoch stale: have {have}, need {need}")
            }
            Self::ProductionGate(r) => write!(f, "production gate: {r}"),
        }
    }
}

impl std::error::Error for DomainError {}
