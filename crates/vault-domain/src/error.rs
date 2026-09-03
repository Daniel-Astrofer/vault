use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidNodeId,
    PeerNotFound(String),
    SimAttestationForbidden,
    AttestationRejected(String),
    MeasurementMismatch,
    InvalidConstitution(String),
    LedgerConflict(String),
    UnauthorizedWriter(String),
    QuorumNotMet {
        have: usize,
        need: usize,
    },
    UnknownProposal(String),
    EpochMismatch {
        expected: u64,
        got: u64,
    },
    ProposalClosed(String),
    InvalidShare(String),
    ThresholdError(String),
    NonceReuse(String),
    FailStop {
        online: usize,
        need: usize,
    },
    SessionConsumed(String),
    BadSigningPhase {
        session_id: String,
        phase: String,
    },
    InvalidRelease(String),
    UnknownBlob(String),
    UnknownRelease(String),
    RebuildMismatch {
        expected: String,
        got: String,
    },
    ReleasePredicate(String),
    TimelockNotElapsed {
        age_secs: u64,
        need_secs: u64,
    },
    ReleaseClosed(String),
    NotAllowlisted(String),
    InvalidBucket(String),
    InvalidIntent(String),
    CapExceeded {
        amount: u64,
        cap: u64,
        scope: String,
    },
    DestinationNotAllowed(String),
    IntentReplay(String),
    /// Soft Intent / anti-nonce reservation expired or missing before commit.
    ReservationMissing(String),
    UsersOmnibusProtected,
    LabFlagForbidden(String),
    RequestRejected(String),
    NoEligibleMiners,
    InsufficientMinerPool {
        have: u64,
        want: u64,
    },
    MinerSelfPayForbidden,
    AuthRejected(String),
    ShareStoreForbidden(String),
    DealerForbidden(String),
    TeeRequired(String),
    /// Domestic TPM seal required / unavailable (honest: TPM ≠ SEV).
    TpmRequired(String),
    BitcoinNetworkMismatch(String),
    DayEpochStale {
        have: String,
        need: String,
    },
    ProductionGate(String),
}

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
