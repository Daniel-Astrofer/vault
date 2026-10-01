//! Application layer: use cases depend on ports (DIP).

pub mod ports;
mod use_cases;

pub use ports::SourceArchiveStorePort;
pub use ports::{
    bind_session_to_intent, AntiNoncePort, AttestationPort, BlobStorePort, BucketLedgerPort, ClockPort,
    DailyRotationPort, DkgPort, EconomyPort, HybridEnvelopePort, KeyLifecyclePort, LedgerPort, PeerDirectoryPort,
    ReleaseStorePort, ReshareHookPort, ShareStorePort, SigningPort, VaultAuthPort,
};
pub use use_cases::{
    economy_snapshot_json, is_payout_epoch, AccrueGovernanceWork, AccrueMinerRewards, AccrueReceipt, AllocateProfit,
    EconomyStatusView, GateIntent, GateReceipt, GetEconomyStatus, GetHealth, GetLedgerSnapshot, GetMetrics, KeyDomain,
    KeyLifecycle, KeyLifecycleEvent, KeyMetadata, LedgerSnapshot, PayoutProposal, PingPeer, PingReport,
    ProfitAllocation, ProposeEpochAdvance, ProposeMinerPayouts, UpsertMiner, VoteEpochAdvance,
};
pub use use_cases::{validate_emergency_ready, PsbtSkeleton, QuantumMigrationPort, StubQuantumMigrationController};
pub use use_cases::{
    ActivateRelease, CosignRelease, GetAllowlist, MutableOnlineCount, NoopShareMigration, OnlineStatusPort,
    ProposeRelease, RebuildRelease, ShareMigrationPort, SignMessage, StaticOnlineCount,
};
pub use use_cases::{GetReleaseCompatibility, IngestSourceArchive, ReleaseCompatibilityContext};
