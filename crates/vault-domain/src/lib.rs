//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod crypto;
mod epoch;
mod error;
mod health;
mod identity;
mod intent;
mod ledger;
mod membership;
mod policy;
mod psbt;
mod quorum;
mod release;
mod signing;

pub use crypto::{HybridContext, HybridEnvelope, HybridKeyMaterial};
pub use epoch::DayEpoch;
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth, PeerReachability};
pub use identity::{admits_attestation_measurement, AttestationMode, AttestationQuote, Measurement};
pub use intent::{
    assert_channels_taproot_bucket, assert_outputs_match_intent, assert_shared_taproot_bucket, evaluate_intent,
    BucketKind, BucketPolicy, IntentSignature, ProfitSplits, SettlementIntent,
};
pub use ledger::{
    assert_bank_issued_miner_payout, EconomyState, Epoch, EpochAdvanceProposal, GovernanceAccrual, GovernanceJobKind,
    GovernanceRewardConfig, LedgerEntry, LedgerEventKind, MinerOperator, MinerPayoutCadence, MinerPayoutShare,
    ProfitSplitAccrual, RewardPolicy,
};
pub use membership::{
    admission_seating, resolve_node_tier, seat_genesis_by_tier, NodeId, PeerEndpoint, PeerIdentity, PeerInfo,
    SeatingCandidate, VaultNodeTier,
};
pub use policy::{quorum_two_thirds, Constitution, DowngradePolicy, FormatVersions, ResharePolicy};
pub use psbt::{validate_destination, BitcoinNetwork, PsbtPolicy, RbfPolicy};
pub use quorum::run_dkg;
pub use release::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, ReleaseCandidate, ReleasePhase, ReleasePolicy,
};
pub use release::{DrillReport, QuantumMigrationConfig, QuantumState, SweepReport, TransitionAuth, UtxoRecord};
pub use signing::{
    derive_nonce, eval_poly, field_add, field_mul, interpolate_secret, lab_random_u64, nonce_commitment,
    CombinedSignature, GroupKey, KeyShare, PartialSignature, ShareIndex, SigningPhase, SigningSession, LAB_PRIME,
};
