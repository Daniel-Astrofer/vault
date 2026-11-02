//! Technology adapters: FROST, Bitcoin, persistence, transport, and hardware.

#[cfg(all(feature = "production", feature = "dealer_lab"))]
compile_error!("production adapters must never compile dealer_lab support");

pub use crate as adapters;
pub use vault_application as application;
pub use vault_domain as domain;

mod attestation;
mod bitcoin;
mod crypto;
mod frost;
mod http;
mod identity;
mod mtls;
mod storage;
mod system;

pub use attestation::{detect_tee_at_paths, detect_tee_devices, SimAttestationAdapter, TeeAttestationAdapter};
pub use bitcoin::{
    destination_script_pubkey, to_bitcoin_network, validate_psbt, validate_psbt_independent, StubChannelInject,
};
pub use crypto::HybridEnvelopeAdapter;
pub use frost::ThresholdVaultState;
#[cfg(feature = "dealer_lab")]
pub use frost::{dealer_fatal_banner, DealerLabAdapter, FrostDealerBundle};
pub use frost::{
    load_tr_channels_shares, load_tr_shares, persist_tr_channels_shares, persist_tr_shares,
    refresh_tr_shares_in_process, FrostTrBitcoinOrchestrator, FrostTrShareSlot, FrostTrShareState, SignedPsbtResult,
};
pub use frost::{
    refresh_shares_in_process, FrostAggregateResult, FrostShareSlot, FrostShareState, FrostSignOrchestrator,
    PolicyReshareHook,
};
pub use frost::{
    session_transcript, session_transcript_tr, DistributedDkgAdapter, DistributedWireDkgPort, DkgStartRequest,
    FrostDistributedBundle, Round1WireMessage, Round2WireMessage, Round3WireRequest, TrDkgKeyset, TrWireDkgHub,
    WireDkgHub, WireDkgPeerAuth, WireDkgStatus,
};
pub use frost::{
    sign_raw_wire, sign_raw_wire_attributed, tr_state_local_only, AttributedWireSignature, HttpTrCosignTransport,
    NoopTrCosignTransport, TrCommitRequest, TrCommitResponse, TrCosignKeyset, TrCosignPeerState, TrCosignTransport,
    TrSignShareRequest, TrSignShareResponse,
};
pub use frost::{
    ReshareRound1WireMessage, ReshareRound2WireMessage, ReshareStartRequest, WireReshareHub, WireResharePeerAuth,
    WireResharePhase, WireReshareStatus,
};
pub use http::{
    peer_addr_is_onion, post_json_with_retry, HttpIntentConsumeTransport, IntentConsumeQuorumTransport,
    IntentPrepareAck, MemoryIntentConsumeTransport, PeerHttpSettings, ProbedOnlineCount, QuorumBucketLedger,
    SlidingWindowLimiter, VaultTransport,
};
pub use http::{
    DayVoteTransport, HttpDayVoteTransport, LedgerDayEpochStub, MemoryDayVoteTransport, NoopDayVoteTransport,
    NoopReshareHook, PeerDayVote, QuorumDailyRotation, RecordingReshareHook,
};
pub use identity::HybridIdentity;
pub use identity::{
    bind_dkg_sender_to_peer, mesh_allowed_node_ids, parse_spiffe_principal, principal_from_cert_sans,
    resolve_mesh_caller_identity, resolve_mesh_caller_identity_with_principal, route_class_for_path,
    MeshAuditKeyAllowlist, MeshPrincipal, MeshRole, RouteClass,
};
pub use mtls::{
    build_mtls_rustls_client_config, build_mtls_server_config, extract_sans, MutualTlsAuthAdapter, PeerCertAcceptor,
    PeerClientCert, TlsPeerVerifyPolicy,
};
pub(crate) use storage::{atomic_write_fsync, lock_mutex};
pub use storage::{
    build_seal_aad, build_seed_aad, build_seed_share_id, build_tpm_seal_port, pcr_composite_digest,
    resolve_aead_passphrase, sealed_passphrase_path, tpm_device_present, validate_tpm_counter, AeadDiskShareStore,
    CounterSealedBlob, HttpAntiNonceTransport, InMemoryBucketLedger, InMemoryEconomy, InMemoryLedger,
    InMemoryPeerDirectory, InMemoryReleaseMesh, MemoryAntiNonceTransport, PersistedAntiNonce, PersistedBucketLedger,
    PersistedEconomy, PersistedReleaseMesh, QuorumAntiNonce, ResolvedPassphrase, SeedKind, SharedAntiNonce,
    TeeSealAdapter, TeeSealShareStore, TpmSealAdapter, TpmSealPort, TpmTssSealAdapter, TSS_MAGIC, TSS_MODE_HW,
    VAULT_PCR_BASE,
};
pub use system::SystemClock;
