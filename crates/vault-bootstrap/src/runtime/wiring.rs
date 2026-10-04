use std::collections::BTreeMap;
use std::sync::Arc;

use crate::adapters::ProbedOnlineCount;
use crate::adapters::{
    build_tpm_seal_port, resolve_aead_passphrase, AeadDiskShareStore, DistributedDkgAdapter, DistributedWireDkgPort,
    FrostShareSlot, FrostShareState, FrostSignOrchestrator, FrostTrBitcoinOrchestrator, FrostTrShareSlot,
    HttpAntiNonceTransport, HttpDayVoteTransport, HttpIntentConsumeTransport, HttpTrCosignTransport, HybridIdentity,
    InMemoryLedger, InMemoryPeerDirectory, MutualTlsAuthAdapter, PersistedBucketLedger, PersistedEconomy,
    PersistedReleaseMesh, PolicyReshareHook, QuorumAntiNonce, QuorumBucketLedger, QuorumDailyRotation, SharedAntiNonce,
    SimAttestationAdapter, SystemClock, TeeAttestationAdapter, TeeSealAdapter, ThresholdVaultState, TrCosignPeerState,
    TrCosignTransport, TrWireDkgHub, WireDkgHub, WireDkgPeerAuth,
};
#[cfg(feature = "dealer_lab")]
use crate::adapters::{
    dealer_fatal_banner, generate_tr_dealer, persist_tr_channels_shares, persist_tr_shares, DealerLabAdapter,
};
use crate::adapters::{load_tr_channels_shares, load_tr_shares};
use crate::application::{
    AccrueGovernanceWork, AccrueMinerRewards, ActivateRelease, AllocateProfit, AntiNoncePort, CosignRelease,
    DailyRotationPort, DkgPort, GateIntent, GetAllowlist, GetEconomyStatus, GetHealth, GetLedgerSnapshot, GetMetrics,
    OnlineStatusPort, PingPeer, ProposeEpochAdvance, ProposeMinerPayouts, ProposeRelease, RebuildRelease,
    ReshareHookPort, ShareStorePort, SignMessage, StaticOnlineCount, UpsertMiner, VaultAuthPort, VoteEpochAdvance,
};
use crate::domain::{
    quorum_two_thirds, run_dkg, Constitution, DomainError, Measurement, NodeId, PeerEndpoint, PeerInfo, ReleasePolicy,
};
use crate::{CeremonyMode, DkgMode, ShareStoreMode, VaultConfig};

pub struct VaultRuntime {
    pub config: VaultConfig,
    /// Genesis / wire-DKG roster after SEV-priority seating (§3.1).
    pub genesis_roster: Vec<NodeId>,
    /// Hybrid cryptographic identity (Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768).
    pub hybrid_identity: Option<HybridIdentity>,
    pub get_health: GetHealth,
    pub get_metrics: GetMetrics,
    pub ping_peer: PingPeer,
    pub get_ledger: GetLedgerSnapshot,
    pub propose_epoch: ProposeEpochAdvance,
    pub vote_epoch: VoteEpochAdvance,
    pub sign_message: SignMessage,
    pub propose_release: ProposeRelease,
    pub rebuild_release: RebuildRelease,
    pub cosign_release: CosignRelease,
    pub activate_release: ActivateRelease,
    pub get_allowlist: GetAllowlist,
    pub gate_intent: GateIntent,
    pub allocate_profit: AllocateProfit,
    pub get_economy: GetEconomyStatus,
    pub upsert_miner: UpsertMiner,
    pub accrue_rewards: AccrueMinerRewards,
    pub propose_miner_payouts: ProposeMinerPayouts,
    pub peers: Arc<InMemoryPeerDirectory>,
    pub ledger: Arc<InMemoryLedger>,
    pub threshold: Arc<ThresholdVaultState>,
    pub online: Arc<dyn OnlineStatusPort>,
    pub release_mesh: Arc<PersistedReleaseMesh>,
    pub buckets: Arc<QuorumBucketLedger>,
    pub economy: Arc<PersistedEconomy>,
    pub auth: Arc<dyn VaultAuthPort>,
    pub share_store: Arc<dyn ShareStorePort>,
    pub dkg: Arc<dyn DkgPort>,
    pub daily_rotation: Arc<dyn DailyRotationPort>,
    pub reshare_hook: Arc<dyn ReshareHookPort>,
    pub frost_shares: Arc<FrostShareSlot>,
    pub anti_nonce: Arc<dyn AntiNoncePort>,
    /// Present after dealer_lab or distributed FROST DKG keygen.
    pub frost: Option<Arc<FrostSignOrchestrator>>,
    /// Taproot BIP-340 FROST keyset for on-chain PSBT / sighash signing (USERS omnibus).
    pub frost_tr: Option<Arc<FrostTrBitcoinOrchestrator>>,
    pub frost_tr_shares: Arc<FrostTrShareSlot>,
    /// Dedicated CHANNELS Taproot keyset (≠ USERS omnibus).
    pub frost_tr_channels: Option<Arc<FrostTrBitcoinOrchestrator>>,
    pub frost_tr_channels_shares: Arc<FrostTrShareSlot>,
    /// Peer helper for over-wire TR FROST co-sign rounds.
    pub tr_cosign_peer: Arc<TrCosignPeerState>,
    /// Over-wire DKG hub (HTTP round exchange between peers).
    pub wire_dkg: Arc<WireDkgHub>,
    pub tr_wire_dkg: Arc<TrWireDkgHub>,
}

impl VaultRuntime {
    pub fn build(config: VaultConfig) -> Result<Self, DomainError> {
        config.validate_attestation_policy()?;
        config.validate_hygiene()?;

        if matches!(config.ceremony_mode, CeremonyMode::Staging | CeremonyMode::Production) && config.dealer_requested {
            return Err(DomainError::DealerForbidden("dealer DKG refused in staging/production".into()));
        }

        let peers = Arc::new(InMemoryPeerDirectory::new());
        for (id, addr) in &config.seed_peers {
            peers.upsert_sync(PeerInfo {
                id: NodeId::new(id.clone())?,
                endpoint: PeerEndpoint { address: addr.clone() },
            })?;
        }

        // Genesis seating: prefer SEV > SGX > domestic when filling signing_n.
        // Same roster drives ledger active_set and over-wire FROST DKG start.
        let active_set = config.seat_genesis()?;
        let n = active_set.len();
        if !active_set.iter().any(|id| id == &config.node_id) {
            return Err(DomainError::ThresholdError(format!(
                "local node {} not seated in genesis roster (SEV/SGX peers filled VAULT_GENESIS_N seats; this node is waiting-set only)",
                config.node_id
            )));
        }

        let mut constitution = if config.open_economy { Constitution::v1_open(n)? } else { Constitution::v1_lab(n)? };
        if let Some(hex) = config.measurement_pin_hex.as_deref() {
            constitution = constitution.with_measurement_pin(Measurement::from_hex(hex)?);
        } else {
            constitution.ensure_measurement_pin();
        }
        constitution = constitution.with_payout_frequency(config.miner_payout_frequency);
        let measurement = constitution.measurement_pin_or_hash();
        let configured_members = constitution.signing_n;
        let required_threshold = constitution.signing_t;
        let max_tx = constitution.max_withdraw_per_tx_sats;
        let max_day = constitution.max_withdraw_per_day_sats;
        let t = constitution.signing_t;
        // Day-advance quorum = ⌈2n/3⌉ authenticated peers (Critical #5). Solo (no seed
        // peers) stays t=1. Cross-node votes via authenticated outbound fan-out.
        let peer_n = config.seed_peers.len();
        let n_mesh = active_set.len().max(1);
        let rotation_quorum = if peer_n == 0 { 1usize } else { quorum_two_thirds(n_mesh).max(t) };
        let dkg_set = active_set.clone();
        let ledger = Arc::new(InMemoryLedger::genesis(constitution, active_set.clone(), config.node_id.clone())?);

        let entropy =
            format!("genesis|{}|{}", config.lab_root, dkg_set.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(","));
        // Lab domain DKG is deterministic from lab_root + roster (#17) — not FROST Bitcoin.
        if matches!(config.ceremony_mode, CeremonyMode::Lab) {
            eprintln!(
                "WARN lab domain DKG entropy is deterministic (LAB_ATTESTATION_ROOT+roster); not production wallet material"
            );
        }
        let (group, shares) = run_dkg(&dkg_set, t, entropy.as_bytes())?;
        let local_share = shares
            .iter()
            .find(|s| s.node_id == config.node_id)
            .cloned()
            .ok_or_else(|| DomainError::ThresholdError("local share missing after DKG".into()))?;
        let mut online: Arc<dyn OnlineStatusPort> =
            Arc::new(StaticOnlineCount { count: config.online_count.unwrap_or(n) });
        let threshold = Arc::new(ThresholdVaultState::new(group, local_share, shares));
        let mut sign_message = SignMessage::new(threshold.clone(), online.clone());

        let attestation: Arc<dyn crate::application::AttestationPort> = match config.attestation_mode {
            crate::domain::AttestationMode::Sim => Arc::new(SimAttestationAdapter::new(config.lab_root.as_bytes())),
            crate::domain::AttestationMode::Software => {
                Arc::new(SimAttestationAdapter::software(config.lab_root.as_bytes()))
            }
            crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx => {
                let refuse_stub =
                    matches!(config.ceremony_mode, CeremonyMode::Production) || cfg!(feature = "production");
                Arc::new(TeeAttestationAdapter::with_policy(
                    config.attestation_mode,
                    config.attestation_staging_stub,
                    refuse_stub,
                    config.lab_root.as_bytes(),
                    measurement.clone(),
                    Vec::new(),
                )?)
            }
        };

        let clock: Arc<dyn crate::application::ClockPort> = Arc::new(SystemClock);
        let peers_port: Arc<dyn crate::application::PeerDirectoryPort> = peers.clone();
        let ledger_port: Arc<dyn crate::application::LedgerPort> = ledger.clone();

        let mut release_policy = ReleasePolicy::lab_default(n);
        release_policy.lab_timelock_scale = config.effective_lab_timelock_scale();
        release_policy.council_n = config.lab_council_n.max(2);
        release_policy.min_rebuilds = config.lab_min_rebuilds.max(1);
        let data_root_early = config.effective_data_dir();
        let release_mesh = Arc::new(PersistedReleaseMesh::open(data_root_early.join("release"), release_policy)?);
        let release_port: Arc<dyn crate::application::ReleaseStorePort> = release_mesh.clone();
        let blob_port: Arc<dyn crate::application::BlobStorePort> = release_mesh.clone();

        let economy = Arc::new(PersistedEconomy::open(data_root_early.join("economy.json"))?);
        let economy_port: Arc<dyn crate::application::EconomyPort> = economy.clone();
        let governance_reward = config.governance_reward_config();
        let accrue_governance = Arc::new(AccrueGovernanceWork::new(
            economy_port.clone(),
            ledger_port.clone(),
            config.node_id.clone(),
            governance_reward,
        ));

        // --- Hybrid identity: generate or load ---
        let hybrid_identity = HybridIdentity::genesis(config.node_id.clone()).ok();

        let mut mtls = MutualTlsAuthAdapter::with_reshare_trigger(config.allow_manual_reshare);
        if let Some(ref id) = hybrid_identity {
            mtls = mtls.with_identity(id.ed25519_public);
        }
        let auth: Arc<dyn VaultAuthPort> = Arc::new(mtls);

        let data_root = config.effective_data_dir();
        let local_buckets =
            Arc::new(PersistedBucketLedger::open(data_root.join("consumed_intents.log"), max_tx, max_day)?);
        if !config.users_destination_allowlist.is_empty() {
            local_buckets
                .admit_destinations(crate::domain::BucketKind::Users, config.users_destination_allowlist.clone())?;
        }
        if !config.miners_destination_allowlist.is_empty() {
            local_buckets
                .admit_destinations(crate::domain::BucketKind::Miners, config.miners_destination_allowlist.clone())?;
        }
        let share_store: Arc<dyn ShareStorePort> = match config.share_store_mode {
            ShareStoreMode::AeadDisk => {
                if config.share_tpm_seal {
                    let refuse_stub = config.hardened
                        || !matches!(config.ceremony_mode, CeremonyMode::Lab)
                        || cfg!(feature = "production");
                    let tpm = build_tpm_seal_port(true, config.share_tpm_stub, refuse_stub)?
                        .expect("TPM seal port when VAULT_SHARE_TPM_SEAL=1");
                    let resolved = resolve_aead_passphrase(
                        &data_root,
                        config.effective_share_passphrase().as_deref(),
                        tpm.as_ref(),
                        config.share_tpm_clear_fallback,
                    )?;
                    if resolved.used_clear_fallback {
                        eprintln!(
                            "WARN share_tpm=clear_fallback backend={} (lab only; TPM ≠ SEV)",
                            resolved.tpm_backend
                        );
                    } else {
                        eprintln!("share_tpm=sealed backend={} (disk-at-rest only; TPM ≠ SEV)", resolved.tpm_backend);
                    }
                    Arc::new(AeadDiskShareStore::with_tpm_seal(
                        data_root.join("shares"),
                        resolved.passphrase,
                        !resolved.used_clear_fallback,
                    ))
                } else {
                    let pass = config.effective_share_passphrase().ok_or_else(|| {
                        DomainError::ShareStoreForbidden(
                            "VAULT_DATA_PASSPHRASE required outside lab (no default passphrase)".into(),
                        )
                    })?;
                    Arc::new(AeadDiskShareStore::new(data_root.join("shares"), pass))
                }
            }
            ShareStoreMode::TeeSeal => {
                #[cfg(feature = "production")]
                {
                    // Production feature: never wire staging stub.
                    #[cfg(feature = "tee_hw")]
                    {
                        if matches!(
                            config.attestation_mode,
                            crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx
                        ) {
                            Arc::new(TeeSealAdapter::hw(
                                data_root.join("tee-shares"),
                                config.attestation_mode,
                                measurement.clone(),
                                attestation.clone(),
                            )?)
                        } else {
                            Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                        }
                    }
                    #[cfg(not(feature = "tee_hw"))]
                    {
                        let _ = &attestation;
                        Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                    }
                }
                #[cfg(not(feature = "production"))]
                {
                    if config.attestation_staging_stub && !matches!(config.ceremony_mode, CeremonyMode::Production) {
                        let pass = config.effective_share_passphrase().ok_or_else(|| {
                            DomainError::ShareStoreForbidden(
                                "VAULT_DATA_PASSPHRASE required for tee staging stub outside lab".into(),
                            )
                        })?;
                        Arc::new(
                            TeeSealAdapter::staging_stub(data_root.join("tee-shares"), pass, measurement.clone())
                                .with_attestation(attestation.clone()),
                        )
                    } else {
                        #[cfg(feature = "tee_hw")]
                        {
                            if matches!(
                                config.attestation_mode,
                                crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx
                            ) {
                                Arc::new(TeeSealAdapter::hw(
                                    data_root.join("tee-shares"),
                                    config.attestation_mode,
                                    measurement.clone(),
                                    attestation.clone(),
                                )?)
                            } else {
                                Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                            }
                        }
                        #[cfg(not(feature = "tee_hw"))]
                        {
                            let _ = &attestation;
                            Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                        }
                    }
                }
            }
        };

        let mut peer_bases: Vec<(String, String)> = Vec::new();
        for (id, addr) in &config.seed_peers {
            let base = if addr.starts_with("http://") || addr.starts_with("https://") {
                if addr.starts_with("http://") {
                    format!("https://{}", addr.trim_start_matches("http://"))
                } else {
                    addr.clone()
                }
            } else {
                format!("https://{addr}")
            };
            peer_bases.push((id.clone(), base));
        }
        let peer_count = peer_bases.len();
        // Probe a non-recursive local-ready endpoint. Probing /v1/health here
        // would recursively ask every peer to calculate financial readiness.
        if !(config.online_static || (matches!(config.ceremony_mode, CeremonyMode::Lab) && peer_count == 0)) {
            let peer_health: Vec<String> = peer_bases.iter().map(|(_, b)| format!("{b}/v1/local-health")).collect();
            let (client_cert, client_key, ca) = config.require_mtls_client_identity()?;
            online = Arc::new(ProbedOnlineCount::new_mtls(
                peers.clone(),
                peer_health,
                config.peer_http.clone(),
                config.online_count,
                std::path::Path::new(client_cert),
                std::path::Path::new(client_key),
                std::path::Path::new(ca),
                &config.tls_verify_policy,
            )?);
            sign_message = SignMessage::new(threshold.clone(), online.clone());
        }
        let peer_prepare: Vec<String> = peer_bases.iter().map(|(_, b)| format!("{b}/v1/anti-nonce/prepare")).collect();
        let intent_prepare: Vec<String> =
            peer_bases.iter().map(|(_, b)| format!("{b}/v1/intent/consume/prepare")).collect();
        let day_vote_peers: Vec<(String, String)> =
            peer_bases.iter().map(|(id, b)| (id.clone(), format!("{b}/v1/day/vote"))).collect();

        let (cert, key, ca) = config.require_mtls_client_identity()?;
        let anti_transport = Arc::new(HttpAntiNonceTransport::with_mtls(
            peer_prepare,
            config.peer_http.clone(),
            std::path::Path::new(cert),
            std::path::Path::new(key),
            std::path::Path::new(ca),
            &config.tls_verify_policy,
        )?);
        let anti_nonce: Arc<dyn AntiNoncePort> =
            Arc::new(QuorumAntiNonce::open(data_root.join("used_sessions.log"), anti_transport, peer_count)?);

        let intent_transport: Arc<dyn crate::adapters::IntentConsumeQuorumTransport> =
            Arc::new(HttpIntentConsumeTransport::with_mtls(
                intent_prepare,
                config.peer_http.clone(),
                std::path::Path::new(cert),
                std::path::Path::new(key),
                std::path::Path::new(ca),
                &config.tls_verify_policy,
            )?);
        // Fail-closed when peers configured (incl. hardened): quorum prepare before authorize.
        let buckets = Arc::new(QuorumBucketLedger::from_local(local_buckets, intent_transport, peer_count));
        let bucket_port: Arc<dyn crate::application::BucketLedgerPort> = buckets.clone();

        let frost_shares = Arc::new(FrostShareSlot::new());
        let frost_tr_shares = Arc::new(FrostTrShareSlot::new());
        let frost_tr_channels_shares = Arc::new(FrostTrShareSlot::new());
        let allow_in_process_reshare = false;
        let reshare_hook: Arc<dyn ReshareHookPort> = Arc::new(
            PolicyReshareHook::new(
                config.reshare_policy,
                ledger_port.clone(),
                config.node_id.clone(),
                frost_shares.clone(),
                frost_tr_shares.clone(),
            )
            .with_channels_tr_shares(frost_tr_channels_shares.clone())
            .with_allow_in_process_nshare_reshare(allow_in_process_reshare)
            .with_share_store(share_store.clone())
            .with_governance(accrue_governance.clone()),
        );

        let day_vote_transport: Arc<dyn crate::adapters::DayVoteTransport> = Arc::new(HttpDayVoteTransport::with_mtls(
            day_vote_peers,
            config.peer_http.clone(),
            std::path::Path::new(cert),
            std::path::Path::new(key),
            std::path::Path::new(ca),
            &config.tls_verify_policy,
        )?);
        let daily_rotation: Arc<dyn DailyRotationPort> = Arc::new(QuorumDailyRotation::with_persist_and_transport(
            clock.clone(),
            rotation_quorum,
            config.node_id.as_str(),
            reshare_hook.clone(),
            data_root.join("day_epoch"),
            day_vote_transport,
        ));

        // Wire DKG fan-out only to seated peers (not waiting-set seeds cut by tier).
        let mut peer_addrs = BTreeMap::new();
        for (id, addr) in &config.seed_peers {
            if active_set.iter().any(|s| s.as_str() == id.as_str()) {
                peer_addrs.insert(id.clone(), addr.clone());
            }
        }
        let peer_auth = WireDkgPeerAuth::MutualTls {
            client_cert_path: std::path::PathBuf::from(cert),
            client_key_path: std::path::PathBuf::from(key),
            ca_path: std::path::PathBuf::from(ca),
            verify: config.tls_verify_policy.clone(),
        };
        let wire_dkg = Arc::new(WireDkgHub::with_peer_http(
            config.node_id.as_str().to_string(),
            peer_addrs.clone(),
            peer_auth.clone(),
            config.peer_http.clone(),
        )?);
        let tr_wire_dkg = Arc::new(TrWireDkgHub::with_peer_http(
            config.node_id.as_str().to_string(),
            peer_addrs,
            peer_auth,
            config.peer_http.clone(),
        )?);

        // Taproot FROST co-sign transport always uses peer mTLS.
        let tr_cosign_peers: Vec<(String, String)> = peer_bases.iter().map(|(id, b)| (id.clone(), b.clone())).collect();
        let tr_cosign_transport: Arc<dyn TrCosignTransport> = Arc::new(HttpTrCosignTransport::with_mtls(
            tr_cosign_peers,
            config.peer_http.clone(),
            std::path::Path::new(cert),
            std::path::Path::new(key),
            std::path::Path::new(ca),
            &config.tls_verify_policy,
        )?);
        let tr_cosign_peer = Arc::new(TrCosignPeerState::new(config.node_id.as_str(), frost_tr_shares.clone()));

        #[cfg(feature = "dealer_lab")]
        let (dkg, frost, frost_tr, frost_tr_channels): (
            Arc<dyn DkgPort>,
            Option<Arc<FrostSignOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
        ) = {
            if config.dealer_requested && matches!(config.ceremony_mode, CeremonyMode::Lab) && !config.hardened {
                dealer_fatal_banner();
                let adapter = DealerLabAdapter::new();
                let max = n.min(u16::MAX as usize) as u16;
                let min = t.min(u16::MAX as usize) as u16;
                let max = max.max(2);
                let min = min.max(2).min(max);
                let bundle = DealerLabAdapter::generate(max, min)?;
                // Seal local share bytes (serialized verifying key + identifier index) for lab store smoke.
                if let Some((id, kp)) = bundle.key_packages.iter().next() {
                    let blob = format!("frost-lab-share:{id:?}");
                    let _ = share_store.put_share(config.node_id.as_str(), blob.as_bytes());
                    let _ = kp;
                }
                frost_shares.install(FrostShareState {
                    key_packages: bundle.key_packages,
                    pubkey_package: bundle.pubkey_package,
                    min_signers: t,
                });
                let orch = FrostSignOrchestrator::from_share_slot(
                    frost_shares.clone(),
                    Box::new(SharedAntiNonce(anti_nonce.clone())),
                    daily_rotation.clone(),
                );
                // Prefer sealed Taproot material in VAULT_DATA_DIR; dealer only if missing.
                let tr_state = match load_tr_shares(share_store.as_ref()) {
                    Ok(existing) => existing,
                    Err(_) => {
                        let fresh = generate_tr_dealer(max, min)?;
                        persist_tr_shares(&fresh, share_store.as_ref())?;
                        fresh
                    }
                };
                frost_tr_shares.install(tr_state);
                let tr_orch = FrostTrBitcoinOrchestrator::new(
                    frost_tr_shares.clone(),
                    Box::new(SharedAntiNonce(anti_nonce.clone())),
                    daily_rotation.clone(),
                    config.bitcoin_network,
                )
                .with_psbt_policy(config.psbt_policy)
                .with_wire_cosign(
                    config.node_id.as_str(),
                    true, // dealer_lab: in-process N-share OK
                    tr_cosign_transport.clone(),
                );
                // CHANNELS Taproot key ≠ USERS omnibus (separate dealer keygen / sealed shares).
                let tr_ch_state = match load_tr_channels_shares(share_store.as_ref()) {
                    Ok(existing) => existing,
                    Err(_) => {
                        let fresh = generate_tr_dealer(max, min)?;
                        persist_tr_channels_shares(&fresh, share_store.as_ref())?;
                        fresh
                    }
                };
                frost_tr_channels_shares.install(tr_ch_state);
                let tr_ch_orch = FrostTrBitcoinOrchestrator::new(
                    frost_tr_channels_shares.clone(),
                    Box::new(SharedAntiNonce(anti_nonce.clone())),
                    daily_rotation.clone(),
                    config.bitcoin_network,
                )
                .with_psbt_policy(config.psbt_policy)
                .with_wire_cosign(config.node_id.as_str(), true, tr_cosign_transport.clone());
                (Arc::new(adapter), Some(Arc::new(orch)), Some(Arc::new(tr_orch)), Some(Arc::new(tr_ch_orch)))
            } else if matches!(config.dkg_mode, DkgMode::DistributedWire) {
                // Over-wire ceremony via /v1/dkg/round{1,2,3}; no in-process dealer/sim.
                // frost_tr installed after TR DKG / sealed single-share load; wire co-sign required.
                let frost_tr = match load_tr_shares(share_store.as_ref()) {
                    Ok(existing) => {
                        if existing.key_packages.len() > 1 {
                            return Err(DomainError::ThresholdError(
                                "distributed_wire refuses sealed multi-share TR material; install local share only"
                                    .into(),
                            ));
                        }
                        frost_tr_shares.install(existing);
                        Some(Arc::new(
                            FrostTrBitcoinOrchestrator::new(
                                frost_tr_shares.clone(),
                                Box::new(SharedAntiNonce(anti_nonce.clone())),
                                daily_rotation.clone(),
                                config.bitcoin_network,
                            )
                            .with_psbt_policy(config.psbt_policy)
                            .with_wire_cosign(
                                config.node_id.as_str(),
                                false,
                                tr_cosign_transport.clone(),
                            ),
                        ))
                    }
                    Err(_) => None,
                };
                let frost_tr_channels = match load_tr_channels_shares(share_store.as_ref()) {
                    Ok(existing) => {
                        if existing.key_packages.len() > 1 {
                            return Err(DomainError::ThresholdError(
                                "distributed_wire refuses sealed multi-share CHANNELS TR material".into(),
                            ));
                        }
                        frost_tr_channels_shares.install(existing);
                        Some(Arc::new(
                            FrostTrBitcoinOrchestrator::new(
                                frost_tr_channels_shares.clone(),
                                Box::new(SharedAntiNonce(anti_nonce.clone())),
                                daily_rotation.clone(),
                                config.bitcoin_network,
                            )
                            .with_psbt_policy(config.psbt_policy)
                            .with_wire_cosign(
                                config.node_id.as_str(),
                                false,
                                tr_cosign_transport.clone(),
                            ),
                        ))
                    }
                    Err(_) => None,
                };
                (Arc::new(DistributedWireDkgPort), None, frost_tr, frost_tr_channels)
            } else if matches!(config.dkg_mode, DkgMode::Distributed) {
                let (dkg, frost) = wire_distributed_dkg(
                    n,
                    t,
                    &share_store,
                    daily_rotation.clone(),
                    frost_shares.clone(),
                    anti_nonce.clone(),
                )?;
                (dkg, frost, None, None)
            } else {
                (Arc::new(DistributedDkgAdapter::new()), None, None, None)
            }
        };

        #[cfg(not(feature = "dealer_lab"))]
        let (dkg, frost, frost_tr, frost_tr_channels): (
            Arc<dyn DkgPort>,
            Option<Arc<FrostSignOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
        ) = {
            if config.dealer_requested || matches!(config.dkg_mode, DkgMode::DealerLab) {
                return Err(DomainError::DealerForbidden("dealer DKG not compiled (build without dealer_lab)".into()));
            }
            if matches!(config.dkg_mode, DkgMode::DistributedWire) {
                let frost_tr = match load_tr_shares(share_store.as_ref()) {
                    Ok(existing) => {
                        if existing.key_packages.len() > 1 {
                            return Err(DomainError::ThresholdError(
                                "distributed_wire refuses sealed multi-share TR material; install local share only"
                                    .into(),
                            ));
                        }
                        frost_tr_shares.install(existing);
                        Some(Arc::new(
                            FrostTrBitcoinOrchestrator::new(
                                frost_tr_shares.clone(),
                                Box::new(SharedAntiNonce(anti_nonce.clone())),
                                daily_rotation.clone(),
                                config.bitcoin_network,
                            )
                            .with_psbt_policy(config.psbt_policy)
                            .with_wire_cosign(
                                config.node_id.as_str(),
                                false,
                                tr_cosign_transport.clone(),
                            ),
                        ))
                    }
                    Err(_) => None,
                };
                let frost_tr_channels = match load_tr_channels_shares(share_store.as_ref()) {
                    Ok(existing) => {
                        if existing.key_packages.len() > 1 {
                            return Err(DomainError::ThresholdError(
                                "distributed_wire refuses sealed multi-share CHANNELS TR material".into(),
                            ));
                        }
                        frost_tr_channels_shares.install(existing);
                        Some(Arc::new(
                            FrostTrBitcoinOrchestrator::new(
                                frost_tr_channels_shares.clone(),
                                Box::new(SharedAntiNonce(anti_nonce.clone())),
                                daily_rotation.clone(),
                                config.bitcoin_network,
                            )
                            .with_psbt_policy(config.psbt_policy)
                            .with_wire_cosign(
                                config.node_id.as_str(),
                                false,
                                tr_cosign_transport.clone(),
                            ),
                        ))
                    }
                    Err(_) => None,
                };
                (Arc::new(DistributedWireDkgPort), None, frost_tr, frost_tr_channels)
            } else {
                let (dkg, frost) = wire_distributed_dkg(
                    n,
                    t,
                    &share_store,
                    daily_rotation.clone(),
                    frost_shares.clone(),
                    anti_nonce.clone(),
                )?;
                (dkg, frost, None, None)
            }
        };

        let get_health = GetHealth::with_roster(
            config.node_id.clone(),
            peers_port.clone(),
            attestation.clone(),
            config.node_tier,
            // High #14: software measurement is never TEE.
            config.tee_available && config.attestation_mode.is_tee(),
            dkg_set.iter().map(|n| n.as_str().to_string()).collect(),
        )
        .with_peer_probe(!config.online_static && peer_count > 0)
        .with_constitution(configured_members, required_threshold)
        .with_online_status(online.clone());
        let get_metrics = GetMetrics::new(config.node_id.clone(), ledger_port.clone(), Some(bucket_port.clone()));
        let ping_peer = PingPeer::new(peers_port, attestation, clock.clone(), measurement);
        let get_ledger = GetLedgerSnapshot::new(ledger_port.clone());
        let propose_epoch = ProposeEpochAdvance::new(ledger_port.clone(), config.node_id.clone());
        let vote_epoch = VoteEpochAdvance::new(ledger_port.clone(), config.node_id.clone());
        let propose_release =
            ProposeRelease::new(release_port.clone(), blob_port.clone(), ledger_port.clone(), clock.clone());
        let rebuild_release = RebuildRelease::new(release_port.clone(), blob_port);
        let cosign_release =
            CosignRelease::new(release_port.clone(), ledger_port.clone(), clock.clone(), config.node_id.clone())
                .with_governance(accrue_governance.clone());
        let activate_release = ActivateRelease::new(release_port.clone(), ledger_port.clone(), clock.clone())
            .with_governance(accrue_governance.clone());
        let get_allowlist = GetAllowlist::new(release_port);
        let gate_intent = GateIntent::new(bucket_port, ledger_port.clone(), economy_port.clone());
        let allocate_profit = AllocateProfit::new(ledger_port.clone());
        let get_economy = GetEconomyStatus::new(
            economy_port.clone(),
            ledger_port.clone(),
            governance_reward,
            config.miner_payout_cadence,
            config.node_tier,
            config.attestation_mode,
            config.tee_available,
        );
        let upsert_miner = UpsertMiner::new(economy_port.clone());
        let accrue_rewards = AccrueMinerRewards::new(economy_port.clone(), ledger_port.clone(), config.node_id.clone());
        let propose_miner_payouts =
            ProposeMinerPayouts::new(economy_port, ledger_port, clock, config.miner_payout_cadence);

        let mode = if config.hardened { "production-refuse" } else { "lab-visualize" };
        eprintln!(
            "MODE={mode} tier={} tee_available={} auth={} share_store={} dkg={} reshare={} bitcoin={}",
            config.node_tier.as_str(),
            config.tee_available,
            auth.mode_name(),
            share_store.store_kind(),
            dkg.mode_name(),
            config.reshare_policy.as_str(),
            config.bitcoin_network.as_str()
        );

        Ok(Self {
            config,
            genesis_roster: dkg_set,
            hybrid_identity,
            get_health,
            get_metrics,
            ping_peer,
            get_ledger,
            propose_epoch,
            vote_epoch,
            sign_message,
            propose_release,
            rebuild_release,
            cosign_release,
            activate_release,
            get_allowlist,
            gate_intent,
            allocate_profit,
            get_economy,
            upsert_miner,
            accrue_rewards,
            propose_miner_payouts,
            peers,
            ledger,
            threshold,
            online,
            release_mesh,
            buckets,
            economy,
            auth,
            share_store,
            dkg,
            daily_rotation,
            reshare_hook,
            frost_shares,
            anti_nonce,
            frost,
            frost_tr,
            frost_tr_shares,
            frost_tr_channels,
            frost_tr_channels_shares,
            tr_cosign_peer,
            wire_dkg,
            tr_wire_dkg,
        })
    }
}

fn wire_distributed_dkg(
    n: usize,
    t: usize,
    share_store: &Arc<dyn ShareStorePort>,
    rotation: Arc<dyn DailyRotationPort>,
    shares: Arc<FrostShareSlot>,
    anti_nonce: Arc<dyn AntiNoncePort>,
) -> Result<(Arc<dyn DkgPort>, Option<Arc<FrostSignOrchestrator>>), DomainError> {
    let max = n.min(u16::MAX as usize) as u16;
    let min = t.min(u16::MAX as usize) as u16;
    let max = max.max(2);
    let min = min.max(2).min(max);
    let bundle = DistributedDkgAdapter::run_in_process(max, min)?;
    // Persist via ShareStorePort only (AEAD lab; TEE refuses in prod until Gate seal).
    DistributedDkgAdapter::persist_shares(&bundle, share_store.as_ref())?;
    shares.install(FrostShareState {
        key_packages: bundle.key_packages,
        pubkey_package: bundle.pubkey_package,
        min_signers: min as usize,
    });
    let orch = FrostSignOrchestrator::from_share_slot(shares, Box::new(SharedAntiNonce(anti_nonce)), rotation);
    Ok((Arc::new(DistributedDkgAdapter::new()), Some(Arc::new(orch))))
}
