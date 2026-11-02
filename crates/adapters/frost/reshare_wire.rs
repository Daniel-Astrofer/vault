//! Wire-based Taproot FROST reshare hub (mirrors WireDkgHub).
//!
//! Each vault runs the reshare protocol independently, exchanging round
//! messages over authenticated HTTP. The protocol preserves the group
//! verifying key (same tb1p deposit address) while rotating each vault's
//! share. Only the local share is persisted — no central dealer.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::refresh::{refresh_dkg_part1, refresh_dkg_part2, refresh_dkg_shares};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384 as Sha384};

use crate::application::ShareStorePort;
use crate::domain::{DayEpoch, DomainError, HybridEnvelope};
use crate::{build_mtls_rustls_client_config, post_json_with_retry, PeerHttpSettings, TlsPeerVerifyPolicy};

// ── Phase enumeration ───────────────────────────────────────────────────────

/// Local state of one distributed reshare session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireResharePhase {
    /// Round-one refresh commitments are being collected.
    Round1,
    /// Round-two per-recipient refresh packages are being collected.
    Round2,
    /// The refreshed local share was produced and persisted.
    Complete,
}

impl WireResharePhase {
    /// Return the stable lowercase phase label used by the status response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Round1 => "round1",
            Self::Round2 => "round2",
            Self::Complete => "complete",
        }
    }
}

// ── Peer auth ───────────────────────────────────────────────────────────────

/// Authentication configuration for outbound reshare requests to peers.
#[derive(Debug, Clone)]
pub enum WireResharePeerAuth {
    /// Attach the shared Vault token header; transport uses cleartext HTTP.
    StaticToken(String),
    /// Use client certificates and the configured peer verification policy.
    MutualTls {
        /// PEM client certificate presented to the remote vault.
        client_cert_path: PathBuf,
        /// PEM private key corresponding to `client_cert_path`.
        client_key_path: PathBuf,
        /// CA bundle used to validate the remote TLS certificate.
        ca_path: PathBuf,
        /// Rules controlling remote peer certificate verification.
        verify: TlsPeerVerifyPolicy,
    },
}

impl WireResharePeerAuth {
    /// Return whether outbound requests are configured to use mutual TLS.
    pub fn is_mtls(&self) -> bool {
        matches!(self, Self::MutualTls { .. })
    }
}

// ── Wire message types ──────────────────────────────────────────────────────

/// Round-one broadcast carrying one node's FROST refresh DKG package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareRound1WireMessage {
    /// Session identifier tying this message to a frozen reshare transcript.
    pub session_id: String,
    /// Mesh node identifier that produced the round-one package.
    pub sender_node_id: String,
    /// Numeric FROST identifier assigned to the sender in the canonical roster.
    pub sender_identifier: u16,
    /// Total roster size committed by the session.
    pub max_signers: u16,
    /// Threshold required by the refreshed key package.
    pub min_signers: u16,
    /// UTC day epoch bound into this reshare.
    pub day_epoch: String,
    /// SHA-384 transcript digest binding session, epoch, roster, thresholds, and constitution.
    pub transcript_hex: String,
    /// Serialized FROST round-one package encoded as hexadecimal.
    pub package_hex: String,
    /// Optional encrypted envelope for deployments that wrap wire payloads.
    #[serde(default)]
    pub envelope: Option<HybridEnvelope>,
}

/// Private round-two refresh package addressed to one roster participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareRound2WireMessage {
    /// Session identifier tying this message to a frozen reshare transcript.
    pub session_id: String,
    /// Mesh node identifier that produced this package.
    pub sender_node_id: String,
    /// Numeric FROST identifier assigned to the sender in the canonical roster.
    pub sender_identifier: u16,
    /// Intended mesh node recipient for this private round-two package.
    pub recipient_node_id: String,
    /// Numeric FROST identifier assigned to the intended recipient.
    pub recipient_identifier: u16,
    /// SHA-384 transcript digest binding this message to the active session.
    pub transcript_hex: String,
    /// Serialized recipient-specific FROST round-two package encoded as hexadecimal.
    pub package_hex: String,
    /// Optional encrypted envelope for deployments that wrap wire payloads.
    #[serde(default)]
    pub envelope: Option<HybridEnvelope>,
}

/// Configuration and transcript inputs used to initialize a reshare session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareStartRequest {
    /// Caller-selected identifier for this reshare attempt.
    pub session_id: String,
    /// Total number of nodes in the roster.
    pub max_signers: u16,
    /// Minimum signer threshold for the refreshed key.
    pub min_signers: u16,
    /// Node IDs whose sorted order determines stable FROST identifiers.
    pub roster: Vec<String>,
    /// UTC day epoch to bind into the session transcript.
    pub day_epoch: String,
    /// Active constitution digest bound into the session transcript.
    pub constitution_hash: String,
}

/// Public progress snapshot for one local reshare session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireReshareStatus {
    /// Identifier of the reported reshare session.
    pub session_id: String,
    /// Stable lowercase label of the current protocol phase.
    pub phase: String,
    /// Node identifier of the vault producing this local status.
    pub local_node_id: String,
    /// Local node's numeric FROST identifier in the roster.
    pub local_identifier: u16,
    /// Total participant count frozen for this session.
    pub max_signers: u16,
    /// Required signer threshold frozen for this session.
    pub min_signers: u16,
    /// SHA-384 transcript digest all messages must match.
    pub transcript_hex: String,
    /// Number of round-one packages currently stored, including the local package.
    pub round1_received: usize,
    /// Number of remote round-two packages currently stored.
    pub round2_received: usize,
    /// Whether the local refreshed key share has been persisted successfully.
    pub complete: bool,
    /// Group verifying key as hex after completion; absent before finalization.
    pub verifying_key_hex: Option<String>,
}

// ── Session inner state ─────────────────────────────────────────────────────

struct ReshareSessionInner {
    session_id: String,
    local_node_id: String,
    local_identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    roster: BTreeMap<String, Identifier>,
    transcript_hex: String,
    day_epoch: DayEpoch,
    phase: WireResharePhase,
    round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    round1_packages: BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    round2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    round2_inbox: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
    round2_outbound: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
    old_key_package: Option<KeyPackage>,
    old_pubkey_package: PublicKeyPackage,
    new_key_package: Option<KeyPackage>,
    new_pubkey_package: Option<PublicKeyPackage>,
}

impl ReshareSessionInner {
    /// Derive a status view from the local phase and package maps.
    fn status(&self) -> WireReshareStatus {
        let verifying_key_hex =
            self.new_pubkey_package.as_ref().map(|pk| hex::encode(pk.verifying_key().serialize().unwrap_or_default()));
        WireReshareStatus {
            session_id: self.session_id.clone(),
            phase: self.phase.as_str().to_string(),
            local_node_id: self.local_node_id.clone(),
            local_identifier: identifier_to_u16(&self.roster, self.local_identifier),
            max_signers: self.max_signers,
            min_signers: self.min_signers,
            transcript_hex: self.transcript_hex.clone(),
            round1_received: self.round1_packages.len(),
            round2_received: self.round2_inbox.len(),
            complete: self.phase == WireResharePhase::Complete,
            verifying_key_hex,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Convert the one-based wire identifier to the FROST library identifier type.
fn identifier_from_u16(v: u16) -> Result<Identifier, DomainError> {
    Identifier::try_from(v).map_err(|e| DomainError::ThresholdError(format!("invalid identifier {v}: {e}")))
}

/// Find a FROST identifier in the roster and convert it back to its wire number.
/// Returns zero only when the identifier is not present in the roster.
fn identifier_to_u16(roster: &BTreeMap<String, Identifier>, id: Identifier) -> u16 {
    for ident in roster.values() {
        if *ident == id {
            return ident.serialize()[0] as u16;
        }
    }
    0
}

/// Assign stable one-based FROST identifiers from lexicographically sorted node IDs.
fn build_reshare_roster(roster: &[String]) -> Result<BTreeMap<String, Identifier>, DomainError> {
    let mut sorted: Vec<String> = roster.to_vec();
    sorted.sort();
    let mut map = BTreeMap::new();
    for (i, node) in sorted.into_iter().enumerate() {
        let id = identifier_from_u16((i + 1) as u16)?;
        map.insert(node, id);
    }
    Ok(map)
}

fn reshare_transcript(
    session_id: &str,
    day_epoch: &DayEpoch,
    max_signers: u16,
    min_signers: u16,
    roster: &BTreeMap<String, Identifier>,
    constitution_hash: &str,
) -> String {
    let mut h = Sha384::new();
    h.update(session_id.as_bytes());
    h.update(day_epoch.as_str().as_bytes());
    h.update(max_signers.to_be_bytes());
    h.update(min_signers.to_be_bytes());
    let mut sorted: Vec<&String> = roster.keys().collect();
    sorted.sort();
    for node in &sorted {
        h.update(node.as_bytes());
    }
    h.update(constitution_hash.as_bytes());
    hex::encode(h.finalize())
}

/// Require a reshare to preserve the group's public verifying key.
fn assert_vk_preserved(old: &PublicKeyPackage, new: &PublicKeyPackage, suite: &str) -> Result<(), DomainError> {
    if *old.verifying_key() != *new.verifying_key() {
        return Err(DomainError::ThresholdError(format!(
            "{suite} reshare changed group verifying key (deposit address would change)"
        )));
    }
    Ok(())
}

// ── HTTP client ─────────────────────────────────────────────────────────────

fn build_reshare_http_client(
    auth: &WireResharePeerAuth,
    peer_http: &PeerHttpSettings,
) -> Result<reqwest::Client, DomainError> {
    let builder = reqwest::Client::builder()
        .timeout(peer_http.backoff_delay(0).saturating_mul(3))
        .connect_timeout(std::time::Duration::from_secs(10));
    match auth {
        WireResharePeerAuth::StaticToken(_) => {
            builder.build().map_err(|e| DomainError::ThresholdError(format!("reshare http client: {e}")))
        }
        WireResharePeerAuth::MutualTls { client_cert_path, client_key_path, ca_path, verify } => {
            let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
            builder
                .use_preconfigured_tls(tls)
                .build()
                .map_err(|e| DomainError::ThresholdError(format!("reshare mTLS http: {e}")))
        }
    }
}

// ── Hub ─────────────────────────────────────────────────────────────────────

/// Coordinates one node's local FROST Taproot refresh protocol and peer message exchange.
pub struct WireReshareHub {
    local_node_id: String,
    peer_addrs: BTreeMap<String, String>,
    peer_auth: WireResharePeerAuth,
    peer_http: PeerHttpSettings,
    sessions: Mutex<BTreeMap<String, ReshareSessionInner>>,
    completed: Mutex<Option<(KeyPackage, PublicKeyPackage, u16)>>,
    http: reqwest::Client,
}

impl WireReshareHub {
    /// Create a hub using default clearnet HTTP retry settings.
    ///
    /// Static-token authentication selects HTTP; mutual TLS selects HTTPS and
    /// builds the TLS client from the supplied certificate paths.
    pub fn new(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        peer_auth: WireResharePeerAuth,
    ) -> Result<Self, DomainError> {
        let http = build_reshare_http_client(&peer_auth, &PeerHttpSettings::clearnet_defaults())?;
        Ok(Self {
            local_node_id: local_node_id.into(),
            peer_addrs,
            peer_auth,
            peer_http: PeerHttpSettings::clearnet_defaults(),
            sessions: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(None),
            http,
        })
    }

    /// Create a hub with explicit peer timeout/backoff settings.
    pub fn with_peer_http(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        peer_auth: WireResharePeerAuth,
        peer_http: PeerHttpSettings,
    ) -> Result<Self, DomainError> {
        let http = build_reshare_http_client(&peer_auth, &peer_http)?;
        Ok(Self {
            local_node_id: local_node_id.into(),
            peer_addrs,
            peer_auth,
            peer_http,
            sessions: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(None),
            http,
        })
    }

    /// Return the most recently finalized local key and public package, if any.
    pub fn completed_local(&self) -> Option<(KeyPackage, PublicKeyPackage, u16)> {
        self.completed.lock().expect("reshare completed").clone()
    }

    /// Return local progress for a session, or a threshold error if it is unknown.
    pub fn status(&self, session_id: &str) -> Result<WireReshareStatus, DomainError> {
        let g = self.sessions.lock().expect("reshare sessions");
        let s = g
            .get(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown reshare session: {session_id}")))?;
        Ok(s.status())
    }

    /// Start or idempotently resume round one for the supplied frozen roster and transcript.
    ///
    /// Existing sessions may be resumed only when transcript, roster, and
    /// threshold parameters match exactly. A new session requires this node to
    /// appear in the roster and retains the prior local key package for finalization.
    pub fn start(
        &self,
        req: ReshareStartRequest,
        old_pubkey_package: PublicKeyPackage,
        old_key_package: Option<KeyPackage>,
    ) -> Result<(WireReshareStatus, ReshareRound1WireMessage), DomainError> {
        let day_epoch = DayEpoch::parse(&req.day_epoch)
            .map_err(|e| DomainError::ThresholdError(format!("invalid day_epoch: {e}")))?;
        let roster = build_reshare_roster(&req.roster)?;
        if roster.len() as u16 != req.max_signers {
            return Err(DomainError::ThresholdError(format!(
                "roster len {} != max_signers {}",
                roster.len(),
                req.max_signers
            )));
        }
        let transcript_hex = reshare_transcript(
            &req.session_id,
            &day_epoch,
            req.max_signers,
            req.min_signers,
            &roster,
            &req.constitution_hash,
        );

        {
            let g = self.sessions.lock().expect("reshare sessions");
            if let Some(existing) = g.get(&req.session_id) {
                if existing.transcript_hex != transcript_hex
                    || existing.max_signers != req.max_signers
                    || existing.min_signers != req.min_signers
                    || existing.roster != roster
                {
                    return Err(DomainError::ThresholdError(
                        "reshare participants/threshold frozen at round1; constitution drift rejected".into(),
                    ));
                }
                let local_identifier = existing.local_identifier;
                let package = existing
                    .round1_packages
                    .get(&local_identifier)
                    .ok_or_else(|| DomainError::ThresholdError("missing local reshare round1 package".into()))?;
                let package_hex = hex::encode(
                    package
                        .serialize()
                        .map_err(|e| DomainError::ThresholdError(format!("reshare r1 serialize: {e}")))?,
                );
                let wire = ReshareRound1WireMessage {
                    session_id: existing.session_id.clone(),
                    sender_node_id: existing.local_node_id.clone(),
                    sender_identifier: identifier_to_u16(&existing.roster, local_identifier),
                    max_signers: existing.max_signers,
                    min_signers: existing.min_signers,
                    day_epoch: existing.day_epoch.as_str().to_string(),
                    transcript_hex: existing.transcript_hex.clone(),
                    package_hex,
                    envelope: None,
                };
                return Ok((existing.status(), wire));
            }
        }

        let local_identifier = *roster.get(&self.local_node_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("local node {} missing from reshare roster", self.local_node_id))
        })?;

        let rng = OsRng;
        let (secret, package) = refresh_dkg_part1(local_identifier, req.max_signers, req.min_signers, rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost refresh part1: {e}")))?;

        let package_hex = hex::encode(
            package.serialize().map_err(|e| DomainError::ThresholdError(format!("reshare r1 serialize: {e}")))?,
        );

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(local_identifier, package.clone());

        let inner = ReshareSessionInner {
            session_id: req.session_id.clone(),
            local_node_id: self.local_node_id.clone(),
            local_identifier,
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            roster,
            transcript_hex: transcript_hex.clone(),
            day_epoch,
            phase: WireResharePhase::Round1,
            round1_secret: Some(secret),
            round1_packages,
            round2_secret: None,
            round2_inbox: BTreeMap::new(),
            round2_outbound: BTreeMap::new(),
            old_key_package,
            old_pubkey_package,
            new_key_package: None,
            new_pubkey_package: None,
        };

        let wire = ReshareRound1WireMessage {
            session_id: req.session_id.clone(),
            sender_node_id: self.local_node_id.clone(),
            sender_identifier: identifier_to_u16(&inner.roster, local_identifier),
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            day_epoch: req.day_epoch,
            transcript_hex,
            package_hex,
            envelope: None,
        };
        let status = inner.status();
        self.sessions.lock().expect("reshare sessions").insert(req.session_id, inner);
        Ok((status, wire))
    }

    /// Validate and record one peer's round-one package; advances locally when the roster is complete.
    pub fn ingest_round1(&self, msg: ReshareRound1WireMessage) -> Result<WireReshareStatus, DomainError> {
        if let Some(ref env) = msg.envelope {
            env.validate_header().map_err(|e| DomainError::ThresholdError(format!("reshare r1 envelope: {e}")))?;
        }
        let mut g = self.sessions.lock().expect("reshare sessions");
        let session = g.get_mut(&msg.session_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("unknown reshare session {} (start locally first)", msg.session_id))
        })?;
        if session.phase == WireResharePhase::Complete {
            return Ok(session.status());
        }
        if msg.max_signers != session.max_signers || msg.min_signers != session.min_signers {
            return Err(DomainError::ThresholdError("reshare round1 threshold drift rejected".into()));
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("reshare round1 transcript binding mismatch".into()));
        }
        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "reshare late join rejected: unknown sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!(
                "reshare sender {} identifier mismatch",
                msg.sender_node_id
            )));
        }
        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("reshare r1 hex: {e}")))?;
        let package = frost::keys::dkg::round1::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("reshare r1 deserialize: {e}")))?;
        session.round1_packages.insert(sender_id, package);

        if session.round1_packages.len() as u16 == session.max_signers
            && session.round1_secret.is_some()
            && session.phase == WireResharePhase::Round1
        {
            Self::advance_to_round2(session)?;
        }
        Ok(session.status())
    }

    /// Consume the round-one secret and derive the local secret plus outbound round-two packages.
    fn advance_to_round2(session: &mut ReshareSessionInner) -> Result<(), DomainError> {
        let mut r1_received = session.round1_packages.clone();
        r1_received.remove(&session.local_identifier);
        let r1_secret = session
            .round1_secret
            .take()
            .ok_or_else(|| DomainError::ThresholdError("missing reshare round1 secret".into()))?;
        let (r2_secret, outbound) = refresh_dkg_part2(r1_secret, &r1_received)
            .map_err(|e| DomainError::ThresholdError(format!("frost refresh part2: {e}")))?;
        session.round2_secret = Some(r2_secret);
        session.round2_outbound = outbound;
        session.phase = WireResharePhase::Round2;
        Ok(())
    }

    /// Drain locally generated round-two packages into recipient-addressed wire messages.
    ///
    /// The packages are removed from the outbound map before serialization, so
    /// a serialization error does not automatically restore them for another call.
    pub fn take_round2_outbound(&self, session_id: &str) -> Result<Vec<ReshareRound2WireMessage>, DomainError> {
        let mut g = self.sessions.lock().expect("reshare sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown reshare session: {session_id}")))?;
        let mut out = Vec::new();
        let outbound = std::mem::take(&mut session.round2_outbound);
        for (recipient_id, package) in outbound {
            let recipient_node_id =
                session.roster.iter().find(|(_, id)| **id == recipient_id).map(|(n, _)| n.clone()).ok_or_else(
                    || DomainError::ThresholdError(format!("unknown reshare recipient id {recipient_id:?}")),
                )?;
            let package_hex = hex::encode(
                package.serialize().map_err(|e| DomainError::ThresholdError(format!("reshare r2 serialize: {e}")))?,
            );
            out.push(ReshareRound2WireMessage {
                session_id: session_id.to_string(),
                sender_node_id: session.local_node_id.clone(),
                sender_identifier: identifier_to_u16(&session.roster, session.local_identifier),
                recipient_node_id,
                recipient_identifier: identifier_to_u16(&session.roster, recipient_id),
                transcript_hex: session.transcript_hex.clone(),
                package_hex,
                envelope: None,
            });
        }
        Ok(out)
    }

    /// Validate recipient/transcript/sender binding and store a round-two peer package.
    pub fn ingest_round2(&self, msg: ReshareRound2WireMessage) -> Result<WireReshareStatus, DomainError> {
        if let Some(ref env) = msg.envelope {
            env.validate_header().map_err(|e| DomainError::ThresholdError(format!("reshare r2 envelope: {e}")))?;
        }
        let mut g = self.sessions.lock().expect("reshare sessions");
        let session = g
            .get_mut(&msg.session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown reshare session: {}", msg.session_id)))?;
        if session.phase == WireResharePhase::Complete {
            return Ok(session.status());
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("reshare round2 transcript binding mismatch".into()));
        }
        if msg.recipient_node_id != session.local_node_id {
            return Err(DomainError::ThresholdError("reshare round2 package not addressed to this vault".into()));
        }
        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "reshare late join rejected: unknown round2 sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!(
                "reshare sender {} identifier mismatch",
                msg.sender_node_id
            )));
        }
        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("reshare r2 hex: {e}")))?;
        let package = frost::keys::dkg::round2::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("reshare r2 deserialize: {e}")))?;
        session.round2_inbox.insert(sender_id, package);
        Ok(session.status())
    }

    /// Finalize the refreshed share after all remote round-two packages arrive, preserving the group key.
    ///
    /// Persists the private local package and public package via `share_store`
    /// before marking the session complete. The share identifier is scoped to
    /// the local FROST identifier.
    pub fn finalize(
        &self,
        session_id: &str,
        share_store: &dyn ShareStorePort,
    ) -> Result<WireReshareStatus, DomainError> {
        let mut g = self.sessions.lock().expect("reshare sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown reshare session: {session_id}")))?;
        if session.phase == WireResharePhase::Complete {
            return Ok(session.status());
        }
        let need = (session.max_signers as usize).saturating_sub(1);
        if session.round2_inbox.len() < need {
            return Err(DomainError::ThresholdError(format!(
                "reshare round2 incomplete: have {} need {need}",
                session.round2_inbox.len()
            )));
        }
        let r2_secret = session
            .round2_secret
            .as_ref()
            .ok_or_else(|| DomainError::ThresholdError("missing reshare round2 secret".into()))?;
        let mut r1_received = session.round1_packages.clone();
        r1_received.remove(&session.local_identifier);

        let old_pk = session.old_pubkey_package.clone();
        let old_kp = session
            .old_key_package
            .clone()
            .ok_or_else(|| DomainError::ThresholdError("missing old key package for reshare finalize".into()))?;

        let (kp, pk) = refresh_dkg_shares(r2_secret, &r1_received, &session.round2_inbox, old_pk.clone(), old_kp)
            .map_err(|e| DomainError::ThresholdError(format!("frost refresh part3: {e}")))?;

        if *kp.min_signers() != session.min_signers {
            return Err(DomainError::ThresholdError(format!(
                "reshare threshold drift: got {} want {}",
                kp.min_signers(),
                session.min_signers
            )));
        }
        assert_vk_preserved(&old_pk, &pk, "tr")?;

        let bytes =
            kp.serialize().map_err(|e| DomainError::ThresholdError(format!("reshare key package serialize: {e}")))?;
        let share_id = format!("frost-tr-reshare-id-{}", hex::encode(session.local_identifier.serialize()));
        share_store.put_share(&share_id, &bytes)?;
        let pk_bytes =
            pk.serialize().map_err(|e| DomainError::ThresholdError(format!("reshare pubkey serialize: {e}")))?;
        share_store.put_share("frost-tr-reshare-pubkey", &pk_bytes)?;

        session.new_key_package = Some(kp.clone());
        session.new_pubkey_package = Some(pk.clone());
        session.phase = WireResharePhase::Complete;
        session.round2_secret = None;

        *self.completed.lock().expect("reshare completed") = Some((kp, pk, session.min_signers));
        Ok(session.status())
    }

    /// Apply the configured static-token header; mTLS credentials are set on the client itself.
    fn apply_peer_auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.peer_auth {
            WireResharePeerAuth::StaticToken(token) => req.header("X-Vault-Token", token),
            WireResharePeerAuth::MutualTls { .. } => req,
        }
    }

    /// Send the round-one package to every configured remote peer with retry policy.
    pub async fn fanout_round1(&self, msg: &ReshareRound1WireMessage) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for (peer_id, addr) in &self.peer_addrs {
            if peer_id == &self.local_node_id {
                continue;
            }
            let base = if mtls { format!("https://{addr}") } else { format!("http://{addr}") };
            let url = format!("{base}/v1/reshare/tr/round1");
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| DomainError::ThresholdError(format!("reshare r1 fanout to {peer_id}: {e}")))?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!("reshare r1 fanout to {peer_id} failed: {body}")));
            }
        }
        Ok(())
    }

    /// Send each private round-two package to its named recipient with retry policy.
    pub async fn fanout_round2(&self, messages: &[ReshareRound2WireMessage]) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for msg in messages {
            let addr = self.peer_addrs.get(&msg.recipient_node_id).ok_or_else(|| {
                DomainError::ThresholdError(format!("unknown reshare peer: {}", msg.recipient_node_id))
            })?;
            let base = if mtls { format!("https://{addr}") } else { format!("http://{addr}") };
            let url = format!("{base}/v1/reshare/tr/round2");
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| {
                        DomainError::ThresholdError(format!("reshare r2 fanout to {}: {e}", msg.recipient_node_id))
                    })?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!(
                    "reshare r2 fanout to {} failed: {body}",
                    msg.recipient_node_id
                )));
            }
        }
        Ok(())
    }
}
