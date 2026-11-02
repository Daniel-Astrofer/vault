//! Over-wire multi-party FROST DKG (no dealer) — Production Gate.
//!
//! Each vault runs `part1`/`part2`/`part3` locally and exchanges only public
//! round packages over HTTP. Peer auth:
//! - `VAULT_AUTH_MODE=static_token` → `X-Vault-Token` (lab)
//! - `VAULT_AUTH_MODE=mtls` → HTTPS + client certificate (no static token)
//!
//! After part3 the vault persists **only its own** key package.
//!
//! ToB 2024 / Gate integrity:
//! - Participant set + `(max_signers, min_signers)` frozen at round1 start
//! - Reject threshold / min_signers drift on wire messages
//! - Reject late join / unknown senders after freeze
//! - Transcript binding: SHA-256 over session constitution on every round message
//!
//! Lab: `VAULT_DKG_MODE=distributed_wire` + compose peers, or in-process fallback
//! via `VAULT_DKG_MODE=distributed` (`DistributedDkgAdapter::run_in_process`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use frost_secp256k1 as frost;
use frost_secp256k1::keys::dkg::{round1, round2};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::application::ShareStorePort;
use crate::domain::DomainError;
use crate::{build_mtls_rustls_client_config, post_json_with_retry, PeerHttpSettings, TlsPeerVerifyPolicy};

/// Local protocol phase of a distributed wire DKG session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDkgPhase {
    /// Round-one public packages are being collected.
    Round1,
    /// Round-two private packages addressed to this node are being collected.
    Round2,
    /// The local key package was generated and persisted.
    Complete,
}

impl WireDkgPhase {
    /// Return the stable lowercase phase label used in status responses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Round1 => "round1",
            Self::Round2 => "round2",
            Self::Complete => "complete",
        }
    }
}

/// How this vault authenticates outbound DKG peer round posts.
#[derive(Debug, Clone)]
pub enum WireDkgPeerAuth {
    /// Lab: send `X-Vault-Token` over plain HTTP.
    StaticToken(String),
    /// Gate: mTLS client identity; never send static token header.
    MutualTls {
        /// PEM client certificate presented to the remote vault.
        client_cert_path: PathBuf,
        /// PEM private key corresponding to the client certificate.
        client_key_path: PathBuf,
        /// CA bundle used to validate the remote server certificate.
        ca_path: PathBuf,
        /// Peer certificate verification policy for the TLS connection.
        verify: TlsPeerVerifyPolicy,
    },
}

impl WireDkgPeerAuth {
    /// Return whether outbound posts use mutual TLS.
    pub fn is_mtls(&self) -> bool {
        matches!(self, Self::MutualTls { .. })
    }
}

/// Public round-one DKG package broadcast by each participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1WireMessage {
    /// Identifier shared by every participant in this DKG attempt.
    pub session_id: String,
    /// Mesh identity of the participant that generated the package.
    pub sender_node_id: String,
    /// One-based FROST identifier assigned from the sorted roster.
    pub sender_identifier: u16,
    /// Number of participants frozen into the session.
    pub max_signers: u16,
    /// Threshold required for the resulting key package.
    pub min_signers: u16,
    /// SHA-256 hex binding of frozen session constitution (see `session_transcript`).
    pub transcript_hex: String,
    /// Serialized public round-one package encoded as hexadecimal.
    pub package_hex: String,
    /// Optional hybrid envelope (X25519 + ML-KEM-768). When present the
    /// envelope must validate before the plain payload is accepted.
    #[serde(default)]
    pub envelope: Option<crate::domain::HybridEnvelope>,
}

/// Private round-two DKG package addressed to exactly one participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2WireMessage {
    /// Identifier shared by every participant in this DKG attempt.
    pub session_id: String,
    /// Mesh identity of the participant that generated the package.
    pub sender_node_id: String,
    /// One-based FROST identifier assigned to the sender.
    pub sender_identifier: u16,
    /// Intended receiver's mesh identity.
    pub recipient_node_id: String,
    /// One-based FROST identifier assigned to the recipient.
    pub recipient_identifier: u16,
    /// Must match the frozen round1 transcript.
    pub transcript_hex: String,
    /// Serialized recipient-specific round-two package encoded as hexadecimal.
    pub package_hex: String,
    /// Optional hybrid envelope. When present, must validate before
    /// the round2 package is processed.
    #[serde(default)]
    pub envelope: Option<crate::domain::HybridEnvelope>,
}

/// Optional round-three trigger request for a DKG session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round3WireRequest {
    /// Session to finalize on this vault.
    pub session_id: String,
    /// When true, run part3 if round2 inbox is full (idempotent if already complete).
    #[serde(default)]
    pub finalize: bool,
}

/// Frozen participant set and threshold parameters used to start distributed DKG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgStartRequest {
    /// Caller-selected session identifier.
    pub session_id: String,
    /// Total participant count expected in the roster.
    pub max_signers: u16,
    /// Minimum participant threshold for the generated key.
    pub min_signers: u16,
    /// Sorted unique node ids (includes self). Assigned frost ids 1..=n in sort order.
    pub roster: Vec<String>,
}

/// Public progress information for one local DKG session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireDkgStatus {
    /// Session identifier.
    pub session_id: String,
    /// Stable lowercase name of the current DKG phase.
    pub phase: String,
    /// Local vault's node identifier.
    pub local_node_id: String,
    /// Local node's one-based FROST participant identifier.
    pub local_identifier: u16,
    /// Total participants frozen into the transcript.
    pub max_signers: u16,
    /// Signature threshold frozen into the transcript.
    pub min_signers: u16,
    /// SHA-256 digest binding session id, thresholds, and sorted participants.
    pub transcript_hex: String,
    /// Number of round-one packages held, including the local package.
    pub round1_received: usize,
    /// Number of remote round-two packages held.
    pub round2_received: usize,
    /// Whether finalization and local persistence completed.
    pub complete: bool,
    /// Group verifying key in hex when available after completion.
    pub verifying_key_hex: Option<String>,
}

struct SessionInner {
    session_id: String,
    local_node_id: String,
    local_identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    /// Frozen at start — participant set may not change.
    roster: BTreeMap<String, Identifier>,
    /// Frozen constitution binding (ToB transcript).
    transcript_hex: String,
    /// True once round1 packages are full and part2 ran (blocks late join).
    roster_closed: bool,
    phase: WireDkgPhase,
    round1_secret: Option<round1::SecretPackage>,
    round1_packages: BTreeMap<Identifier, round1::Package>,
    round2_secret: Option<round2::SecretPackage>,
    /// Packages addressed to us (sender -> package)
    round2_inbox: BTreeMap<Identifier, round2::Package>,
    /// Outbound round2 packages we still need to deliver (recipient_id -> package)
    round2_outbound: BTreeMap<Identifier, round2::Package>,
    key_package: Option<KeyPackage>,
    pubkey_package: Option<PublicKeyPackage>,
}

impl SessionInner {
    /// Project mutable round state into a public status value.
    fn status(&self) -> WireDkgStatus {
        let verifying_key_hex =
            self.pubkey_package.as_ref().map(|pk| hex::encode(pk.verifying_key().serialize().unwrap_or_default()));
        WireDkgStatus {
            session_id: self.session_id.clone(),
            phase: self.phase.as_str().to_string(),
            local_node_id: self.local_node_id.clone(),
            local_identifier: identifier_to_u16(&self.roster, self.local_identifier),
            max_signers: self.max_signers,
            min_signers: self.min_signers,
            transcript_hex: self.transcript_hex.clone(),
            round1_received: self.round1_packages.len(),
            round2_received: self.round2_inbox.len(),
            complete: self.phase == WireDkgPhase::Complete,
            verifying_key_hex,
        }
    }
}

/// Convert a one-based wire identifier into the FROST library identifier type.
fn identifier_from_u16(v: u16) -> Result<Identifier, DomainError> {
    Identifier::try_from(v).map_err(|e| DomainError::ThresholdError(format!("identifier {v}: {e}")))
}

/// Roster is BTreeMap sorted by node_id; frost ids were assigned 1..=n in that order.
/// Convert a roster identifier back to its one-based wire number, or zero if absent.
fn identifier_to_u16(roster: &BTreeMap<String, Identifier>, id: Identifier) -> u16 {
    for (i, (_, rid)) in roster.iter().enumerate() {
        if *rid == id {
            return (i + 1) as u16;
        }
    }
    0
}

/// Trim, sort, and deduplicate node IDs, then assign stable one-based FROST identifiers.
fn build_roster(roster: &[String]) -> Result<BTreeMap<String, Identifier>, DomainError> {
    let mut sorted: Vec<String> = roster.iter().map(|s| s.trim().to_string()).collect();
    sorted.sort();
    sorted.dedup();
    if sorted.len() < 2 {
        return Err(DomainError::ThresholdError("DKG roster must have >= 2 unique node ids".into()));
    }
    let mut map = BTreeMap::new();
    for (i, node) in sorted.into_iter().enumerate() {
        let id = identifier_from_u16((i + 1) as u16)?;
        map.insert(node, id);
    }
    Ok(map)
}

/// Bind session_id + threshold + frozen participant set (ToB transcript).
pub fn session_transcript(
    session_id: &str,
    max_signers: u16,
    min_signers: u16,
    roster: &BTreeMap<String, Identifier>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"kerosene-dkg-wire-v1|");
    h.update(session_id.as_bytes());
    h.update(b"|max=");
    h.update(max_signers.to_string().as_bytes());
    h.update(b"|min=");
    h.update(min_signers.to_string().as_bytes());
    h.update(b"|roster=");
    for (i, node) in roster.keys().enumerate() {
        if i > 0 {
            h.update(b",");
        }
        h.update(node.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Confirm the generated private and public key packages match the frozen group dimensions.
fn assert_threshold(kp: &KeyPackage, pk: &PublicKeyPackage, min: u16, max: u16) -> Result<(), DomainError> {
    if *kp.min_signers() != min {
        return Err(DomainError::ThresholdError(format!(
            "DKG threshold mismatch (ToB): key_package.min_signers={} expected={min}",
            kp.min_signers()
        )));
    }
    if let Some(pk_min) = pk.min_signers() {
        if pk_min != min {
            return Err(DomainError::ThresholdError(format!(
                "DKG threshold mismatch (ToB): pubkey.min_signers={pk_min} expected={min}"
            )));
        }
    }
    if pk.max_signers() != max {
        return Err(DomainError::ThresholdError(format!(
            "DKG n mismatch: pubkey.max_signers={} expected={max}",
            pk.max_signers()
        )));
    }
    Ok(())
}

/// Build the HTTP transport and attach TLS configuration when peer auth selects mTLS.
fn build_http_client(auth: &WireDkgPeerAuth, peer_http: &PeerHttpSettings) -> Result<reqwest::Client, DomainError> {
    let builder = peer_http.apply_builder(reqwest::Client::builder())?;
    match auth {
        WireDkgPeerAuth::StaticToken(_) => {
            builder.build().map_err(|e| DomainError::ThresholdError(format!("dkg http client: {e}")))
        }
        WireDkgPeerAuth::MutualTls { client_cert_path, client_key_path, ca_path, verify } => {
            let tls = build_mtls_rustls_client_config(client_cert_path, client_key_path, ca_path, verify)?;
            builder
                .use_preconfigured_tls(tls)
                .build()
                .map_err(|e| DomainError::ThresholdError(format!("dkg mTLS http client: {e}")))
        }
    }
}

pub(super) fn peer_base_url(addr: &str, mtls: bool) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        if mtls && addr.starts_with("http://") {
            format!("https://{}", addr.trim_start_matches("http://"))
        } else {
            addr.to_string()
        }
    } else if mtls {
        format!("https://{addr}")
    } else {
        format!("http://{addr}")
    }
}

/// In-memory over-wire DKG hub for one vault process.
pub struct WireDkgHub {
    local_node_id: String,
    peer_addrs: BTreeMap<String, String>,
    peer_auth: WireDkgPeerAuth,
    peer_http: PeerHttpSettings,
    sessions: Mutex<BTreeMap<String, SessionInner>>,
    /// Completed local share (single session at a time for lab).
    completed: Mutex<Option<(KeyPackage, PublicKeyPackage, u16)>>,
    http: reqwest::Client,
}

impl WireDkgHub {
    /// Create a hub using default clearnet peer HTTP settings.
    pub fn new(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        peer_auth: WireDkgPeerAuth,
    ) -> Result<Self, DomainError> {
        Self::with_peer_http(local_node_id, peer_addrs, peer_auth, PeerHttpSettings::clearnet_defaults())
    }

    /// Create a hub using the supplied retry, timeout, and proxy settings.
    pub fn with_peer_http(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        peer_auth: WireDkgPeerAuth,
        peer_http: PeerHttpSettings,
    ) -> Result<Self, DomainError> {
        let http = build_http_client(&peer_auth, &peer_http)?;
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

    /// Lab convenience: static-token peer auth (no TLS).
    pub fn with_static_token(
        local_node_id: impl Into<String>,
        peer_addrs: BTreeMap<String, String>,
        token: impl Into<String>,
    ) -> Self {
        Self::new(local_node_id, peer_addrs, WireDkgPeerAuth::StaticToken(token.into()))
            .expect("static_token dkg http client")
    }

    /// Report the configured outbound peer authentication mode.
    pub fn peer_auth_mode(&self) -> &'static str {
        if self.peer_auth.is_mtls() {
            "mtls"
        } else {
            "static_token"
        }
    }

    /// Return the most recently completed local key package, if any.
    pub fn completed_local(&self) -> Option<(KeyPackage, PublicKeyPackage, u16)> {
        self.completed.lock().expect("dkg completed").clone()
    }

    /// Return status for a local session or an error if its identifier is unknown.
    pub fn status(&self, session_id: &str) -> Result<WireDkgStatus, DomainError> {
        let g = self.sessions.lock().expect("dkg sessions");
        let s = g
            .get(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown DKG session: {session_id}")))?;
        Ok(s.status())
    }

    /// Start local session: run part1, freeze roster+threshold, return wire message for fan-out.
    ///
    /// A repeated start is idempotent only when session id, roster, and thresholds
    /// match the original transcript. The local node must be included in that roster.
    pub fn start(&self, req: DkgStartRequest) -> Result<(WireDkgStatus, Round1WireMessage), DomainError> {
        if req.max_signers < 2 || req.min_signers < 2 || req.min_signers > req.max_signers {
            return Err(DomainError::ThresholdError(format!(
                "bad frost DKG params: max={} min={}",
                req.max_signers, req.min_signers
            )));
        }
        let roster = build_roster(&req.roster)?;
        if roster.len() as u16 != req.max_signers {
            return Err(DomainError::ThresholdError(format!(
                "roster len {} != max_signers {}",
                roster.len(),
                req.max_signers
            )));
        }
        let transcript_hex = session_transcript(&req.session_id, req.max_signers, req.min_signers, &roster);

        {
            let g = self.sessions.lock().expect("dkg sessions");
            if let Some(existing) = g.get(&req.session_id) {
                // Idempotent re-start only when constitution matches the freeze.
                if existing.transcript_hex != transcript_hex
                    || existing.max_signers != req.max_signers
                    || existing.min_signers != req.min_signers
                    || existing.roster != roster
                {
                    return Err(DomainError::ThresholdError(
                        "DKG participants/threshold frozen at round1; constitution drift rejected".into(),
                    ));
                }
                let local_identifier = existing.local_identifier;
                let package = existing
                    .round1_packages
                    .get(&local_identifier)
                    .ok_or_else(|| DomainError::ThresholdError("missing local round1 package".into()))?;
                let package_hex = hex::encode(
                    package.serialize().map_err(|e| DomainError::ThresholdError(format!("round1 serialize: {e}")))?,
                );
                let wire = Round1WireMessage {
                    session_id: existing.session_id.clone(),
                    sender_node_id: existing.local_node_id.clone(),
                    sender_identifier: identifier_to_u16(&existing.roster, local_identifier),
                    max_signers: existing.max_signers,
                    min_signers: existing.min_signers,
                    transcript_hex: existing.transcript_hex.clone(),
                    package_hex,
                    envelope: None,
                };
                return Ok((existing.status(), wire));
            }
        }

        let local_identifier = *roster.get(&self.local_node_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("local node {} missing from DKG roster", self.local_node_id))
        })?;

        let rng = OsRng;
        let (secret, package) = frost::keys::dkg::part1(local_identifier, req.max_signers, req.min_signers, rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost dkg part1: {e}")))?;

        let package_hex = hex::encode(
            package.serialize().map_err(|e| DomainError::ThresholdError(format!("round1 serialize: {e}")))?,
        );

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(local_identifier, package.clone());

        let inner = SessionInner {
            session_id: req.session_id.clone(),
            local_node_id: self.local_node_id.clone(),
            local_identifier,
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            roster,
            transcript_hex: transcript_hex.clone(),
            roster_closed: false,
            phase: WireDkgPhase::Round1,
            round1_secret: Some(secret),
            round1_packages,
            round2_secret: None,
            round2_inbox: BTreeMap::new(),
            round2_outbound: BTreeMap::new(),
            key_package: None,
            pubkey_package: None,
        };

        let wire = Round1WireMessage {
            session_id: req.session_id.clone(),
            sender_node_id: self.local_node_id.clone(),
            sender_identifier: identifier_to_u16(&inner.roster, local_identifier),
            max_signers: req.max_signers,
            min_signers: req.min_signers,
            transcript_hex,
            package_hex,
            envelope: None,
        };
        let status = inner.status();
        self.sessions.lock().expect("dkg sessions").insert(req.session_id, inner);
        Ok((status, wire))
    }

    /// Ingest a peer's round1 package. Auto-advances to part2 when all packages present.
    /// Unknown senders, changed thresholds/transcript, and late joins are rejected.
    pub fn ingest_round1(&self, msg: Round1WireMessage) -> Result<WireDkgStatus, DomainError> {
        // Validate hybrid envelope if present (fail-closed on invalid envelope).
        if let Some(ref env) = msg.envelope {
            env.validate_header()
                .map_err(|e| DomainError::ThresholdError(format!("round1 hybrid envelope validation failed: {e}")))?;
        }
        let mut g = self.sessions.lock().expect("dkg sessions");
        let session = g.get_mut(&msg.session_id).ok_or_else(|| {
            DomainError::ThresholdError(format!("unknown DKG session {} (start locally first)", msg.session_id))
        })?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }

        // Threshold / min_signers drift (ToB 2024 silent bump).
        if msg.max_signers != session.max_signers || msg.min_signers != session.min_signers {
            return Err(DomainError::ThresholdError(
                "round1 threshold/min_signers drift rejected (ToB); constitution frozen at start".into(),
            ));
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("round1 transcript binding mismatch; abort DKG".into()));
        }

        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "late join / participant set change rejected: unknown sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!("sender {} identifier mismatch", msg.sender_node_id)));
        }
        if sender_id == session.local_identifier {
            return Ok(session.status());
        }

        // Late join after roster closed (round2 started).
        if session.roster_closed || session.phase != WireDkgPhase::Round1 {
            if session.round1_packages.contains_key(&sender_id) {
                return Ok(session.status());
            }
            return Err(DomainError::ThresholdError("late join rejected: participant set frozen after round1".into()));
        }

        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("round1 hex: {e}")))?;
        let package = round1::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("round1 deserialize: {e}")))?;
        session.round1_packages.insert(sender_id, package);

        if session.round1_packages.len() as u16 == session.max_signers
            && session.round1_secret.is_some()
            && session.phase == WireDkgPhase::Round1
        {
            Self::advance_to_round2(session)?;
        }
        Ok(session.status())
    }

    /// Consume the round-one secret and create recipient-specific round-two packages.
    fn advance_to_round2(session: &mut SessionInner) -> Result<(), DomainError> {
        let secret =
            session.round1_secret.take().ok_or_else(|| DomainError::ThresholdError("missing round1 secret".into()))?;
        let mut received = session.round1_packages.clone();
        received.remove(&session.local_identifier);
        let (r2_secret, outbound) = frost::keys::dkg::part2(secret, &received)
            .map_err(|e| DomainError::ThresholdError(format!("frost dkg part2: {e}")))?;
        session.round2_secret = Some(r2_secret);
        session.round2_outbound = outbound;
        session.roster_closed = true;
        session.phase = WireDkgPhase::Round2;
        Ok(())
    }

    /// Packages this vault must send for round2 (after advance).
    /// The outbound map is drained before each package is serialized.
    pub fn take_round2_outbound(&self, session_id: &str) -> Result<Vec<Round2WireMessage>, DomainError> {
        let mut g = self.sessions.lock().expect("dkg sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown DKG session: {session_id}")))?;
        let mut out = Vec::new();
        let outbound = std::mem::take(&mut session.round2_outbound);
        for (recipient_id, package) in outbound {
            let recipient_node_id = session
                .roster
                .iter()
                .find(|(_, id)| **id == recipient_id)
                .map(|(n, _)| n.clone())
                .ok_or_else(|| DomainError::ThresholdError(format!("unknown recipient id {recipient_id:?}")))?;
            let package_hex = hex::encode(
                package.serialize().map_err(|e| DomainError::ThresholdError(format!("round2 serialize: {e}")))?,
            );
            out.push(Round2WireMessage {
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

    /// Validate and retain a peer's round-two package addressed to this vault.
    pub fn ingest_round2(&self, msg: Round2WireMessage) -> Result<WireDkgStatus, DomainError> {
        // Validate hybrid envelope if present (fail-closed).
        if let Some(ref env) = msg.envelope {
            env.validate_header()
                .map_err(|e| DomainError::ThresholdError(format!("round2 hybrid envelope validation failed: {e}")))?;
        }
        let mut g = self.sessions.lock().expect("dkg sessions");
        let session = g
            .get_mut(&msg.session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown DKG session: {}", msg.session_id)))?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }
        if msg.transcript_hex != session.transcript_hex {
            return Err(DomainError::ThresholdError("round2 transcript binding mismatch; abort DKG".into()));
        }
        if msg.recipient_node_id != session.local_node_id {
            return Err(DomainError::ThresholdError("round2 package not addressed to this vault".into()));
        }
        let sender_id = identifier_from_u16(msg.sender_identifier)?;
        let expected = session.roster.get(&msg.sender_node_id).copied();
        if expected.is_none() {
            return Err(DomainError::ThresholdError(format!(
                "late join / participant set change rejected: unknown round2 sender {}",
                msg.sender_node_id
            )));
        }
        if expected != Some(sender_id) {
            return Err(DomainError::ThresholdError(format!(
                "round2 sender {} identifier mismatch",
                msg.sender_node_id
            )));
        }
        let bytes =
            hex::decode(&msg.package_hex).map_err(|e| DomainError::ThresholdError(format!("round2 hex: {e}")))?;
        let package = round2::Package::deserialize(&bytes)
            .map_err(|e| DomainError::ThresholdError(format!("round2 deserialize: {e}")))?;
        session.round2_inbox.insert(sender_id, package);
        Ok(session.status())
    }

    /// Finalize part3 when round2 inbox has n-1 packages. Persists only local share.
    /// Repeated calls after completion return the existing status without regenerating keys.
    pub fn finalize_round3(
        &self,
        session_id: &str,
        share_store: &dyn ShareStorePort,
    ) -> Result<WireDkgStatus, DomainError> {
        let mut g = self.sessions.lock().expect("dkg sessions");
        let session = g
            .get_mut(session_id)
            .ok_or_else(|| DomainError::ThresholdError(format!("unknown DKG session: {session_id}")))?;
        if session.phase == WireDkgPhase::Complete {
            return Ok(session.status());
        }
        let need = (session.max_signers as usize).saturating_sub(1);
        if session.round2_inbox.len() < need {
            return Err(DomainError::ThresholdError(format!(
                "round2 incomplete: have {} need {need}",
                session.round2_inbox.len()
            )));
        }
        let r2_secret = session
            .round2_secret
            .as_ref()
            .ok_or_else(|| DomainError::ThresholdError("missing round2 secret".into()))?;
        let mut r1_received = session.round1_packages.clone();
        r1_received.remove(&session.local_identifier);
        let (kp, pk) = frost::keys::dkg::part3(r2_secret, &r1_received, &session.round2_inbox)
            .map_err(|e| DomainError::ThresholdError(format!("frost dkg part3: {e}")))?;
        assert_threshold(&kp, &pk, session.min_signers, session.max_signers)?;

        // Persist only this vault's share (+ group pubkey for verify).
        let bytes = kp.serialize().map_err(|e| DomainError::ThresholdError(format!("key package serialize: {e}")))?;
        let share_id = format!("frost-dkg-id-{}", hex::encode(session.local_identifier.serialize()));
        share_store.put_share(&share_id, &bytes)?;
        let pk_bytes = pk.serialize().map_err(|e| DomainError::ThresholdError(format!("pubkey serialize: {e}")))?;
        share_store.put_share("frost-dkg-pubkey", &pk_bytes)?;

        session.key_package = Some(kp.clone());
        session.pubkey_package = Some(pk.clone());
        session.phase = WireDkgPhase::Complete;
        session.round2_secret = None;

        *self.completed.lock().expect("dkg completed") = Some((kp, pk, session.min_signers));
        Ok(session.status())
    }

    /// Add the static token header when configured; mTLS identity is carried by the client.
    fn apply_peer_auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.peer_auth {
            WireDkgPeerAuth::StaticToken(token) => req.header("X-Vault-Token", token),
            WireDkgPeerAuth::MutualTls { .. } => req, // identity is on the client; no token
        }
    }

    /// Fan-out round1 package to configured peers (HTTP/HTTPS; SOCKS when Tor).
    pub async fn fanout_round1(&self, msg: &Round1WireMessage) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for (peer_id, addr) in &self.peer_addrs {
            if peer_id == &self.local_node_id {
                continue;
            }
            let url = format!("{}/v1/dkg/round1", peer_base_url(addr, mtls));
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| DomainError::ThresholdError(format!("round1 fanout to {peer_id}: {e}")))?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!("round1 fanout to {peer_id} failed: {body}")));
            }
        }
        Ok(())
    }

    /// Deliver private round-two messages only to their named recipients.
    pub async fn fanout_round2(&self, messages: &[Round2WireMessage]) -> Result<(), DomainError> {
        let mtls = self.peer_auth.is_mtls();
        for msg in messages {
            let addr = self
                .peer_addrs
                .get(&msg.recipient_node_id)
                .ok_or_else(|| DomainError::ThresholdError(format!("no peer addr for {}", msg.recipient_node_id)))?;
            let url = format!("{}/v1/dkg/round2", peer_base_url(addr, mtls));
            let res =
                post_json_with_retry(&self.http, &self.peer_http, &url, |req| self.apply_peer_auth_headers(req), msg)
                    .await
                    .map_err(|e| {
                        DomainError::ThresholdError(format!("round2 fanout to {}: {e}", msg.recipient_node_id))
                    })?;
            if !res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                return Err(DomainError::ThresholdError(format!(
                    "round2 fanout to {} failed: {body}",
                    msg.recipient_node_id
                )));
            }
        }
        Ok(())
    }
}

/// Port marker for `VAULT_DKG_MODE=distributed_wire` (no dealer).
pub struct DistributedWireDkgPort;

impl crate::application::DkgPort for DistributedWireDkgPort {
    fn mode_name(&self) -> &'static str {
        "distributed_wire"
    }

    fn is_dealer(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        AeadDiskShareStore, FrostSignOrchestrator, LedgerDayEpochStub, PersistedAntiNonce, SystemClock,
    };
    use std::sync::Arc;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-wire-dkg-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn three_hubs() -> (Vec<WireDkgHub>, Vec<String>, DkgStartRequest) {
        let roster = vec!["vault-1".into(), "vault-2".into(), "vault-3".into()];
        let hubs: Vec<WireDkgHub> = (1..=3)
            .map(|i| WireDkgHub::with_static_token(format!("vault-{i}"), BTreeMap::new(), "lab-token"))
            .collect();
        let start = DkgStartRequest {
            session_id: "sess-wire-1".into(),
            max_signers: 3,
            min_signers: 2,
            roster: roster.clone(),
        };
        (hubs, roster, start)
    }

    #[test]
    fn wire_dkg_three_party_message_exchange_no_dealer() {
        let (hubs, _roster, start) = three_hubs();
        let session = start.session_id.clone();

        let mut r1_msgs = Vec::new();
        for h in &hubs {
            let (_st, msg) = h.start(start.clone()).unwrap();
            assert!(!msg.transcript_hex.is_empty());
            r1_msgs.push(msg);
        }
        for (i, h) in hubs.iter().enumerate() {
            for (j, msg) in r1_msgs.iter().enumerate() {
                if i != j {
                    h.ingest_round1(msg.clone()).unwrap();
                }
            }
        }

        let mut r2_all = Vec::new();
        for h in &hubs {
            r2_all.extend(h.take_round2_outbound(&session).unwrap());
        }
        for msg in &r2_all {
            assert!(!msg.transcript_hex.is_empty());
            let idx = msg.recipient_node_id.trim_start_matches("vault-");
            let i: usize = idx.parse().unwrap();
            hubs[i - 1].ingest_round2(msg.clone()).unwrap();
        }

        let tmp = TempDir::new("wire");
        let mut key_packages = BTreeMap::new();
        let mut pubkey = None;
        for (i, h) in hubs.iter().enumerate() {
            let store = AeadDiskShareStore::new(tmp.0.join(format!("shares-{i}")), "lab-pass");
            let st = h.finalize_round3(&session, &store).unwrap();
            assert!(st.complete);
            let (kp, pk, min) = h.completed_local().unwrap();
            assert_eq!(min, 2);
            assert_eq!(*kp.min_signers(), 2);
            key_packages.insert(*kp.identifier(), kp);
            pubkey = Some(pk);
        }
        assert_eq!(key_packages.len(), 3);

        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation = LedgerDayEpochStub::new(Arc::new(SystemClock));
        let orch = FrostSignOrchestrator::new(key_packages, pubkey.unwrap(), 2, Box::new(anti), Arc::new(rotation));
        let r = orch.sign_lab_quorum("wire-sign-1", b"over-wire-dkg").unwrap();
        assert_eq!(r.participants, 2);
    }

    #[test]
    fn rejects_malicious_threshold_bump_on_round1() {
        let (hubs, _roster, start) = three_hubs();
        let (_st, mut msg) = hubs[0].start(start.clone()).unwrap();
        hubs[1].start(start).unwrap();

        msg.min_signers = 3;
        msg.transcript_hex = "deadbeef".into();
        let err = hubs[1].ingest_round1(msg).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("threshold") || s.contains("transcript") || s.contains("drift"), "unexpected err: {s}");
    }

    #[test]
    fn rejects_participant_set_change_and_late_join() {
        let (hubs, _roster, start) = three_hubs();
        let session = start.session_id.clone();
        let mut r1 = Vec::new();
        for h in &hubs {
            r1.push(h.start(start.clone()).unwrap().1);
        }
        hubs[0].ingest_round1(r1[1].clone()).unwrap();
        hubs[0].ingest_round1(r1[2].clone()).unwrap();
        assert_eq!(hubs[0].status(&session).unwrap().phase, "round2");

        let mut evil = r1[1].clone();
        evil.sender_node_id = "vault-evil".into();
        evil.sender_identifier = 99;
        let err = hubs[0].ingest_round1(evil).unwrap_err();
        assert!(err.to_string().contains("participant") || err.to_string().contains("late join"), "{err}");

        let mut late = r1[1].clone();
        late.package_hex = "00".repeat(64);
        late.sender_identifier = 3;
        let err2 = hubs[0].ingest_round1(late).unwrap_err();
        assert!(err2.to_string().contains("mismatch") || err2.to_string().contains("late"), "{err2}");

        let mut bumped = start.clone();
        bumped.roster.push("vault-4".into());
        bumped.max_signers = 4;
        let err3 = hubs[0].start(bumped).unwrap_err();
        assert!(err3.to_string().contains("frozen") || err3.to_string().contains("drift"), "{err3}");
    }

    #[test]
    fn rejects_transcript_mismatch_on_round2() {
        let (hubs, _roster, start) = three_hubs();
        let session = start.session_id.clone();
        let mut r1 = Vec::new();
        for h in &hubs {
            r1.push(h.start(start.clone()).unwrap().1);
        }
        for (i, h) in hubs.iter().enumerate() {
            for (j, msg) in r1.iter().enumerate() {
                if i != j {
                    h.ingest_round1(msg.clone()).unwrap();
                }
            }
        }
        let mut outbound = hubs[0].take_round2_outbound(&session).unwrap();
        assert!(!outbound.is_empty());
        outbound[0].transcript_hex = "00".repeat(32);
        let err = hubs[1].ingest_round2(outbound[0].clone()).unwrap_err();
        assert!(err.to_string().contains("transcript"), "{err}");
    }

    #[test]
    fn peer_base_url_forces_https_for_mtls() {
        assert_eq!(peer_base_url("vault-2:7701", true), "https://vault-2:7701");
        assert_eq!(peer_base_url("http://vault-2:7701", true), "https://vault-2:7701");
        assert_eq!(peer_base_url("vault-2:7701", false), "http://vault-2:7701");
    }

    #[test]
    fn mtls_peer_auth_refuses_building_without_files() {
        let Err(err) = WireDkgHub::new(
            "vault-1",
            BTreeMap::new(),
            WireDkgPeerAuth::MutualTls {
                client_cert_path: PathBuf::from("/no/such/client.crt"),
                client_key_path: PathBuf::from("/no/such/client.key"),
                ca_path: PathBuf::from("/no/such/ca.crt"),
                verify: TlsPeerVerifyPolicy::Hostname,
            },
        ) else {
            unreachable!("expected AuthRejected when mTLS files missing");
        };
        assert!(matches!(err, DomainError::AuthRejected(_)));
    }
}
