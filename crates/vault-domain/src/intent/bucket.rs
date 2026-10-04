//! Treasury buckets: USERS / PROFIT / MINERS / CHANNELS / INFRA (F6).

use std::collections::BTreeSet;

use crate::DomainError;

/// Treasury partition that scopes settlement funds, limits, and key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BucketKind {
    /// User-owned funds; the only bucket allowed to use the shared USERS Taproot key.
    Users,
    /// Incoming profit before allocation into operational pools.
    Profit,
    /// Pool reserved for bank-issued miner payouts.
    Miners,
    /// Pool for channel operations and rebalancing.
    Channels,
    /// Pool for infrastructure expenses.
    Infra,
}

impl BucketKind {
    /// Parse a bucket name after trimming whitespace and ignoring ASCII case.
    ///
    /// Returns [`DomainError::InvalidBucket`] for any name outside the five
    /// canonical bucket identifiers.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "USERS" => Ok(Self::Users),
            "PROFIT" => Ok(Self::Profit),
            "MINERS" => Ok(Self::Miners),
            "CHANNELS" => Ok(Self::Channels),
            "INFRA" => Ok(Self::Infra),
            _ => Err(DomainError::InvalidBucket(raw.to_string())),
        }
    }

    /// Return the canonical uppercase identifier used in configuration and wire data.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Users => "USERS",
            Self::Profit => "PROFIT",
            Self::Miners => "MINERS",
            Self::Channels => "CHANNELS",
            Self::Infra => "INFRA",
        }
    }

    /// Operational buckets must never debit the USERS omnibus.
    pub fn may_debit_users(self) -> bool {
        matches!(self, Self::Users)
    }

    /// Shared Taproot FROST deposit key (USERS omnibus `tr()` / `tb1p`) may only be
    /// spent under USERS policy. CHANNELS has its **own** Taproot keyset — never this one.
    pub fn may_use_shared_taproot_key(self) -> bool {
        matches!(self, Self::Users)
    }

    /// Dedicated CHANNELS Taproot FROST key (≠ USERS omnibus).
    pub fn may_use_channels_taproot_key(self) -> bool {
        matches!(self, Self::Channels)
    }
}

/// Refuse client-chosen bucket escape against the shared mesh Taproot key (USERS-only).
///
/// Returns [`DomainError::InvalidIntent`] for every bucket except [`BucketKind::Users`].
pub fn assert_shared_taproot_bucket(bucket: BucketKind) -> Result<(), DomainError> {
    if !bucket.may_use_shared_taproot_key() {
        return Err(DomainError::InvalidIntent(format!(
            "bucket {} cannot spend shared Taproot key; only USERS (CHANNELS uses its own key)",
            bucket.as_str()
        )));
    }
    Ok(())
}

/// CHANNELS Taproot spends must use the CHANNELS key — not USERS omnibus.
///
/// Returns [`DomainError::InvalidIntent`] for every bucket except [`BucketKind::Channels`].
pub fn assert_channels_taproot_bucket(bucket: BucketKind) -> Result<(), DomainError> {
    if !bucket.may_use_channels_taproot_key() {
        return Err(DomainError::InvalidIntent(format!(
            "bucket {} cannot spend CHANNELS Taproot key",
            bucket.as_str()
        )));
    }
    Ok(())
}

/// How PROFIT is split across child buckets (basis points, sum = 10_000).
///
/// TODO(4.1): Add `treasury_bps` field when treasury allocation is decided.
/// Current placeholders: miners=0 (lab) or p_reward (open), channels/infra = rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitSplits {
    /// Share of profit credited to MINERS, in basis points.
    pub miners_bps: u32,
    /// Share of profit credited to CHANNELS, in basis points.
    pub channels_bps: u32,
    /// Share of profit credited to INFRA, in basis points.
    pub infra_bps: u32,
}

impl ProfitSplits {
    /// Lab dry-run: miners payout `p%=0`; channels/infra split the rest evenly.
    pub fn lab_dry_run() -> Self {
        Self { miners_bps: 0, channels_bps: 5_000, infra_bps: 5_000 }
    }

    /// Explicit splits (must sum to 10_000 bps).
    pub fn explicit(miners_bps: u32, channels_bps: u32, infra_bps: u32) -> Result<Self, DomainError> {
        let s = Self { miners_bps, channels_bps, infra_bps };
        s.validate()?;
        Ok(s)
    }

    /// Open economy: miners get `p_reward_bps` of PROFIT; remainder split channels/infra.
    pub fn open_with_reward(p_reward_bps: u32) -> Result<Self, DomainError> {
        if p_reward_bps > 10_000 {
            return Err(DomainError::InvalidConstitution("p_reward_bps > 10000".into()));
        }
        let rest = 10_000 - p_reward_bps;
        let channels = rest / 2;
        let infra = rest - channels;
        Self::explicit(p_reward_bps, channels, infra)
    }

    /// Require the three allocations to total exactly 10,000 basis points.
    ///
    /// Uses saturating addition, so an overflow cannot wrap into an apparently
    /// valid split. Returns [`DomainError::InvalidConstitution`] otherwise.
    pub fn validate(&self) -> Result<(), DomainError> {
        let sum = self.miners_bps.saturating_add(self.channels_bps).saturating_add(self.infra_bps);
        if sum != 10_000 {
            return Err(DomainError::InvalidConstitution(format!("profit splits must sum to 10000 bps, got {sum}")));
        }
        Ok(())
    }

    /// Allocate satoshis according to these proportions using integer floor rounding.
    ///
    /// The INFRA allocation receives the remainder after MINERS and CHANNELS,
    /// preserving the full input total even when the first two divisions round down.
    pub fn allocate(&self, profit_sats: u64) -> (u64, u64, u64) {
        let miners = profit_sats.saturating_mul(self.miners_bps as u64) / 10_000;
        let channels = profit_sats.saturating_mul(self.channels_bps as u64) / 10_000;
        let infra = profit_sats.saturating_sub(miners).saturating_sub(channels);
        (miners, channels, infra)
    }
}

/// Destination and spend-limit rules for one treasury bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketPolicy {
    /// Bucket to which this policy and its limits apply.
    pub kind: BucketKind,
    /// Maximum permitted amount for one settlement, in satoshis.
    pub max_per_tx_sats: u64,
    /// Maximum cumulative amount permitted per day, in satoshis.
    pub max_per_day_sats: u64,
    /// Exact destination strings admitted for this bucket.
    pub destination_allowlist: BTreeSet<String>,
}

impl BucketPolicy {
    /// Construct a policy with caller-supplied caps and the bucket's lab destination tags.
    ///
    /// These opaque defaults support lab flows; production addresses still need
    /// the relevant network validation at the service boundary.
    pub fn lab_defaults(kind: BucketKind, max_tx: u64, max_day: u64) -> Self {
        let mut destination_allowlist = BTreeSet::new();
        match kind {
            BucketKind::Users => {
                // Lab opaque tags (testnet3); real bc1 mainnet addresses are rejected by network policy.
                destination_allowlist.insert("tb1q-users-withdraw".into());
                destination_allowlist.insert("ln-users-withdraw".into());
            }
            BucketKind::Profit => {
                destination_allowlist.insert("internal-profit-split".into());
            }
            BucketKind::Miners => {
                destination_allowlist.insert("tb1q-miner-payout".into());
            }
            BucketKind::Channels => {
                destination_allowlist.insert("ln-channel-rebalance".into());
            }
            BucketKind::Infra => {
                destination_allowlist.insert("tb1q-infra-ops".into());
            }
        }
        Self { kind, max_per_tx_sats: max_tx, max_per_day_sats: max_day, destination_allowlist }
    }

    /// Check exact membership in the configured destination allowlist.
    pub fn allows_destination(&self, dest: &str) -> bool {
        self.destination_allowlist.contains(dest)
    }

    /// CHANNELS policy-exception: allowlisted opaque tags **or** any valid Bitcoin
    /// address on `network` (LND funding inject). USERS stays strict allowlist-only.
    pub fn allows_destination_for_network(&self, dest: &str, network: crate::BitcoinNetwork) -> bool {
        if self.allows_destination(dest) {
            return true;
        }
        if self.kind != BucketKind::Channels {
            return false;
        }
        crate::validate_destination(network, dest).is_ok() && is_explicit_bitcoin_address(dest)
    }

    /// Admit an explicit destination into this bucket's allowlist (config / Intent registry).
    pub fn admit_destination(&mut self, dest: impl Into<String>) {
        let d = dest.into();
        if !d.trim().is_empty() {
            self.destination_allowlist.insert(d);
        }
    }

    /// Merge config / Intent-registered destinations into the policy allowlist.
    pub fn extend_destinations<I, S>(&mut self, dests: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for d in dests {
            self.admit_destination(d);
        }
    }
}

/// Settlement intent as seen by the vault enclave (mirrors contracts Intent fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementIntent {
    /// Unique identifier used for deduplication and replay protection by consumers.
    pub intent_id: String,
    /// Treasury bucket whose policy governs this payment.
    pub bucket: BucketKind,
    /// Exact registered destination receiving the funds.
    pub destination: String,
    /// Requested transfer amount in satoshis; positivity and caps are checked at evaluation.
    pub amount_sats: u64,
    /// Hash of the policy snapshot the issuer used to create this intent.
    pub policy_hash: String,
    /// Hybrid signature (Ed25519 + ML-DSA-65) over canonical intent hash.
    /// None = pre-hybrid intent (allowed if downgrade policy permits).
    pub signature: Option<crate::IntentSignature>,
}

impl SettlementIntent {
    /// Maximum accepted UTF-8 byte length for an intent identifier.
    pub const MAX_ID_LEN: usize = 128;
    /// Maximum accepted UTF-8 byte length for a destination string.
    pub const MAX_DEST_LEN: usize = 256;

    /// Validate structural bounds and create an unsigned settlement intent.
    ///
    /// This checks identifier characters, destination path-like content, and
    /// policy-hash length. It does not enforce the bucket allowlist, amount caps,
    /// network address validity, or signature validity; those belong to subsequent gates.
    pub fn new(
        intent_id: impl Into<String>,
        bucket: BucketKind,
        destination: impl Into<String>,
        amount_sats: u64,
        policy_hash: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let intent_id = intent_id.into();
        let destination = destination.into();
        let policy_hash = policy_hash.into();
        if intent_id.trim().is_empty() {
            return Err(DomainError::InvalidIntent("empty intent_id".into()));
        }
        if intent_id.len() > Self::MAX_ID_LEN {
            return Err(DomainError::InvalidIntent("intent_id too long".into()));
        }
        if intent_id.chars().any(|c| c.is_control() || c == '/' || c == '\\') {
            return Err(DomainError::InvalidIntent("intent_id contains illegal characters".into()));
        }
        if destination.trim().is_empty() {
            return Err(DomainError::InvalidIntent("empty destination".into()));
        }
        if destination.len() > Self::MAX_DEST_LEN {
            return Err(DomainError::InvalidIntent("destination too long".into()));
        }
        if destination.contains("..") || destination.contains('/') || destination.contains('\\') {
            return Err(DomainError::InvalidIntent("destination path traversal rejected".into()));
        }
        if policy_hash.len() > 128 {
            return Err(DomainError::InvalidIntent("policy_hash too long".into()));
        }
        Ok(Self { intent_id, bucket, destination, amount_sats, policy_hash, signature: None })
    }

    /// Attach a hybrid intent signature. Consumers validate it via
    /// `IntentSignature::validate_stub` before executing the intent.
    pub fn with_signature(mut self, sig: crate::IntentSignature) -> Self {
        self.signature = Some(sig);
        self
    }
}

/// Apply pure settlement gates for bucket binding, policy version, limits, and destination.
///
/// `spent_today_sats` is the amount already charged to this bucket for the day;
/// the requested amount is added with saturating arithmetic before comparison
/// with the daily cap. CHANNELS alone accepts the explicit Bitcoin-address
/// shape used by LND funding injection when the exact destination is not
/// allowlisted; actual network/address validation is performed at the HTTP edge.
/// This function performs no I/O and does not verify intent signatures.
///
/// Returns a domain error for policy mismatch, zero or over-cap amounts,
/// protected bucket use, or a destination rejected by the applicable rule.
pub fn evaluate_intent(
    intent: &SettlementIntent,
    policy: &BucketPolicy,
    spent_today_sats: u64,
    active_policy_hash: &str,
) -> Result<(), DomainError> {
    if policy.kind != intent.bucket {
        return Err(DomainError::InvalidIntent("bucket/policy mismatch".into()));
    }
    if intent.policy_hash != active_policy_hash {
        return Err(DomainError::InvalidIntent("policy_hash mismatch with active constitution".into()));
    }
    if !intent.bucket.may_debit_users() && intent.bucket == BucketKind::Users {
        unreachable!();
    }
    // Cross-bucket isolation: operational buckets never use USERS policy.
    if !intent.bucket.may_debit_users() && policy.kind == BucketKind::Users {
        return Err(DomainError::UsersOmnibusProtected);
    }
    if intent.amount_sats == 0 {
        return Err(DomainError::InvalidIntent("amount must be > 0".into()));
    }
    if intent.amount_sats > policy.max_per_tx_sats {
        return Err(DomainError::CapExceeded {
            amount: intent.amount_sats,
            cap: policy.max_per_tx_sats,
            scope: "per_tx".into(),
        });
    }
    let day_total = spent_today_sats.saturating_add(intent.amount_sats);
    if day_total > policy.max_per_day_sats {
        return Err(DomainError::CapExceeded {
            amount: day_total,
            cap: policy.max_per_day_sats,
            scope: "per_day".into(),
        });
    }
    // CHANNELS policy-exception: opaque allowlist tags **or** parseable Bitcoin
    // addresses (LND funding inject). Network HRP checked at HTTP edge via
    // validate_destination. USERS/others stay strict allowlist-only.
    let dest_ok = if policy.allows_destination(&intent.destination) {
        true
    } else if policy.kind == BucketKind::Channels {
        is_explicit_bitcoin_address(&intent.destination)
    } else {
        false
    };
    if !dest_ok {
        return Err(DomainError::DestinationNotAllowed(intent.destination.clone()));
    }
    Ok(())
}

/// Apply the narrow address-prefix/length heuristic used by the CHANNELS exception.
///
/// This is not a checksum or network validator; callers that accept this shape
/// must also use [`crate::validate_destination`] at the network boundary.
fn is_explicit_bitcoin_address(destination: &str) -> bool {
    let destination = destination.trim().to_ascii_lowercase();
    (destination.starts_with("tb1")
        || destination.starts_with('m')
        || destination.starts_with('n')
        || destination.starts_with('2'))
        && destination.len() >= 14
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_cap_rejects_oversize_tx() {
        let policy = BucketPolicy::lab_defaults(BucketKind::Users, 100, 1_000);
        let intent = SettlementIntent::new("i1", BucketKind::Users, "tb1q-users-withdraw", 101, "ph").unwrap();
        assert!(evaluate_intent(&intent, &policy, 0, "ph").is_err());
    }

    #[test]
    fn profit_split_lab_dry_run_miners_zero() {
        let s = ProfitSplits::lab_dry_run();
        s.validate().unwrap();
        let (m, c, i) = s.allocate(10_000);
        assert_eq!(m, 0);
        assert_eq!(c, 5_000);
        assert_eq!(i, 5_000);
    }

    #[test]
    fn shared_taproot_key_users_only_channels_has_own() {
        assert!(BucketKind::Users.may_use_shared_taproot_key());
        assert!(!BucketKind::Channels.may_use_shared_taproot_key());
        assert!(BucketKind::Channels.may_use_channels_taproot_key());
        assert!(!BucketKind::Users.may_use_channels_taproot_key());
        assert!(assert_shared_taproot_bucket(BucketKind::Users).is_ok());
        assert!(assert_shared_taproot_bucket(BucketKind::Channels).is_err());
        assert!(assert_channels_taproot_bucket(BucketKind::Channels).is_ok());
        assert!(assert_channels_taproot_bucket(BucketKind::Users).is_err());
    }

    #[test]
    fn users_requires_explicit_allowlist_not_any_parseable_address() {
        let mut policy = BucketPolicy::lab_defaults(BucketKind::Users, 100, 1_000);
        assert!(policy.allows_destination("tb1q-users-withdraw"));
        // Soft allowlist removed: parseable ≠ allowlisted.
        assert!(!policy.allows_destination("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
        policy.admit_destination("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert!(policy.allows_destination("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
        let channels = BucketPolicy::lab_defaults(BucketKind::Channels, 100, 1_000);
        assert!(!channels.allows_destination("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
        // CHANNELS policy-exception: valid network addresses allowed for LND inject.
        assert!(channels.allows_destination_for_network(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            crate::BitcoinNetwork::Testnet3,
        ));
    }

    #[test]
    fn evaluate_rejects_users_destination_off_allowlist() {
        let policy = BucketPolicy::lab_defaults(BucketKind::Users, 100, 1_000);
        let intent =
            SettlementIntent::new("i-off", BucketKind::Users, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 50, "ph")
                .unwrap();
        let err = evaluate_intent(&intent, &policy, 0, "ph").unwrap_err();
        assert!(matches!(err, DomainError::DestinationNotAllowed(_)));
    }
}
