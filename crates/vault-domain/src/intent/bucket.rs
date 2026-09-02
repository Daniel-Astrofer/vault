//! Treasury buckets: USERS / PROFIT / MINERS / CHANNELS / INFRA (F6).

use std::collections::BTreeSet;

use crate::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BucketKind {
    Users,
    Profit,
    Miners,
    Channels,
    Infra,
}

impl BucketKind {
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
    pub miners_bps: u32,
    pub channels_bps: u32,
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

    pub fn validate(&self) -> Result<(), DomainError> {
        let sum = self.miners_bps.saturating_add(self.channels_bps).saturating_add(self.infra_bps);
        if sum != 10_000 {
            return Err(DomainError::InvalidConstitution(format!("profit splits must sum to 10000 bps, got {sum}")));
        }
        Ok(())
    }

    pub fn allocate(&self, profit_sats: u64) -> (u64, u64, u64) {
        let miners = profit_sats.saturating_mul(self.miners_bps as u64) / 10_000;
        let channels = profit_sats.saturating_mul(self.channels_bps as u64) / 10_000;
        let infra = profit_sats.saturating_sub(miners).saturating_sub(channels);
        (miners, channels, infra)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketPolicy {
    pub kind: BucketKind,
    pub max_per_tx_sats: u64,
    pub max_per_day_sats: u64,
    pub destination_allowlist: BTreeSet<String>,
}

impl BucketPolicy {
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
    pub intent_id: String,
    pub bucket: BucketKind,
    pub destination: String,
    pub amount_sats: u64,
    pub policy_hash: String,
    /// Hybrid signature (Ed25519 + ML-DSA-65) over canonical intent hash.
    /// None = pre-hybrid intent (allowed if downgrade policy permits).
    pub signature: Option<crate::IntentSignature>,
}

impl SettlementIntent {
    pub const MAX_ID_LEN: usize = 128;
    pub const MAX_DEST_LEN: usize = 256;

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

/// Pure gate: caps, allowlist, bucket isolation (no I/O).
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
