//! Pure parameters used by the Bitcoin PSBT-policy adapter.

/// Rule for whether a transaction may use replace-by-fee signaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbfPolicy {
    /// Permit either replaceable or non-replaceable transaction inputs.
    Allow,
    /// Require transaction inputs to signal replaceability.
    Require,
    /// Require final/non-replaceable transaction inputs.
    Forbid,
}

impl RbfPolicy {
    /// Parse the canonical policy name or a supported configuration alias.
    ///
    /// Parsing trims whitespace and ignores ASCII case. Returns `None` when
    /// the supplied value does not identify one of the three policies.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" | "any" => Some(Self::Allow),
            "require" | "rbf" => Some(Self::Require),
            "forbid" | "final" | "no_rbf" => Some(Self::Forbid),
            _ => None,
        }
    }

    /// Return the canonical lowercase configuration value for this policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Require => "require",
            Self::Forbid => "forbid",
        }
    }
}

/// Fee, locktime, and replaceability limits passed to the PSBT adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsbtPolicy {
    /// Maximum total transaction fee accepted by policy, in satoshis.
    pub max_fee_sats: u64,
    /// Maximum fee rate accepted by policy, in satoshis per virtual byte.
    pub max_fee_rate_sat_vb: u64,
    /// Highest absolute transaction locktime accepted by policy.
    pub max_locktime: u32,
    /// Whether replaceability is optional, required, or forbidden.
    pub rbf: RbfPolicy,
}

impl PsbtPolicy {
    /// Return the permissive lab limits used for local adapter exercises.
    ///
    /// These values are not a production fee recommendation; production callers
    /// should inject limits appropriate to their network and transaction class.
    pub fn lab_defaults() -> Self {
        Self { max_fee_sats: 50_000, max_fee_rate_sat_vb: 250, max_locktime: 0, rbf: RbfPolicy::Allow }
    }
}
