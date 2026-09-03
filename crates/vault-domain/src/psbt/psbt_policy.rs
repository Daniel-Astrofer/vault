//! Pure parameters used by the Bitcoin PSBT-policy adapter.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbfPolicy {
    Allow,
    Require,
    Forbid,
}

impl RbfPolicy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" | "any" => Some(Self::Allow),
            "require" | "rbf" => Some(Self::Require),
            "forbid" | "final" | "no_rbf" => Some(Self::Forbid),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Require => "require",
            Self::Forbid => "forbid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsbtPolicy {
    pub max_fee_sats: u64,
    pub max_fee_rate_sat_vb: u64,
    pub max_locktime: u32,
    pub rbf: RbfPolicy,
}

impl PsbtPolicy {
    pub fn lab_defaults() -> Self {
        Self { max_fee_sats: 50_000, max_fee_rate_sat_vb: 250, max_locktime: 0, rbf: RbfPolicy::Allow }
    }
}
