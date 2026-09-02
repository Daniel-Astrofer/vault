//! In-memory + process-local persisted miner economy state (F9).
//!
//! # Persistence honesty (#18)
//! `PersistedEconomy` snapshots atomically under `VAULT_DATA_DIR` via
//! [`super::durable_fs::atomic_write_fsync`]. Restart retains pool / operators /
//! accruals on that host. **Not** an authenticated append-only mesh BFT ledger.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::durable_fs::atomic_write_fsync;
use super::sync_util::lock_mutex;

use crate::application::ports::EconomyPort;
use crate::domain::{
    DomainError, EconomyState, GovernanceAccrual, GovernanceJobKind, GovernanceRewardConfig, MinerOperator, NodeId,
    ProfitSplitAccrual, ProfitSplits, RewardPolicy,
};

pub struct InMemoryEconomy {
    inner: Mutex<EconomyState>,
}

impl InMemoryEconomy {
    pub fn new(state: EconomyState) -> Self {
        Self { inner: Mutex::new(state) }
    }

    pub fn open() -> Self {
        Self::new(EconomyState::new_open())
    }
}

impl EconomyPort for InMemoryEconomy {
    fn snapshot(&self) -> Result<EconomyState, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.clone())
    }

    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.upsert_operator(op)
    }

    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.accrue_from_profit(profit_sats, p_reward_bps))
    }

    fn accrue_profit_splits(&self, profit_sats: u64, splits: &ProfitSplits) -> Result<ProfitSplitAccrual, DomainError> {
        lock_mutex(&self.inner, "economy")?.accrue_profit_splits(profit_sats, splits)
    }

    fn accrue_governance_job(
        &self,
        job: GovernanceJobKind,
        participants: &[NodeId],
        config: &GovernanceRewardConfig,
    ) -> Result<GovernanceAccrual, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.accrue_governance_job(job, participants, config))
    }

    fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<crate::domain::MinerPayoutShare>, DomainError> {
        lock_mutex(&self.inner, "economy")?.propose_equal_payouts(amount)
    }

    fn debit_pool(&self, amount: u64) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.debit_pool(amount)
    }

    fn record_miner_payout(&self, at_secs: u64, epoch: Option<u64>) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.record_miner_payout(at_secs, epoch);
        Ok(())
    }
}

/// Process-local durable economy snapshot (atomic JSON + fsync).
pub struct PersistedEconomy {
    path: PathBuf,
    inner: Mutex<EconomyState>,
}

impl PersistedEconomy {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DomainError> {
        let path = path.into();
        let state = if path.exists() { load_economy(&path)? } else { EconomyState::new_open() };
        let eco = Self { path, inner: Mutex::new(state) };
        eco.persist()?;
        Ok(eco)
    }

    fn persist(&self) -> Result<(), DomainError> {
        let state = lock_mutex(&self.inner, "economy")?.clone();
        let json = serialize_economy(&state);
        atomic_write_fsync(&self.path, json.as_bytes())
            .map_err(|e| DomainError::ThresholdError(format!("economy persist: {e}")))
    }
}

impl EconomyPort for PersistedEconomy {
    fn snapshot(&self) -> Result<EconomyState, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.clone())
    }

    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.upsert_operator(op)?;
        self.persist()
    }

    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError> {
        let got = lock_mutex(&self.inner, "economy")?.accrue_from_profit(profit_sats, p_reward_bps);
        self.persist()?;
        Ok(got)
    }

    fn accrue_profit_splits(&self, profit_sats: u64, splits: &ProfitSplits) -> Result<ProfitSplitAccrual, DomainError> {
        let got = lock_mutex(&self.inner, "economy")?.accrue_profit_splits(profit_sats, splits)?;
        self.persist()?;
        Ok(got)
    }

    fn accrue_governance_job(
        &self,
        job: GovernanceJobKind,
        participants: &[NodeId],
        config: &GovernanceRewardConfig,
    ) -> Result<GovernanceAccrual, DomainError> {
        let got = lock_mutex(&self.inner, "economy")?.accrue_governance_job(job, participants, config);
        self.persist()?;
        Ok(got)
    }

    fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<crate::domain::MinerPayoutShare>, DomainError> {
        lock_mutex(&self.inner, "economy")?.propose_equal_payouts(amount)
    }

    fn debit_pool(&self, amount: u64) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.debit_pool(amount)?;
        self.persist()
    }

    fn record_miner_payout(&self, at_secs: u64, epoch: Option<u64>) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.record_miner_payout(at_secs, epoch);
        self.persist()
    }
}

fn serialize_economy(state: &EconomyState) -> String {
    let ops: Vec<String> = state
        .operators
        .values()
        .map(|o| {
            format!(
                r#"{{"node_id":"{}","payout_destination":"{}","uptime_bps_30d":{},"attestation_streak_days":{},"bond_sats":{},"waiting":{}}}"#,
                escape(o.node_id.as_str()),
                escape(&o.payout_destination),
                o.uptime_bps_30d,
                o.attestation_streak_days,
                o.bond_sats,
                o.waiting
            )
        })
        .collect();
    let credits: Vec<String> = state
        .governance_credits
        .iter()
        .map(|(k, v)| format!(r#"{{"node_id":"{}","sats":{}}}"#, escape(k), v))
        .collect();
    let last_at = state.last_miner_payout_at_secs.map(|n| n.to_string()).unwrap_or_else(|| "null".into());
    let last_ep = state.last_miner_payout_epoch.map(|n| n.to_string()).unwrap_or_else(|| "null".into());
    format!(
        r#"{{"version":1,"miner_pool_sats":{},"channels_pool_sats":{},"infra_pool_sats":{},"accrued_profit_sats":{},"pending_governance_reward_sats":{},"crypto_suite_id_pq":"{}","last_miner_payout_at_secs":{},"last_miner_payout_epoch":{},"policy":{{"min_uptime_bps_30d":{},"min_attestation_streak_days":{},"min_bond_sats":{},"waiting_pool_share_bps":{}}},"operators":[{}],"governance_credits":[{}]}}"#,
        state.miner_pool_sats,
        state.channels_pool_sats,
        state.infra_pool_sats,
        state.accrued_profit_sats,
        state.pending_governance_reward_sats,
        escape(&state.crypto_suite_id_pq),
        last_at,
        last_ep,
        state.policy.min_uptime_bps_30d,
        state.policy.min_attestation_streak_days,
        state.policy.min_bond_sats,
        state.policy.waiting_pool_share_bps,
        ops.join(","),
        credits.join(",")
    )
}

fn load_economy(path: &Path) -> Result<EconomyState, DomainError> {
    let raw = fs::read_to_string(path).map_err(|e| DomainError::ThresholdError(format!("economy read: {e}")))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| DomainError::ThresholdError(format!("economy json: {e}")))?;
    let mut state = EconomyState::new_open();
    state.miner_pool_sats = v["miner_pool_sats"].as_u64().unwrap_or(0);
    state.channels_pool_sats = v["channels_pool_sats"].as_u64().unwrap_or(0);
    state.infra_pool_sats = v["infra_pool_sats"].as_u64().unwrap_or(0);
    state.accrued_profit_sats = v["accrued_profit_sats"].as_u64().unwrap_or(0);
    state.pending_governance_reward_sats = v["pending_governance_reward_sats"].as_u64().unwrap_or(0);
    if let Some(pq) = v["crypto_suite_id_pq"].as_str() {
        state.crypto_suite_id_pq = pq.to_string();
    }
    state.last_miner_payout_at_secs = v["last_miner_payout_at_secs"].as_u64();
    state.last_miner_payout_epoch = v["last_miner_payout_epoch"].as_u64();
    if let Some(p) = v.get("policy") {
        state.policy = RewardPolicy {
            min_uptime_bps_30d: p["min_uptime_bps_30d"].as_u64().unwrap_or(9_500) as u32,
            min_attestation_streak_days: p["min_attestation_streak_days"].as_u64().unwrap_or(1) as u32,
            min_bond_sats: p["min_bond_sats"].as_u64().unwrap_or(0),
            waiting_pool_share_bps: p["waiting_pool_share_bps"].as_u64().unwrap_or(0) as u32,
        };
    }
    if let Some(arr) = v["operators"].as_array() {
        for o in arr {
            let id = o["node_id"].as_str().unwrap_or("");
            let Ok(node_id) = NodeId::new(id) else {
                continue;
            };
            let _ = state.upsert_operator(MinerOperator {
                node_id,
                payout_destination: o["payout_destination"].as_str().unwrap_or("").to_string(),
                uptime_bps_30d: o["uptime_bps_30d"].as_u64().unwrap_or(0) as u32,
                attestation_streak_days: o["attestation_streak_days"].as_u64().unwrap_or(0) as u32,
                bond_sats: o["bond_sats"].as_u64().unwrap_or(0),
                waiting: o["waiting"].as_bool().unwrap_or(false),
            });
        }
    }
    let mut credits = BTreeMap::new();
    if let Some(arr) = v["governance_credits"].as_array() {
        for c in arr {
            if let (Some(id), Some(sats)) = (c["node_id"].as_str(), c["sats"].as_u64()) {
                credits.insert(id.to_string(), sats);
            }
        }
    }
    state.governance_credits = credits;
    Ok(state)
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ports::EconomyPort;

    struct TempProbe(PathBuf);
    impl TempProbe {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("kerosene-economy-persist-{}-{}", tag, std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> PathBuf {
            self.0.join("economy.json")
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn economy_snapshot_survives_restart() {
        let tmp = TempProbe::new("restart");
        let eco = PersistedEconomy::open(tmp.path()).unwrap();
        eco.upsert_operator(MinerOperator {
            node_id: NodeId::new("miner-a").unwrap(),
            payout_destination: "bc1q-miner-a".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 3,
            bond_sats: 0,
            waiting: false,
        })
        .unwrap();
        let split = ProfitSplits::open_with_reward(100).unwrap();
        let accrual = eco.accrue_profit_splits(1_000_000, &split).unwrap();
        assert_eq!(accrual.miners_sats, 10_000);
        eco.record_miner_payout(42, Some(7)).unwrap();

        let eco2 = PersistedEconomy::open(tmp.path()).unwrap();
        let snap = eco2.snapshot().unwrap();
        assert_eq!(snap.miner_pool_sats, 10_000);
        assert_eq!(snap.channels_pool_sats + snap.infra_pool_sats, 990_000);
        assert_eq!(snap.last_miner_payout_at_secs, Some(42));
        assert_eq!(snap.last_miner_payout_epoch, Some(7));
        assert!(snap.operators.contains_key("miner-a"));
    }
}
