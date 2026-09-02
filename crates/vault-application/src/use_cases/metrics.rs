use std::sync::Arc;

use crate::ports::{BucketLedgerPort, LedgerPort};
use vault_domain::NodeId;

/// Prometheus-format metrics endpoint handler.
pub struct GetMetrics {
    node_id: NodeId,
    ledger: Arc<dyn LedgerPort>,
    buckets: Option<Arc<dyn BucketLedgerPort>>,
    // Internal counters. Atomic/Arc-based for thread safety across HTTP handlers.
    peer_connected: Arc<std::sync::atomic::AtomicU32>,
    frost_sign_total: Arc<std::sync::atomic::AtomicU64>,
    frost_sign_fail_total: Arc<std::sync::atomic::AtomicU64>,
    reshare_total: Arc<std::sync::atomic::AtomicU64>,
    psbt_rejected_total: Arc<std::sync::atomic::AtomicU64>,
}

impl GetMetrics {
    pub fn new(node_id: NodeId, ledger: Arc<dyn LedgerPort>, buckets: Option<Arc<dyn BucketLedgerPort>>) -> Self {
        Self {
            node_id,
            ledger,
            buckets,
            peer_connected: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            frost_sign_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            frost_sign_fail_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reshare_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            psbt_rejected_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Returns a clone that shares the same atomic counters (for registration from sign/reshare paths).
    pub fn counter_snapshot(&self) -> MetricsCounters {
        MetricsCounters {
            peer_connected: self.peer_connected.clone(),
            frost_sign_total: self.frost_sign_total.clone(),
            frost_sign_fail_total: self.frost_sign_fail_total.clone(),
            reshare_total: self.reshare_total.clone(),
            psbt_rejected_total: self.psbt_rejected_total.clone(),
        }
    }

    pub fn execute(&self) -> Result<String, vault_domain::DomainError> {
        let epoch = self.ledger.epoch()?;
        let buckets = self.buckets.as_ref().map(|b| b.count_pending_intents()).transpose()?.unwrap_or(0);

        let node = &self.node_id;
        let mut buf = String::with_capacity(1024);
        buf.push_str("# HELP vault_mesh_health Vault mesh health gauge (1=ready)\n");
        buf.push_str("# TYPE vault_mesh_health gauge\n");
        buf.push_str(&format!("vault_mesh_health{{node_id=\"{node}\"}} 1\n"));
        buf.push_str("# HELP vault_frost_sign_total Total FROST sign operations\n");
        buf.push_str("# TYPE vault_frost_sign_total counter\n");
        buf.push_str(&format!(
            "vault_frost_sign_total{{node_id=\"{node}\",status=\"ok\"}} {ok}\n",
            ok = self.frost_sign_total.load(std::sync::atomic::Ordering::Relaxed)
        ));
        buf.push_str(&format!(
            "vault_frost_sign_total{{node_id=\"{node}\",status=\"fail\"}} {fail}\n",
            fail = self.frost_sign_fail_total.load(std::sync::atomic::Ordering::Relaxed)
        ));
        buf.push_str("# HELP vault_frost_sign_duration_seconds FROST sign duration histogram placeholder\n");
        buf.push_str("# TYPE vault_frost_sign_duration_seconds gauge\n");
        buf.push_str(&format!("vault_frost_sign_duration_seconds{{node_id=\"{node}\"}} 0.0\n"));
        buf.push_str("# HELP vault_reshare_total Total reshare events\n");
        buf.push_str("# TYPE vault_reshare_total counter\n");
        buf.push_str(&format!(
            "vault_reshare_total{{node_id=\"{node}\"}} {r}\n",
            r = self.reshare_total.load(std::sync::atomic::Ordering::Relaxed)
        ));
        buf.push_str("# HELP vault_day_epoch Current day epoch\n");
        buf.push_str("# TYPE vault_day_epoch gauge\n");
        buf.push_str(&format!("vault_day_epoch{{node_id=\"{node}\"}} {}\n", epoch.number));
        buf.push_str("# HELP vault_peer_connected Connected peers count\n");
        buf.push_str("# TYPE vault_peer_connected gauge\n");
        buf.push_str(&format!(
            "vault_peer_connected{{node_id=\"{node}\"}} {pc}\n",
            pc = self.peer_connected.load(std::sync::atomic::Ordering::Relaxed)
        ));
        buf.push_str("# HELP vault_intent_consumed_total Intents consumed\n");
        buf.push_str("# TYPE vault_intent_consumed_total counter\n");
        buf.push_str(&format!("vault_intent_consumed_total{{node_id=\"{node}\",bucket=\"all\"}} {b}\n", b = buckets));
        buf.push_str("# HELP vault_psbt_policy_rejected_total PSBT rejections by reason\n");
        buf.push_str("# TYPE vault_psbt_policy_rejected_total counter\n");
        buf.push_str(&format!(
            "vault_psbt_policy_rejected_total{{node_id=\"{node}\",reason=\"policy\"}} {pr}\n",
            pr = self.psbt_rejected_total.load(std::sync::atomic::Ordering::Relaxed)
        ));

        Ok(buf)
    }
}

/// Thread-safe counters that can be cloned and handed to sign/reshare paths.
#[derive(Clone)]
pub struct MetricsCounters {
    pub peer_connected: Arc<std::sync::atomic::AtomicU32>,
    pub frost_sign_total: Arc<std::sync::atomic::AtomicU64>,
    pub frost_sign_fail_total: Arc<std::sync::atomic::AtomicU64>,
    pub reshare_total: Arc<std::sync::atomic::AtomicU64>,
    pub psbt_rejected_total: Arc<std::sync::atomic::AtomicU64>,
}
