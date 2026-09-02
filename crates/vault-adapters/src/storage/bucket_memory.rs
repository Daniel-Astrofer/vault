use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::application::ports::BucketLedgerPort;
use crate::domain::{BucketKind, BucketPolicy, DomainError};

/// Soft Intent reservation TTL (High #9) — released automatically if never committed.
const DEFAULT_RESERVE_TTL: Duration = Duration::from_secs(300);

/// In-memory per-bucket spend + policies (lab). Consumed intent ids are tracked
/// under a single mutex; prefer [`PersistedBucketLedger`] for durable replay safety.
pub struct InMemoryBucketLedger {
    pub(crate) inner: Mutex<BucketState>,
}

pub(crate) struct BucketState {
    pub(crate) policies: HashMap<BucketKind, BucketPolicy>,
    pub(crate) spent_today: HashMap<BucketKind, u64>,
    pub(crate) consumed: HashSet<String>,
    /// Soft-reserved intents (not yet durable-burned): id → (kind, amount, expires).
    pub(crate) reserved: HashMap<String, (BucketKind, u64, Instant)>,
}

impl InMemoryBucketLedger {
    pub fn from_constitution_caps(max_tx: u64, max_day: u64) -> Self {
        let mut policies = HashMap::new();
        for kind in [BucketKind::Users, BucketKind::Profit, BucketKind::Miners, BucketKind::Channels, BucketKind::Infra]
        {
            let (tx, day) = match kind {
                BucketKind::Users => (max_tx, max_day),
                BucketKind::Profit => (max_tx, max_day),
                BucketKind::Miners => (max_tx / 10, max_day / 10),
                BucketKind::Channels => (max_tx, max_day),
                BucketKind::Infra => (max_tx / 5, max_day / 5),
            };
            policies.insert(kind, BucketPolicy::lab_defaults(kind, tx.max(1), day.max(1)));
        }
        Self {
            inner: Mutex::new(BucketState {
                policies,
                spent_today: HashMap::new(),
                consumed: HashSet::new(),
                reserved: HashMap::new(),
            }),
        }
    }

    pub(crate) fn sweep_expired(g: &mut BucketState) {
        let now = Instant::now();
        let expired: Vec<String> =
            g.reserved.iter().filter(|(_, (_, _, exp))| *exp <= now).map(|(id, _)| id.clone()).collect();
        for id in expired {
            if let Some((kind, amount, _)) = g.reserved.remove(&id) {
                if let Some(spent) = g.spent_today.get_mut(&kind) {
                    *spent = spent.saturating_sub(amount);
                }
            }
        }
    }

    /// Extend USERS (or other) destination allowlist from config / Intent registry.
    pub fn admit_destinations(
        &self,
        kind: BucketKind,
        dests: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        let policy = g.policies.get_mut(&kind).ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))?;
        policy.extend_destinations(dests);
        Ok(())
    }
}

impl BucketLedgerPort for InMemoryBucketLedger {
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        g.policies.get(&kind).cloned().ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))
    }

    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        Ok(*g.spent_today.get(&kind).unwrap_or(&0))
    }

    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        let e = g.spent_today.entry(kind).or_insert(0);
        *e = e.saturating_add(amount_sats);
        Ok(())
    }

    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        Ok(g.consumed.contains(intent_id))
    }

    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }

    fn try_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        Self::sweep_expired(&mut g);
        if g.consumed.contains(intent_id) {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        g.reserved.remove(intent_id);
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }

    fn has_reservation(&self, intent_id: &str) -> Result<bool, DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        Self::sweep_expired(&mut g);
        Ok(g.reserved.contains_key(intent_id))
    }

    fn reserve_spend(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        Self::sweep_expired(&mut g);
        if g.consumed.contains(intent_id) {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        if let Some((k, amt, _)) = g.reserved.get(intent_id) {
            // Idempotent resume (CHANNELS open crash after reserve / before open).
            if *k == kind && *amt == amount_sats {
                return Ok(());
            }
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        let policy = g.policies.get(&kind).cloned().ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))?;
        let spent = *g.spent_today.get(&kind).unwrap_or(&0);
        validate(&policy, spent)?;
        let e = g.spent_today.entry(kind).or_insert(0);
        *e = e.saturating_add(amount_sats);
        g.reserved.insert(intent_id.to_string(), (kind, amount_sats, Instant::now() + DEFAULT_RESERVE_TTL));
        Ok(())
    }

    fn commit_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        Self::sweep_expired(&mut g);
        if g.consumed.contains(intent_id) {
            // Idempotent commit retry after open-ok / commit-fail.
            return Ok(());
        }
        if !g.reserved.contains_key(intent_id) {
            return Err(DomainError::ReservationMissing(intent_id.to_string()));
        }
        g.reserved.remove(intent_id);
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }

    fn release_reservation(&self, intent_id: &str, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        if let Some((k, amt, _)) = g.reserved.remove(intent_id) {
            let roll_kind = k;
            let roll_amt = amt;
            if let Some(spent) = g.spent_today.get_mut(&roll_kind) {
                *spent = spent.saturating_sub(roll_amt);
            }
        } else if let Some(spent) = g.spent_today.get_mut(&kind) {
            // Best-effort: caller-supplied rollback if reservation already swept.
            *spent = spent.saturating_sub(amount_sats);
        }
        Ok(())
    }

    fn authorize_spend_and_consume(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        Self::sweep_expired(&mut g);
        if g.consumed.contains(intent_id) || g.reserved.contains_key(intent_id) {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        let policy = g.policies.get(&kind).cloned().ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))?;
        let spent = *g.spent_today.get(&kind).unwrap_or(&0);
        validate(&policy, spent)?;
        let e = g.spent_today.entry(kind).or_insert(0);
        *e = e.saturating_add(amount_sats);
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }
}

/// Durable consumed-intent ledger (append-only fsync log) + in-memory spend/policy.
///
/// Prevents Intent replay across restarts and closes the check-then-mark TOCTOU
/// via [`BucketLedgerPort::authorize_spend_and_consume`].
pub struct PersistedBucketLedger {
    path: PathBuf,
    pub(crate) inner: InMemoryBucketLedger,
}

impl PersistedBucketLedger {
    pub fn open(path: impl Into<PathBuf>, max_tx: u64, max_day: u64) -> Result<Self, DomainError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| DomainError::ThresholdError(format!("intent-consume mkdir: {e}")))?;
        }
        let inner = InMemoryBucketLedger::from_constitution_caps(max_tx, max_day);
        if path.exists() {
            load_consumed_into(&path, &inner)?;
        }
        Ok(Self { path, inner })
    }

    pub fn admit_destinations(
        &self,
        kind: BucketKind,
        dests: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), DomainError> {
        self.inner.admit_destinations(kind, dests)
    }

    fn append_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| DomainError::ThresholdError(format!("intent-consume append: {e}")))?;
        writeln!(file, "{intent_id}").map_err(|e| DomainError::ThresholdError(format!("intent-consume write: {e}")))?;
        file.sync_all().map_err(|e| DomainError::ThresholdError(format!("intent-consume sync: {e}")))?;
        Ok(())
    }

    /// Durable check-and-insert for peer prepare. Returns `true` if already present.
    pub fn prepare_consume(&self, intent_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.inner.lock().expect("bucket lock");
        if g.consumed.contains(intent_id) {
            return Ok(true);
        }
        drop(g);
        self.append_consumed(intent_id)?;
        let mut g = self.inner.inner.lock().expect("bucket lock");
        if g.consumed.contains(intent_id) {
            return Ok(true);
        }
        g.reserved.remove(intent_id);
        g.consumed.insert(intent_id.to_string());
        Ok(false)
    }

    /// Soft peer prepare (TTL reservation, not durable burn). High #8/#9.
    pub fn prepare_soft(&self, intent_id: &str) -> Result<bool, DomainError> {
        let mut g = self.inner.inner.lock().expect("bucket lock");
        InMemoryBucketLedger::sweep_expired(&mut g);
        if g.consumed.contains(intent_id) || g.reserved.contains_key(intent_id) {
            return Ok(true);
        }
        g.reserved.insert(intent_id.to_string(), (BucketKind::Users, 0, Instant::now() + DEFAULT_RESERVE_TTL));
        Ok(false)
    }

    pub fn has_reservation(&self, intent_id: &str) -> bool {
        let mut g = self.inner.inner.lock().expect("bucket lock");
        InMemoryBucketLedger::sweep_expired(&mut g);
        g.reserved.contains_key(intent_id)
    }
}

fn load_consumed_into(path: &Path, ledger: &InMemoryBucketLedger) -> Result<(), DomainError> {
    let file = fs::File::open(path).map_err(|e| DomainError::ThresholdError(format!("intent-consume open: {e}")))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| DomainError::ThresholdError(format!("intent-consume read: {e}")))?;
        let id = line.trim();
        if id.is_empty() || id.starts_with('#') {
            continue;
        }
        // Boot hydrate: insert without re-appending.
        let mut g = ledger.inner.lock().expect("bucket lock");
        g.consumed.insert(id.to_string());
    }
    Ok(())
}

impl BucketLedgerPort for PersistedBucketLedger {
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError> {
        self.inner.policy(kind)
    }

    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError> {
        self.inner.spent_today(kind)
    }

    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.inner.record_spend(kind, amount_sats)
    }

    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError> {
        self.inner.is_consumed(intent_id)
    }

    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        // Durable path: prefer try_consume so we fsync.
        self.try_consume(intent_id)
    }

    fn try_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        let g = self.inner.inner.lock().expect("bucket lock");
        if g.consumed.contains(intent_id) {
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        // Persist before memory insert so a crash after fsync still replays as consumed.
        drop(g);
        self.append_consumed(intent_id)?;
        let mut g = self.inner.inner.lock().expect("bucket lock");
        if g.consumed.contains(intent_id) {
            // Lost the race after persist — still replay-safe.
            return Err(DomainError::IntentReplay(intent_id.to_string()));
        }
        g.reserved.remove(intent_id);
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }

    fn reserve_spend(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        self.inner.reserve_spend(intent_id, kind, amount_sats, validate)
    }

    fn commit_consume(&self, intent_id: &str) -> Result<(), DomainError> {
        {
            let mut g = self.inner.inner.lock().expect("bucket lock");
            InMemoryBucketLedger::sweep_expired(&mut g);
            if g.consumed.contains(intent_id) {
                // Idempotent commit retry.
                return Ok(());
            }
            if !g.reserved.contains_key(intent_id) {
                return Err(DomainError::ReservationMissing(intent_id.to_string()));
            }
        }
        self.try_consume(intent_id)
    }

    fn release_reservation(&self, intent_id: &str, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        self.inner.release_reservation(intent_id, kind, amount_sats)
    }

    fn authorize_spend_and_consume(
        &self,
        intent_id: &str,
        kind: BucketKind,
        amount_sats: u64,
        validate: &dyn Fn(&BucketPolicy, u64) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        // Validate + spend under lock, then durable consume (fsync) before releasing intent.
        {
            let mut g = self.inner.inner.lock().expect("bucket lock");
            if g.consumed.contains(intent_id) {
                return Err(DomainError::IntentReplay(intent_id.to_string()));
            }
            let policy =
                g.policies.get(&kind).cloned().ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))?;
            let spent = *g.spent_today.get(&kind).unwrap_or(&0);
            validate(&policy, spent)?;
            let e = g.spent_today.entry(kind).or_insert(0);
            *e = e.saturating_add(amount_sats);
            // Mark consumed in-memory under the same lock (before fsync) so concurrent
            // callers see IntentReplay immediately; fsync below makes it durable.
            g.consumed.insert(intent_id.to_string());
        }
        if let Err(e) = self.append_consumed(intent_id) {
            // Best-effort rollback of in-memory consume on disk failure.
            let mut g = self.inner.inner.lock().expect("bucket lock");
            g.consumed.remove(intent_id);
            if let Some(spent) = g.spent_today.get_mut(&kind) {
                *spent = spent.saturating_sub(amount_sats);
            }
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SettlementIntent;
    use std::sync::Arc;
    use std::thread;

    struct TempProbe(PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("kv-bucket-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn try_consume_is_atomic_against_double_claim() {
        let ledger = Arc::new(InMemoryBucketLedger::from_constitution_caps(1_000, 10_000));
        let id = "intent-race";
        let mut handles = Vec::new();
        for _ in 0..8 {
            let l = ledger.clone();
            handles.push(thread::spawn(move || l.try_consume(id)));
        }
        let mut wins = 0usize;
        let mut replays = 0usize;
        for h in handles {
            match h.join().unwrap() {
                Ok(()) => wins += 1,
                Err(DomainError::IntentReplay(_)) => replays += 1,
                Err(e) => unreachable!("unexpected bucket error in test: {e}"),
            }
        }
        assert_eq!(wins, 1);
        assert_eq!(replays, 7);
    }

    #[test]
    fn persisted_consume_survives_restart() {
        let tmp = TempProbe::new("persist");
        let path = tmp.0.join("consumed_intents.log");
        let a = PersistedBucketLedger::open(&path, 1_000, 10_000).unwrap();
        a.try_consume("intent-durable").unwrap();
        assert!(a.is_consumed("intent-durable").unwrap());

        let b = PersistedBucketLedger::open(&path, 1_000, 10_000).unwrap();
        assert!(b.is_consumed("intent-durable").unwrap());
        let err = b.try_consume("intent-durable").unwrap_err();
        assert!(matches!(err, DomainError::IntentReplay(_)));
    }

    #[test]
    fn authorize_spend_and_consume_rejects_replay() {
        let ledger = InMemoryBucketLedger::from_constitution_caps(100, 1_000);
        let intent = SettlementIntent::new("i1", BucketKind::Users, "tb1q-users-withdraw", 10, "ph").unwrap();
        let validate = |policy: &BucketPolicy, spent: u64| crate::domain::evaluate_intent(&intent, policy, spent, "ph");
        ledger.authorize_spend_and_consume("i1", BucketKind::Users, 10, &validate).unwrap();
        let err = ledger.authorize_spend_and_consume("i1", BucketKind::Users, 10, &validate).unwrap_err();
        assert!(matches!(err, DomainError::IntentReplay(_)));
        assert_eq!(ledger.spent_today(BucketKind::Users).unwrap(), 10);
    }
}
