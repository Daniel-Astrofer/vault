//! Mutex helpers: poison → domain error (no process kill on request path).

use std::sync::{Mutex, MutexGuard};

use crate::domain::DomainError;

pub fn lock_mutex<'a, T>(mutex: &'a Mutex<T>, ctx: &'static str) -> Result<MutexGuard<'a, T>, DomainError> {
    mutex.lock().map_err(|_| DomainError::ThresholdError(format!("mutex poisoned: {ctx}")))
}
