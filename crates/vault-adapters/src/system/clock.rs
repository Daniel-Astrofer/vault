use std::time::{SystemTime, UNIX_EPOCH};

use crate::application::ClockPort;

pub struct SystemClock;

impl ClockPort for SystemClock {
    fn unix_now_secs(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}
