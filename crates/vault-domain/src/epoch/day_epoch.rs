//! UTC day-epoch binding for daily rotation (Gate).

use crate::DomainError;

/// Calendar day in UTC as `YYYY-MM-DD` — binds signing sessions to the day epoch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DayEpoch(String);

impl DayEpoch {
    /// Parse a ten-character `YYYY-MM-DD` shape used to bind state to a UTC day.
    ///
    /// This validates separators and decimal digits but does not check whether
    /// the month/day combination is a real calendar date.
    pub fn parse(raw: impl Into<String>) -> Result<Self, DomainError> {
        let s = raw.into();
        let ok = s.len() == 10
            && s.as_bytes()[4] == b'-'
            && s.as_bytes()[7] == b'-'
            && s.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { true } else { b.is_ascii_digit() });
        if !ok {
            return Err(DomainError::InvalidIntent(format!("invalid day_epoch: {s}")));
        }
        Ok(Self(s))
    }

    /// Convert Unix seconds to the corresponding UTC civil date.
    pub fn from_unix_secs(unix_secs: u64) -> Self {
        // Civil date from Unix days (proleptic Gregorian), UTC.
        let days = (unix_secs / 86_400) as i64;
        let (y, m, d) = civil_from_days(days);
        Self(format!("{y:04}-{m:02}-{d:02}"))
    }

    /// Borrow the stored `YYYY-MM-DD` representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Howard Hinnant civil_from_days (public domain).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_from_known_unix() {
        // 2024-01-01 00:00:00 UTC
        let e = DayEpoch::from_unix_secs(1_704_067_200);
        assert_eq!(e.as_str(), "2024-01-01");
    }
}
