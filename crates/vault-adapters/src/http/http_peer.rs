//! Shared outbound peer HTTP settings: SOCKS (Tor), timeouts, retry+jitter.
//! Used by wire DKG fan-out and anti-nonce prepare — not domain logic.

use std::time::Duration;

use rand::Rng;

use crate::domain::DomainError;

/// Outbound mesh transport: clearnet LAN vs Tor SOCKS to onion peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTransport {
    Clearnet,
    Tor,
}

impl VaultTransport {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "clearnet" | "lan" | "direct" => Some(Self::Clearnet),
            "tor" | "onion" | "socks" => Some(Self::Tor),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clearnet => "clearnet",
            Self::Tor => "tor",
        }
    }

    pub fn is_tor(self) -> bool {
        matches!(self, Self::Tor)
    }
}

/// Tunables for vault↔vault HTTP (DKG, anti-nonce).
#[derive(Debug, Clone)]
pub struct PeerHttpSettings {
    pub transport: VaultTransport,
    /// e.g. `socks5h://127.0.0.1:9050` (hostname resolution via proxy — required for `.onion`).
    pub socks_proxy: Option<String>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_retries: u32,
    pub retry_base_ms: u64,
    pub retry_jitter_ms: u64,
}

impl PeerHttpSettings {
    pub fn clearnet_defaults() -> Self {
        Self {
            transport: VaultTransport::Clearnet,
            socks_proxy: None,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            max_retries: 1,
            retry_base_ms: 100,
            retry_jitter_ms: 50,
        }
    }

    pub fn tor_defaults() -> Self {
        Self {
            transport: VaultTransport::Tor,
            socks_proxy: Some("socks5h://127.0.0.1:9050".into()),
            // Tor circuits: high variance — do not assume LAN.
            timeout: Duration::from_secs(180),
            connect_timeout: Duration::from_secs(60),
            max_retries: 5,
            retry_base_ms: 750,
            retry_jitter_ms: 750,
        }
    }

    pub fn normalize_socks_proxy(raw: &str) -> String {
        let t = raw.trim();
        if t.starts_with("socks5h://")
            || t.starts_with("socks5://")
            || t.starts_with("socks://")
            || t.starts_with("http://")
            || t.starts_with("https://")
        {
            t.to_string()
        } else {
            format!("socks5h://{t}")
        }
    }

    pub fn apply_builder(&self, mut builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, DomainError> {
        builder = builder.timeout(self.timeout).connect_timeout(self.connect_timeout);
        if let Some(proxy_url) = self.socks_proxy.as_deref() {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| DomainError::AttestationRejected(format!("VAULT_SOCKS_PROXY invalid: {e}")))?;
            builder = builder.proxy(proxy);
        }
        Ok(builder)
    }

    pub fn apply_blocking_builder(
        &self,
        mut builder: reqwest::blocking::ClientBuilder,
    ) -> Result<reqwest::blocking::ClientBuilder, DomainError> {
        builder = builder.timeout(self.timeout).connect_timeout(self.connect_timeout);
        if let Some(proxy_url) = self.socks_proxy.as_deref() {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| DomainError::AttestationRejected(format!("VAULT_SOCKS_PROXY invalid: {e}")))?;
            builder = builder.proxy(proxy);
        }
        Ok(builder)
    }

    pub fn build_async_client(&self) -> Result<reqwest::Client, DomainError> {
        self.apply_builder(reqwest::Client::builder())?
            .build()
            .map_err(|e| DomainError::ThresholdError(format!("peer http client: {e}")))
    }

    pub fn build_blocking_client(&self) -> Result<reqwest::blocking::Client, DomainError> {
        self.apply_blocking_builder(reqwest::blocking::Client::builder())?
            .build()
            .map_err(|e| DomainError::ThresholdError(format!("peer http client: {e}")))
    }

    /// Sleep for exponential backoff with jitter before retry `attempt` (0-based after first fail).
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        let exp = self.retry_base_ms.saturating_mul(1u64 << attempt.min(6));
        let jitter = if self.retry_jitter_ms == 0 { 0 } else { rand::thread_rng().gen_range(0..=self.retry_jitter_ms) };
        Duration::from_millis(exp.saturating_add(jitter))
    }

    pub fn should_retry_status(status: reqwest::StatusCode) -> bool {
        status.is_server_error() || status == reqwest::StatusCode::REQUEST_TIMEOUT
    }
}

/// True when peer address is an onion (with or without scheme/port).
pub fn peer_addr_is_onion(addr: &str) -> bool {
    let host = addr
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    host.ends_with(".onion")
}

/// POST with retries; retries on transport errors and 5xx.
pub async fn post_json_with_retry(
    client: &reqwest::Client,
    settings: &PeerHttpSettings,
    url: &str,
    apply_auth: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    body: &impl serde::Serialize,
) -> Result<reqwest::Response, DomainError> {
    let attempts = settings.max_retries.max(1);
    let mut last_err = String::new();
    for attempt in 0..attempts {
        let req = apply_auth(client.post(url).header("Content-Type", "application/json").json(body));
        match req.send().await {
            Ok(res) if res.status().is_success() => return Ok(res),
            Ok(res) => {
                let status = res.status();
                let body_txt = res.text().await.unwrap_or_default();
                last_err = format!("HTTP {status}: {body_txt}");
                if !PeerHttpSettings::should_retry_status(status) || attempt + 1 >= attempts {
                    return Err(DomainError::ThresholdError(format!("peer POST {url}: {last_err}")));
                }
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt + 1 >= attempts {
                    return Err(DomainError::ThresholdError(format!("peer POST {url}: {last_err}")));
                }
            }
        }
        tokio::time::sleep(settings.backoff_delay(attempt)).await;
    }
    Err(DomainError::ThresholdError(format!("peer POST {url}: {last_err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_socks_adds_scheme() {
        assert_eq!(PeerHttpSettings::normalize_socks_proxy("127.0.0.1:9050"), "socks5h://127.0.0.1:9050");
        assert_eq!(PeerHttpSettings::normalize_socks_proxy("socks5h://tor:9050"), "socks5h://tor:9050");
    }

    #[test]
    fn onion_detection() {
        assert!(peer_addr_is_onion("http://abc.onion:7701"));
        assert!(peer_addr_is_onion("xyz.onion"));
        assert!(!peer_addr_is_onion("vault-2:7701"));
        assert!(!peer_addr_is_onion("http://127.0.0.1:7701"));
    }

    #[test]
    fn tor_defaults_are_slower_than_clearnet() {
        let c = PeerHttpSettings::clearnet_defaults();
        let t = PeerHttpSettings::tor_defaults();
        assert!(t.timeout > c.timeout);
        assert!(t.max_retries > c.max_retries);
        assert!(t.socks_proxy.is_some());
    }

    #[test]
    fn backoff_grows_and_stays_finite() {
        let s = PeerHttpSettings::tor_defaults();
        let d0 = s.backoff_delay(0);
        let d3 = s.backoff_delay(3);
        assert!(d3 >= d0);
        assert!(d3 < Duration::from_secs(60));
    }

    #[test]
    fn retry_status_policy() {
        assert!(PeerHttpSettings::should_retry_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!PeerHttpSettings::should_retry_status(reqwest::StatusCode::BAD_REQUEST));
    }
}
