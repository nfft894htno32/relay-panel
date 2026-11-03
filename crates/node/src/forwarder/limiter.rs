// v0.4.6: per-rule, bidirectional, connection-shared rate limiting.
// v1.3.1: extended with optional per-client-IP rate limiting (`PerIpLimiter` + `ConnRateLimit`).
//
// One `RuleLimiter` covers BOTH the upload and download directions of a single
// rule (or a single client IP bucket), and is shared (Arc) across ALL of that
// rule's / client IP's connections / UDP sessions / TCP+UDP listeners. This is
// deliberate: a `tcp_udp` rule must NOT get double the budget, and the cap is
// on aggregate traffic, not per-connection.
//
// Implementation: a continuously-refilled token bucket per direction. The
// balance math is done in a SYNCHRONOUS `Bucket::charge()` that runs under the
// bucket lock and returns how long the caller must sleep; the SLEEP then
// happens AFTER the lock is released. This is critical: the bucket is shared
// across ALL connections, so if a throttled connection slept while holding the
// lock, every other connection sharing the bucket would be frozen behind it
// (head-of-line blocking → jitter + unfairness).
//
// The balance is allowed to go NEGATIVE ("debt"): a chunk LARGER than the burst
// capacity is still admitted, it just incurs a proportionally longer wait to
// repay the debt. (The earlier version capped the balance and looped forever
// when `want > rate*burst`, hanging any connection whose read chunk exceeded
// one second of the configured rate — e.g. a 64 KiB read on a sub-512 kbps
// limit.) Steady-state throughput still equals the cap; short bursts up to one
// second of traffic are allowed.
//
// A rate of 0 / None means unlimited: `acquire()` is a no-op, so unlimited
// rules pay only a single branch per chunk.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// One second of burst capacity — lets a connection send a full-rate chunk
/// immediately, then throttle back to the refill rate.
const BURST_SECS: u64 = 1;

/// Idle eviction TTL for per-client-IP buckets once all active connections/sessions
/// from that IP have closed (`Arc::strong_count == 1`). Keeping the bucket alive
/// for 120s prevents rapid reconnects from resetting burst credit.
const PER_IP_IDLE_TTL: Duration = Duration::from_secs(120);

/// Hard upper bound on tracked client IP entries per rule to bound memory under
/// spoofed-IP connection or UDP floods.
const PER_IP_MAX_ENTRIES: usize = 16_384;
const PER_IP_GC_STRIDE: usize = 256;

struct Bucket {
    /// Refill rate in bytes/sec. 0 = this direction is unlimited.
    rate_bps: u64,
    /// Current token balance in bytes. The POSITIVE side is capped at
    /// rate_bps * BURST_SECS; the balance MAY go negative ("debt") so a chunk
    /// bigger than the burst capacity is still admitted (with a longer wait).
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            // Start full so the first chunk isn't artificially delayed.
            tokens: rate_bps.saturating_mul(BURST_SECS) as f64,
            last_refill: Instant::now(),
        }
    }

    /// SYNCHRONOUS: refill by elapsed wall time (positive side capped at the
    /// burst ceiling), then charge `want` bytes — the balance is allowed to go
    /// negative. Returns `Some(wait)` if the caller must sleep to repay the
    /// resulting debt, or `None` if there was enough balance.
    ///
    /// This intentionally does NOT sleep: the caller holds the bucket lock only
    /// for this call and releases it BEFORE sleeping, so a throttled connection
    /// never blocks the other connections sharing the bucket.
    fn charge(&mut self, want: u64) -> Option<Duration> {
        if self.rate_bps == 0 {
            return None;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        let cap = self.rate_bps.saturating_mul(BURST_SECS) as f64;
        self.tokens += elapsed * self.rate_bps as f64;
        if self.tokens > cap {
            // Only the positive (burst-credit) side is capped; debt is not.
            self.tokens = cap;
        }
        self.tokens -= want as f64;
        if self.tokens >= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(-self.tokens / self.rate_bps as f64))
        }
    }
}

/// Shared bidirectional token-bucket rate limiter (used both for rule-wide caps
/// and for per-client-IP caps).
pub struct RuleLimiter {
    upload: Mutex<Bucket>,
    download: Mutex<Bucket>,
    /// Cached so callers can short-circuit without locking when both are zero.
    unlimited: bool,
}

impl RuleLimiter {
    /// `upload_bps` / `download_bps` are bytes/sec; None / 0 means unlimited.
    pub fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        let up = upload_bps.unwrap_or(0);
        let down = download_bps.unwrap_or(0);
        Self {
            upload: Mutex::new(Bucket::new(up)),
            download: Mutex::new(Bucket::new(down)),
            unlimited: up == 0 && down == 0,
        }
    }

    #[allow(dead_code)]
    pub fn unlimited() -> Self {
        Self::new(None, None)
    }

    #[allow(dead_code)]
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Charge `n` upload bytes without sleeping; returns the wait required to
    /// repay any resulting debt. Lock is dropped before returning.
    pub async fn reserve_upload(&self, n: u64) -> Option<Duration> {
        if self.unlimited {
            return None;
        }
        self.upload.lock().await.charge(n)
    }

    /// Charge `n` download bytes without sleeping; returns the wait required to
    /// repay any resulting debt. Lock is dropped before returning.
    pub async fn reserve_download(&self, n: u64) -> Option<Duration> {
        if self.unlimited {
            return None;
        }
        self.download.lock().await.charge(n)
    }

    /// Reserve `n` upload (client→target) bytes and sleep if needed.
    pub async fn acquire_upload(&self, n: u64) {
        if let Some(w) = self.reserve_upload(n).await {
            tokio::time::sleep(w).await;
        }
    }

    /// Reserve `n` download (target→client) bytes and sleep if needed.
    pub async fn acquire_download(&self, n: u64) {
        if let Some(w) = self.reserve_download(n).await {
            tokio::time::sleep(w).await;
        }
    }
}

/// Normalized bucket key for per-client-IP limiting:
/// - IPv4-mapped IPv6 (`::ffff:x.x.x.x`) canonicalizes to `V4(x.x.x.x)`.
/// - IPv4 addresses key by `/32` (`V4`).
/// - Non-loopback IPv6 addresses key by `/64` prefix (`V6Prefix`) so SLAAC
///   privacy-extension address rotation on the same household/mobile `/64`
///   shares one user budget.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ClientIpKey {
    V4(Ipv4Addr),
    V6Prefix(u64),
    V6Loopback,
}

impl ClientIpKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => ClientIpKey::V4(v4),
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    ClientIpKey::V6Loopback
                } else {
                    ClientIpKey::V6Prefix((v6.to_bits() >> 64) as u64)
                }
            }
        }
    }
}

struct PerIpEntry {
    limiter: Arc<RuleLimiter>,
    last_seen: Instant,
}

/// Per-client-IP rate limiter table shared across all TCP/SNI/UDP listeners of a rule.
pub struct PerIpLimiter {
    upload_bps: Option<u64>,
    download_bps: Option<u64>,
    entries: std::sync::Mutex<HashMap<ClientIpKey, PerIpEntry>>,
    ops_since_gc: AtomicUsize,
}

impl PerIpLimiter {
    pub fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        Self {
            upload_bps,
            download_bps,
            entries: std::sync::Mutex::new(HashMap::new()),
            ops_since_gc: AtomicUsize::new(0),
        }
    }

    /// Resolve (or create) the shared bucket for `client_ip`. Called once per
    /// TCP connection / UDP session setup so the data transfer hot-path never
    /// touches this map lock.
    pub fn limiter_for(&self, client_ip: IpAddr) -> Arc<RuleLimiter> {
        let key = ClientIpKey::from_ip(client_ip);
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap();

        let ops = self.ops_since_gc.fetch_add(1, Ordering::Relaxed) + 1;
        if ops >= PER_IP_GC_STRIDE || map.len() >= PER_IP_MAX_ENTRIES {
            self.ops_since_gc.store(0, Ordering::Relaxed);
            map.retain(|_, entry| {
                Arc::strong_count(&entry.limiter) > 1
                    || now.duration_since(entry.last_seen) < PER_IP_IDLE_TTL
            });
        }

        if let Some(existing) = map.get_mut(&key) {
            existing.last_seen = now;
            return existing.limiter.clone();
        }

        if map.len() >= PER_IP_MAX_ENTRIES {
            // Evict the oldest idle entry (strong_count == 1) to bound memory.
            if let Some(oldest_idle_key) = map
                .iter()
                .filter(|(_, e)| Arc::strong_count(&e.limiter) == 1)
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| *k)
            {
                map.remove(&oldest_idle_key);
            }
        }

        let limiter = Arc::new(RuleLimiter::new(self.upload_bps, self.download_bps));
        map.insert(
            key,
            PerIpEntry {
                limiter: limiter.clone(),
                last_seen: now,
            },
        );
        limiter
    }
}

fn max_opt_duration(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Connection-scoped rate-limit handle holding direct `Arc<RuleLimiter>`
/// references for the rule-wide cap and/or this client IP's cap (zero map
/// lookups on read/write chunks).
#[derive(Clone)]
pub struct ConnRateLimit {
    rule: Option<Arc<RuleLimiter>>,
    per_ip: Option<Arc<RuleLimiter>>,
}

impl ConnRateLimit {
    pub fn unlimited() -> Self {
        Self {
            rule: None,
            per_ip: None,
        }
    }

    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.rule.is_none() && self.per_ip.is_none()
    }

    pub async fn acquire_upload(&self, n: u64) {
        let w1 = match &self.rule {
            Some(r) => r.reserve_upload(n).await,
            None => None,
        };
        let w2 = match &self.per_ip {
            Some(p) => p.reserve_upload(n).await,
            None => None,
        };
        if let Some(wait) = max_opt_duration(w1, w2) {
            tokio::time::sleep(wait).await;
        }
    }

    pub async fn acquire_download(&self, n: u64) {
        let w1 = match &self.rule {
            Some(r) => r.reserve_download(n).await,
            None => None,
        };
        let w2 = match &self.per_ip {
            Some(p) => p.reserve_download(n).await,
            None => None,
        };
        if let Some(wait) = max_opt_duration(w1, w2) {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Rule-level rate-limiting configuration shared across all listeners of a rule.
/// Supports rule-wide aggregate caps, per-client-IP caps, or both simultaneously.
#[derive(Clone)]
pub struct RateLimit {
    rule: Option<Arc<RuleLimiter>>,
    per_ip: Option<Arc<PerIpLimiter>>,
}

impl RateLimit {
    pub fn unlimited() -> Self {
        Self {
            rule: None,
            per_ip: None,
        }
    }

    /// Build a rule-wide limiter (no per-IP cap). `None`/0 on both sides → unlimited.
    pub fn new(upload_bps: Option<u64>, download_bps: Option<u64>) -> Self {
        Self::with_per_ip(upload_bps, download_bps, None, None)
    }

    /// Build a limiter with optional rule-wide caps AND optional per-client-IP caps.
    pub fn with_per_ip(
        upload_bps: Option<u64>,
        download_bps: Option<u64>,
        per_ip_upload_bps: Option<u64>,
        per_ip_download_bps: Option<u64>,
    ) -> Self {
        let rule = if upload_bps.unwrap_or(0) == 0 && download_bps.unwrap_or(0) == 0 {
            None
        } else {
            Some(Arc::new(RuleLimiter::new(upload_bps, download_bps)))
        };
        let per_ip =
            if per_ip_upload_bps.unwrap_or(0) == 0 && per_ip_download_bps.unwrap_or(0) == 0 {
                None
            } else {
                Some(Arc::new(PerIpLimiter::new(
                    per_ip_upload_bps,
                    per_ip_download_bps,
                )))
            };
        Self { rule, per_ip }
    }

    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.rule.is_none() && self.per_ip.is_none()
    }

    /// Bind this rule's rate limiter to a specific `client_ip` once per TCP
    /// connection / UDP session.
    pub fn for_client(&self, client_ip: IpAddr) -> ConnRateLimit {
        if self.is_unlimited() {
            return ConnRateLimit::unlimited();
        }
        ConnRateLimit {
            rule: self.rule.clone(),
            per_ip: self.per_ip.as_ref().map(|p| p.limiter_for(client_ip)),
        }
    }

    /// Charge against the rule-wide upload bucket directly.
    #[allow(dead_code)]
    pub async fn acquire_upload(&self, n: u64) {
        if let Some(l) = &self.rule {
            l.acquire_upload(n).await;
        }
    }

    /// Charge against the rule-wide download bucket directly.
    #[allow(dead_code)]
    pub async fn acquire_download(&self, n: u64) {
        if let Some(l) = &self.rule {
            l.acquire_download(n).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_is_instant_noop() {
        let r = RateLimit::new(None, None);
        assert!(r.is_unlimited());
        // Should return immediately even for a huge amount.
        let start = Instant::now();
        r.acquire_upload(u64::MAX / 2).await;
        r.acquire_download(u64::MAX / 2).await;
        let c = r.for_client("203.0.113.10".parse().unwrap());
        assert!(c.is_unlimited());
        c.acquire_upload(u64::MAX / 2).await;
        c.acquire_download(u64::MAX / 2).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn acquire_blocks_then_refills() {
        // 1000 byte/s. Requesting 1000 bytes right away consumes the initial
        // full bucket; requesting another 1000 immediately must wait ~1s.
        let r = RateLimit::new(Some(1000), Some(1000));
        r.acquire_upload(1000).await; // drains burst
        let start = Instant::now();
        r.acquire_upload(1000).await; // must refill ~1s
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "expected ~1s wait, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn shared_bucket_aggregates_across_clone() {
        // Two tasks sharing one limiter must draw from the SAME bucket, so the
        // combined rate is capped, not doubled.
        let r = RateLimit::new(Some(1000), Some(0));
        // Drain the initial burst once.
        r.acquire_upload(1000).await;
        let r2 = r.clone();
        let h1 = tokio::spawn(async move { r.acquire_upload(500).await });
        let h2 = tokio::spawn(async move { r2.acquire_upload(500).await });
        let start = Instant::now();
        h1.await.unwrap();
        h2.await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(900));
    }

    #[tokio::test]
    async fn large_chunk_over_burst_does_not_hang() {
        // 100_000 B/s, burst cap = 100_000. Ask for 150_000 (1.5× the cap).
        let r = RateLimit::new(Some(100_000), None);
        let start = Instant::now();
        r.acquire_upload(150_000).await;
        let elapsed = start.elapsed();
        // Starts with the full 100_000 burst → 50_000 debt at 100_000 B/s ≈ 0.5s.
        assert!(
            elapsed >= Duration::from_millis(400),
            "must wait to repay the debt, got {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must not hang — the wait is finite, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn concurrent_charges_complete_and_pace_to_cap() {
        let r = RateLimit::new(Some(100_000), None);
        r.acquire_upload(100_000).await; // drain the burst
        let r2 = r.clone();
        let start = Instant::now();
        let h1 = tokio::spawn(async move { r.acquire_upload(50_000).await });
        let h2 = tokio::spawn(async move { r2.acquire_upload(50_000).await });
        h1.await.unwrap();
        h2.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            (Duration::from_millis(800)..Duration::from_secs(3)).contains(&elapsed),
            "aggregate must pace to the cap, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn per_ip_shares_bucket_for_same_ip_but_isolates_different_ips() {
        // Per-IP download cap = 10_000 B/s, rule cap = unlimited.
        let r = RateLimit::with_per_ip(None, None, None, Some(10_000));
        let ip_a1: IpAddr = "198.51.100.10".parse().unwrap();
        // IPv4-mapped IPv6 for the same client IP must share the exact same bucket!
        let ip_a2: IpAddr = "::ffff:198.51.100.10".parse().unwrap();
        let ip_b: IpAddr = "198.51.100.99".parse().unwrap();

        let conn_a1 = r.for_client(ip_a1);
        let conn_a2 = r.for_client(ip_a2);
        let conn_b = r.for_client(ip_b);
        assert!(!conn_a1.is_unlimited());

        // Drain initial 10_000 burst on IP A via first connection
        conn_a1.acquire_download(10_000).await;

        // IP B's bucket is completely independent — its initial 10_000 burst is still instant!
        let b_start = Instant::now();
        conn_b.acquire_download(10_000).await;
        assert!(
            b_start.elapsed() < Duration::from_millis(50),
            "IP B must not be throttled by IP A's usage"
        );

        // Meanwhile, second connection from IP A (`::ffff:198.51.100.10`) shares IP A's empty bucket
        // and must wait ~0.5s for 5_000 bytes!
        let a_start = Instant::now();
        conn_a2.acquire_download(5_000).await;
        assert!(
            a_start.elapsed() >= Duration::from_millis(420),
            "same IP across multiple connections must share one bucket, got {:?}",
            a_start.elapsed()
        );
    }

    #[test]
    fn client_ip_key_groups_ipv6_by_64_subnet() {
        let a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:dead:beef:cafe:9999".parse().unwrap();
        let c: IpAddr = "2001:db8:abcd:1235::1".parse().unwrap();
        assert_eq!(ClientIpKey::from_ip(a), ClientIpKey::from_ip(b));
        assert_ne!(ClientIpKey::from_ip(a), ClientIpKey::from_ip(c));
    }
}
