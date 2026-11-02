use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use relay_shared::protocol::ProxyProtocolConfig;

use super::gate::RuleGate;
use super::limiter::RateLimit;
use super::selector::TargetSelector;
use crate::reporter::{ConnectionTracker, NodeMetrics, TrafficCounter};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HELLO_BYTES: usize = 16 * 1024;

/// One rule's routing entry inside a shared SNI port listener.
#[derive(Clone)]
pub struct SniRouteEntry {
    pub rule_id: i64,
    /// Lowercase normalized SNI pattern (exact like `"a.example.com"` or wildcard `"*.example.com"`).
    pub sni: String,
    pub targets: Vec<String>,
    pub selector: Arc<TargetSelector>,
    pub rate_limit: RateLimit,
    pub gate: RuleGate,
    pub proxy_protocol: Arc<ProxyProtocolConfig>,
}

/// Shared routing table for a single TCP port (e.g. `:443`).
/// Updated atomically in-place when rules are added/removed/restarted on that port
/// so the underlying `TcpListener` never needs to unbind/rebind while at least
/// one SNI rule remains on the port.
pub struct SniRouteTable {
    pub routes: Vec<SniRouteEntry>,
    pub fallback_addr: String,
    pub loop_bypass_ips: Vec<String>,
    pub bypass_loopback: bool,
}

impl SniRouteTable {
    pub fn new(
        routes: Vec<SniRouteEntry>,
        fallback_addr: String,
        loop_bypass_ips: Vec<String>,
    ) -> Self {
        Self {
            routes,
            fallback_addr,
            loop_bypass_ips,
            bypass_loopback: true,
        }
    }
}

/// Match an extracted lowercase SNI hostname against `routes`.
/// Priority:
/// 1. Exact match (`route.sni == host`)
/// 2. Wildcard match (`route.sni == "*.suffix"`), single-label subdomain only
///    (e.g. `*.example.com` matches `a.example.com` but NOT `example.com` and
///    NOT `a.b.example.com`). Longest suffix wins if multiple wildcards match.
pub fn match_sni_route<'a>(routes: &'a [SniRouteEntry], host: &str) -> Option<&'a SniRouteEntry> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    for r in routes {
        if !r.sni.starts_with("*.") && r.sni.eq_ignore_ascii_case(&host) {
            return Some(r);
        }
    }

    let mut best: Option<&'a SniRouteEntry> = None;
    let mut best_suffix_len = 0usize;
    for r in routes {
        if let Some(suffix) = r.sni.strip_prefix("*.") {
            let suffix_lower = suffix.to_ascii_lowercase();
            if host.len() > suffix_lower.len() + 1
                && host.ends_with(&suffix_lower)
                && host.as_bytes()[host.len() - suffix_lower.len() - 1] == b'.'
            {
                let prefix = &host[..host.len() - suffix_lower.len() - 1];
                if !prefix.is_empty()
                    && !prefix.contains('.')
                    && suffix_lower.len() > best_suffix_len
                {
                    best = Some(r);
                    best_suffix_len = suffix_lower.len();
                }
            }
        }
    }
    best
}

/// Parse a TLS ClientHello message from one or more consecutive TLS Handshake
/// records (`0x16`) in `buf` and extract the SNI `host_name` extension (`0x0000`),
/// if present.
///
/// Returns:
/// - `Ok(Some(Some(sni)))` if a complete ClientHello was parsed and had an SNI hostname
/// - `Ok(Some(None))` if a complete ClientHello was parsed and had no SNI extension
/// - `Ok(None)` if `buf` is a prefix of valid TLS Handshake record(s) that need more bytes
/// - `Err(())` if `buf` is definitely not a TLS ClientHello (e.g. plain HTTP, SSH, or corrupt)
pub fn parse_tls_client_hello_sni(buf: &[u8]) -> Result<Option<Option<String>>, ()> {
    if buf.is_empty() {
        return Ok(None);
    }
    // First byte must be ContentType: Handshake (0x16)
    if buf[0] != 0x16 {
        return Err(());
    }
    if buf.len() < 5 {
        return Ok(None);
    }
    if buf[1] != 0x03 {
        return Err(());
    }
    let first_record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if first_record_len == 0 || first_record_len > MAX_HELLO_BYTES {
        return Err(());
    }

    // Fast path: single TLS record containing the entire ClientHello handshake message.
    let reassembled: Vec<u8>;
    let body: &[u8] = if first_record_len >= 4 && buf.len() >= 9 {
        if buf[5] != 0x01 {
            return Err(());
        }
        let hello_len =
            ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | (buf[8] as usize);
        if hello_len > MAX_HELLO_BYTES {
            return Err(());
        }
        if first_record_len >= 4 + hello_len {
            if buf.len() < 5 + 4 + hello_len {
                return Ok(None);
            }
            &buf[9..9 + hello_len]
        } else {
            reassembled = reassemble_handshake_records(buf)?;
            let Some(b) = extract_hello_body(&reassembled)? else {
                return Ok(None);
            };
            b
        }
    } else {
        reassembled = reassemble_handshake_records(buf)?;
        let Some(b) = extract_hello_body(&reassembled)? else {
            return Ok(None);
        };
        b
    };

    if body.len() < 34 {
        return Err(());
    }
    let mut pos = 34;

    if pos >= body.len() {
        return Err(());
    }
    let session_id_len = body[pos] as usize;
    pos += 1;
    if pos + session_id_len > body.len() {
        return Err(());
    }
    pos += session_id_len;

    if pos + 2 > body.len() {
        return Err(());
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > body.len() {
        return Err(());
    }
    pos += cipher_suites_len;

    if pos >= body.len() {
        return Err(());
    }
    let compression_len = body[pos] as usize;
    pos += 1;
    if pos + compression_len > body.len() {
        return Err(());
    }
    pos += compression_len;

    if pos == body.len() {
        return Ok(Some(None));
    }
    if pos + 2 > body.len() {
        return Err(());
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + exts_len > body.len() {
        return Err(());
    }
    let exts_end = pos + exts_len;

    while pos + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts_end {
            return Err(());
        }
        let ext_data = &body[pos..pos + ext_len];
        pos += ext_len;

        if ext_type == 0x0000 {
            if ext_data.len() < 2 {
                return Err(());
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + list_len > ext_data.len() {
                return Err(());
            }
            let mut lpos = 2;
            let lend = 2 + list_len;
            while lpos + 3 <= lend {
                let name_type = ext_data[lpos];
                let name_len =
                    u16::from_be_bytes([ext_data[lpos + 1], ext_data[lpos + 2]]) as usize;
                lpos += 3;
                if lpos + name_len > lend {
                    return Err(());
                }
                if name_type == 0x00 {
                    let raw_name = &ext_data[lpos..lpos + name_len];
                    if let Ok(s) = std::str::from_utf8(raw_name) {
                        let clean = s.trim().trim_end_matches('.').to_ascii_lowercase();
                        if !clean.is_empty() {
                            return Ok(Some(Some(clean)));
                        }
                    }
                }
                lpos += name_len;
            }
            return Ok(Some(None));
        }
    }

    Ok(Some(None))
}

fn reassemble_handshake_records(buf: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut needed: Option<usize> = None;

    while offset < buf.len() {
        if buf[offset] != 0x16 {
            return Err(());
        }
        if offset + 5 > buf.len() {
            break;
        }
        if buf[offset + 1] != 0x03 {
            return Err(());
        }
        let rec_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        if rec_len == 0 || rec_len > MAX_HELLO_BYTES {
            return Err(());
        }
        let payload_start = offset + 5;
        let avail = buf.len().saturating_sub(payload_start).min(rec_len);
        if out.len() + avail > 4 + MAX_HELLO_BYTES {
            return Err(());
        }
        out.extend_from_slice(&buf[payload_start..payload_start + avail]);

        if needed.is_none() && out.len() >= 4 {
            if out[0] != 0x01 {
                return Err(());
            }
            let hello_len =
                ((out[1] as usize) << 16) | ((out[2] as usize) << 8) | (out[3] as usize);
            if hello_len > MAX_HELLO_BYTES {
                return Err(());
            }
            needed = Some(4 + hello_len);
        }
        if let Some(target_len) = needed {
            if out.len() >= target_len {
                break;
            }
        }
        if avail < rec_len {
            break;
        }
        offset = payload_start + rec_len;
    }

    Ok(out)
}

fn extract_hello_body(hs: &[u8]) -> Result<Option<&[u8]>, ()> {
    if hs.len() < 4 {
        return Ok(None);
    }
    if hs[0] != 0x01 {
        return Err(());
    }
    let hello_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hello_len > MAX_HELLO_BYTES {
        return Err(());
    }
    if hs.len() < 4 + hello_len {
        return Ok(None);
    }
    Ok(Some(&hs[4..4 + hello_len]))
}

async fn read_initial_client_hello(stream: &mut TcpStream) -> (Option<String>, Vec<u8>) {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    const MAX_READ_BUF_BYTES: usize = MAX_HELLO_BYTES + 512;

    let read_loop = async {
        loop {
            if buf.len() >= MAX_READ_BUF_BYTES {
                return None;
            }
            match stream.read(&mut chunk).await {
                Ok(0) => return None,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    match parse_tls_client_hello_sni(&buf) {
                        Ok(Some(sni)) => return sni,
                        Ok(None) => continue,
                        Err(()) => return None,
                    }
                }
                Err(_) => return None,
            }
        }
    };

    let sni = tokio::time::timeout(HELLO_TIMEOUT, read_loop)
        .await
        .unwrap_or(None);
    (sni, buf)
}

/// Check if `client_ip` is an anti-loop source that must bypass SNI routing
/// and go directly to `fallback_addr` (`127.0.0.1:10443`):
/// 1. Loopback (`127.0.0.1`, `::1`) when `bypass_loopback` is true
/// 2. Any of this node's own public IPs (`NodeMetrics::own_public_ips()`)
/// 3. Any IP or CIDR in `loop_bypass_ips`
/// 4. Any target IP of any rule on this shared port (literal IP or DNS-resolved IP)
pub async fn is_loop_source(
    client_ip: IpAddr,
    metrics: &NodeMetrics,
    routes: &[SniRouteEntry],
    loop_bypass_ips: &[String],
    bypass_loopback: bool,
) -> bool {
    let ip = client_ip.to_canonical();
    if bypass_loopback && ip.is_loopback() {
        return true;
    }

    for own_ip in metrics.own_public_ips().await {
        if own_ip.to_canonical() == ip {
            return true;
        }
    }

    if !loop_bypass_ips.is_empty() && super::proxy_protocol::peer_trusted(ip, loop_bypass_ips) {
        return true;
    }

    for route in routes {
        for target in &route.targets {
            if let Ok(sock_addr) = target.parse::<SocketAddr>() {
                let tip = sock_addr.ip().to_canonical();
                if (!tip.is_loopback() || bypass_loopback) && tip == ip {
                    return true;
                }
            } else if let Ok(resolved) = super::outbound::resolve_cached(target).await {
                for addr in resolved {
                    let tip = addr.ip().to_canonical();
                    if (!tip.is_loopback() || bypass_loopback) && tip == ip {
                        return true;
                    }
                }
            }
        }
    }

    false
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_sni_tcp_listener(
    listener: TcpListener,
    table: Arc<RwLock<SniRouteTable>>,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    metrics: Arc<NodeMetrics>,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    tracing::info!("SNI shared TCP listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((inbound, client_addr)) => {
                if let Err(e) = inbound.set_nodelay(true) {
                    tracing::debug!(
                        "SNI TCP accept {}: set_nodelay(true) failed: {}",
                        client_addr,
                        e
                    );
                }
                super::outbound::apply_keepalive(&inbound, "SNI TCP accept");

                let table = table.clone();
                let counter = counter.clone();
                let connections = connections.clone();
                let metrics = metrics.clone();

                tokio::spawn(async move {
                    let _guard = connections.tcp_handle();
                    if let Err(e) = handle_sni_connection(
                        inbound,
                        client_addr,
                        table,
                        counter,
                        metrics,
                        source_ipv4,
                    )
                    .await
                    {
                        tracing::debug!("SNI TCP connection error ({}): {}", client_addr, e);
                    }
                });
            }
            Err(e) if super::tcp::is_transient_accept_error(&e) => {
                tracing::warn!(
                    "SNI TCP listener on {}: transient accept error: {}; retrying in 100ms",
                    listen_addr,
                    e
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
            }
        }
    }
}

async fn handle_sni_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    table: Arc<RwLock<SniRouteTable>>,
    counter: Arc<TrafficCounter>,
    metrics: Arc<NodeMetrics>,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let local_addr = inbound.local_addr()?;
    let (routes_snapshot, fallback_addr, loop_bypass_ips, bypass_loopback) = {
        let guard = table.read().unwrap();
        (
            guard.routes.clone(),
            guard.fallback_addr.clone(),
            guard.loop_bypass_ips.clone(),
            guard.bypass_loopback,
        )
    };

    // 1. Anti-loop gate
    if is_loop_source(
        client_addr.ip(),
        &metrics,
        &routes_snapshot,
        &loop_bypass_ips,
        bypass_loopback,
    )
    .await
    {
        tracing::debug!(
            "SNI anti-loop triggered for client {} -> forwarding directly to fallback {}",
            client_addr,
            fallback_addr
        );
        return super::tcp::forward_to_fallback(inbound, &[], &fallback_addr, source_ipv4).await;
    }

    // 2. Peek/read initial bytes to extract TLS ClientHello SNI.
    let (sni_opt, initial_bytes) = read_initial_client_hello(&mut inbound).await;
    if initial_bytes.is_empty() {
        return Ok(());
    }

    // 3. Match SNI against active routes on this port.
    let matched = sni_opt
        .as_deref()
        .and_then(|host| match_sni_route(&routes_snapshot, host).cloned());

    let Some(mut route) = matched else {
        tracing::debug!(
            "SNI unmatched ({:?}) from {} -> forwarding to fallback {}",
            sni_opt,
            client_addr,
            fallback_addr
        );
        return super::tcp::forward_to_fallback(
            inbound,
            &initial_bytes,
            &fallback_addr,
            source_ipv4,
        )
        .await;
    };

    // 4. Matched a rule! Enforce its per-rule connection cap and cancellation token.
    let Some(_conn_guard) = route.gate.admit() else {
        if route.gate.should_warn_cap() {
            tracing::warn!(
                "SNI TCP rule {} ({}): at connection cap ({} live / {} max), rejecting {}",
                route.rule_id,
                route.sni,
                route.gate.live(),
                route.gate.max_connections.unwrap_or(0),
                client_addr
            );
        }
        return Ok(());
    };

    let targets = route.targets.clone();
    let selector = route.selector.clone();
    let rate_limit = route.rate_limit.clone();
    let rule_id = route.rule_id;
    let proxy_protocol = route.proxy_protocol.clone();

    tokio::select! {
        _ = route.gate.cancelled() => {
            tracing::debug!(
                "SNI TCP rule {}: dropping connection from {} (rule restarted)",
                rule_id,
                client_addr
            );
            Ok(())
        }
        r = super::tcp::forward_to_rule_targets(
            inbound,
            client_addr,
            client_addr,
            local_addr,
            &initial_bytes,
            &targets,
            &selector,
            rate_limit,
            &counter,
            rule_id,
            source_ipv4,
            &proxy_protocol,
        ) => r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::LoadBalanceStrategy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let host_bytes = host.as_bytes();
            let list_len = (3 + host_bytes.len()) as u16;
            let ext_len = 2 + list_len;
            exts.extend_from_slice(&0x0000u16.to_be_bytes());
            exts.extend_from_slice(&ext_len.to_be_bytes());
            exts.extend_from_slice(&list_len.to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            exts.extend_from_slice(host_bytes);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let blen = body.len();
        handshake.push(((blen >> 16) & 0xff) as u8);
        handshake.push(((blen >> 8) & 0xff) as u8);
        handshake.push((blen & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn dummy_route(rule_id: i64, sni: &str, targets: Vec<String>) -> SniRouteEntry {
        let rt = super::super::gate::RuleRuntime::new();
        let gate = rt.gate(None);
        std::mem::forget(rt);
        SniRouteEntry {
            rule_id,
            sni: sni.to_ascii_lowercase(),
            targets,
            selector: Arc::new(TargetSelector::new(LoadBalanceStrategy::First, 1)),
            rate_limit: RateLimit::Unlimited,
            gate,
            proxy_protocol: Arc::new(ProxyProtocolConfig::default()),
        }
    }

    #[test]
    fn parses_tls_client_hello_sni_correctly() {
        let pkt = build_client_hello(Some("Sub.Example.COM"));
        assert_eq!(
            parse_tls_client_hello_sni(&pkt),
            Ok(Some(Some("sub.example.com".to_string())))
        );

        assert_eq!(parse_tls_client_hello_sni(&pkt[..10]), Ok(None));

        // Fragmented ClientHello across two TLS 0x16 Handshake records
        let hs = &pkt[5..];
        let split_at = 20;
        let (part1, part2) = hs.split_at(split_at);
        let mut multi_rec = Vec::new();
        multi_rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        multi_rec.extend_from_slice(&(part1.len() as u16).to_be_bytes());
        multi_rec.extend_from_slice(part1);
        // Only first record present so far -> needs more bytes
        assert_eq!(parse_tls_client_hello_sni(&multi_rec), Ok(None));
        // Append second record -> completes ClientHello
        multi_rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        multi_rec.extend_from_slice(&(part2.len() as u16).to_be_bytes());
        multi_rec.extend_from_slice(part2);
        assert_eq!(
            parse_tls_client_hello_sni(&multi_rec),
            Ok(Some(Some("sub.example.com".to_string())))
        );

        let no_sni = build_client_hello(None);
        assert_eq!(parse_tls_client_hello_sni(&no_sni), Ok(Some(None)));

        assert_eq!(parse_tls_client_hello_sni(b"GET / HTTP/1.1\r\n"), Err(()));
    }

    #[test]
    fn matches_exact_and_wildcard_sni_with_priority() {
        let routes = vec![
            dummy_route(1, "*.example.com", vec![]),
            dummy_route(2, "api.example.com", vec![]),
            dummy_route(3, "*.sub.example.com", vec![]),
        ];

        assert_eq!(
            match_sni_route(&routes, "api.example.com").map(|r| r.rule_id),
            Some(2)
        );
        assert_eq!(
            match_sni_route(&routes, "web.example.com").map(|r| r.rule_id),
            Some(1)
        );
        assert_eq!(
            match_sni_route(&routes, "dev.sub.example.com").map(|r| r.rule_id),
            Some(3)
        );
        assert!(match_sni_route(&routes, "example.com").is_none());
        assert!(match_sni_route(&routes, "a.b.example.com").is_none());
    }

    #[tokio::test]
    async fn anti_loop_detects_loopback_target_ip_and_bypass_cidr() {
        let metrics = NodeMetrics::new("auto");
        let routes = vec![dummy_route(1, "a.example.com", vec!["203.0.113.50:443".into()])];
        let bypass = vec!["198.51.100.0/24".to_string()];

        assert!(
            is_loop_source("127.0.0.1".parse().unwrap(), &metrics, &routes, &bypass, true).await
        );
        assert!(
            is_loop_source("203.0.113.50".parse().unwrap(), &metrics, &routes, &bypass, false)
                .await
        );
        assert!(
            is_loop_source("198.51.100.99".parse().unwrap(), &metrics, &routes, &bypass, false)
                .await
        );
        assert!(
            !is_loop_source("8.8.8.8".parse().unwrap(), &metrics, &routes, &bypass, true).await
        );
    }

    #[tokio::test]
    async fn end_to_end_sni_multiplexing_and_fallback() {
        // Spawn 3 mock backends: Target A, Target B, and Fallback (10443)
        async fn spawn_tag_server(tag: &'static [u8]) -> SocketAddr {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut s, _)) = l.accept().await {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(tag).await;
                    let _ = s.shutdown().await;
                }
            });
            addr
        }

        let target_a = spawn_tag_server(b"TARGET_A").await;
        let target_b = spawn_tag_server(b"TARGET_B").await;
        let fallback = spawn_tag_server(b"FALLBACK_10443").await;

        let routes = vec![
            dummy_route(10, "node-a.example.com", vec![target_a.to_string()]),
            dummy_route(20, "*.wild.example.com", vec![target_b.to_string()]),
        ];
        let mut table_inner = SniRouteTable::new(routes, fallback.to_string(), Vec::new());
        table_inner.bypass_loopback = false;
        let table = Arc::new(RwLock::new(table_inner));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let metrics = Arc::new(NodeMetrics::new("auto"));

        tokio::spawn(serve_sni_tcp_listener(
            listener,
            table.clone(),
            counter.clone(),
            connections,
            metrics,
            None,
        ));

        async fn send_and_read(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(payload).await.unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out).await;
            out
        }

        // 1. Exact SNI match -> Target A
        let resp_a = send_and_read(listen_addr, &build_client_hello(Some("node-a.example.com"))).await;
        assert_eq!(resp_a, b"TARGET_A");

        // 2. Wildcard SNI match -> Target B
        let resp_b =
            send_and_read(listen_addr, &build_client_hello(Some("sub.wild.example.com"))).await;
        assert_eq!(resp_b, b"TARGET_B");

        // 3. Unmatched SNI -> Fallback (10443)
        let resp_fb =
            send_and_read(listen_addr, &build_client_hello(Some("unknown.example.com"))).await;
        assert_eq!(resp_fb, b"FALLBACK_10443");

        // 4. Non-TLS traffic -> Fallback (10443)
        let resp_http = send_and_read(listen_addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert_eq!(resp_http, b"FALLBACK_10443");

        // 5. Enable bypass_loopback (production default): loopback connection bypasses SNI and goes straight to Fallback
        table.write().unwrap().bypass_loopback = true;
        let resp_loop =
            send_and_read(listen_addr, &build_client_hello(Some("node-a.example.com"))).await;
        assert_eq!(resp_loop, b"FALLBACK_10443");
    }
}


