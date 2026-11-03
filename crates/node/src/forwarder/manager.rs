use super::gate::RuleRuntime;
use super::limiter::RateLimit;
use super::selector::TargetSelector;
use super::sni::{self, SniRouteEntry, SniRouteTable};
use super::tcp;
use super::udp;
use crate::reporter::{ConnectionTracker, NodeMetrics, TrafficCounter};
use relay_shared::protocol::{
    ListenerConfig, ListenerError, LoadBalanceStrategy, NodeConfigResponse, Protocol,
    ProxyProtocolConfig,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

type ListenerKey = (u16, Protocol);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenerFingerprint {
    rule_id: i64,
    targets: Vec<String>,
    sni: Option<String>,
    sni_fallback_addr: String,
    sni_loop_bypass_ips: Vec<String>,
    load_balance_strategy: LoadBalanceStrategy,
    upload_limit_bps: Option<u64>,
    download_limit_bps: Option<u64>,
    per_ip_upload_limit_bps: Option<u64>,
    per_ip_download_limit_bps: Option<u64>,
    max_connections: Option<u32>,
    proxy_protocol: ProxyProtocolConfig,
}

impl ListenerFingerprint {
    fn from_listener(l: &ListenerConfig) -> Self {
        Self {
            rule_id: l.rule_id,
            targets: l.targets.clone(),
            sni: l.sni.clone(),
            sni_fallback_addr: l.sni_fallback_addr.clone(),
            sni_loop_bypass_ips: l.sni_loop_bypass_ips.clone(),
            load_balance_strategy: l.load_balance_strategy,
            upload_limit_bps: l.upload_limit_bps,
            download_limit_bps: l.download_limit_bps,
            per_ip_upload_limit_bps: l.per_ip_upload_limit_bps,
            per_ip_download_limit_bps: l.per_ip_download_limit_bps,
            max_connections: l.max_connections,
            proxy_protocol: l.proxy_protocol.clone(),
        }
    }
}

struct ManagedListener {
    handle: JoinHandle<()>,
    fingerprint: ListenerFingerprint,
}

struct ManagedSniListener {
    handle: JoinHandle<()>,
    table: Arc<RwLock<SniRouteTable>>,
    rule_fingerprints: HashMap<i64, ListenerFingerprint>,
}

#[derive(Debug, Clone)]
pub struct ListenerInfo {
    pub port: u16,
    pub protocol: String,
    pub transport: String,
    pub targets: Vec<String>,
    pub running: bool,
}

pub struct ForwarderManager {
    listeners: HashMap<ListenerKey, ManagedListener>,
    sni_listeners: HashMap<u16, ManagedSniListener>,
    rule_runtime: HashMap<i64, RuleRuntime>,
    last_config: Option<NodeConfigResponse>,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    metrics: Arc<NodeMetrics>,
    listener_errors: Arc<Mutex<Vec<ListenerError>>>,
    listen_ipv4: String,
    listen_ipv6: String,
    source_ipv4: Option<std::net::Ipv4Addr>,
    shutting_down: bool,
}

fn is_sni_tcp(l: &ListenerConfig) -> bool {
    l.protocol == Protocol::Tcp
        && l.sni
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
}

impl ForwarderManager {
    pub fn new(
        counter: Arc<TrafficCounter>,
        connections: Arc<ConnectionTracker>,
        metrics: Arc<NodeMetrics>,
    ) -> Self {
        Self {
            listeners: HashMap::new(),
            sni_listeners: HashMap::new(),
            rule_runtime: HashMap::new(),
            last_config: None,
            counter,
            connections,
            metrics,
            listener_errors: Arc::new(Mutex::new(Vec::new())),
            listen_ipv4: "0.0.0.0".into(),
            listen_ipv6: "::".into(),
            source_ipv4: None,
            shutting_down: false,
        }
    }

    pub async fn stop_accepting(&mut self) -> usize {
        self.shutting_down = true;
        let mut closed = 0;
        for (_, m) in self.listeners.drain() {
            closed += 1;
            let handle = m.handle;
            handle.abort();
            let _ = (&mut { handle }).await;
        }
        for (_, m) in self.sni_listeners.drain() {
            closed += 1;
            let handle = m.handle;
            handle.abort();
            let _ = (&mut { handle }).await;
        }
        closed
    }

    pub fn set_network_config(
        &mut self,
        cfg: &crate::config::NodeConfig,
    ) -> Result<(), crate::forwarder::outbound::OutboundError> {
        self.listen_ipv4 = cfg.listen_ipv4.clone();
        self.listen_ipv6 = cfg.listen_ipv6.clone();
        self.source_ipv4 = crate::forwarder::outbound::init_outbound(
            &crate::forwarder::outbound::OutboundConfig {
                bind_ipv4: cfg.outbound_bind_ipv4.clone(),
                interface: cfg.outbound_interface.clone(),
            },
        )?;
        Ok(())
    }

    pub async fn take_listener_errors(&self) -> Vec<ListenerError> {
        self.listener_errors.lock().await.drain(..).collect()
    }

    pub fn listener_info_for_rule_tcp(&self, rule_id: i64) -> Option<ListenerInfo> {
        for ((port, proto), ml) in &self.listeners {
            if ml.fingerprint.rule_id == rule_id && *proto == Protocol::Tcp {
                return Some(ListenerInfo {
                    port: *port,
                    protocol: "tcp".to_string(),
                    transport: "raw".to_string(),
                    targets: ml.fingerprint.targets.clone(),
                    running: !ml.handle.is_finished(),
                });
            }
        }
        for (port, m) in &self.sni_listeners {
            if let Some(fp) = m.rule_fingerprints.get(&rule_id) {
                return Some(ListenerInfo {
                    port: *port,
                    protocol: "tcp".to_string(),
                    transport: "sni".to_string(),
                    targets: fp.targets.clone(),
                    running: !m.handle.is_finished(),
                });
            }
        }
        None
    }

    fn rule_still_referenced(&self, rule_id: i64) -> bool {
        self.listeners
            .values()
            .any(|live| live.fingerprint.rule_id == rule_id)
            || self
                .sni_listeners
                .values()
                .any(|m| m.rule_fingerprints.contains_key(&rule_id))
    }

    pub async fn apply_config(&mut self, config: &NodeConfigResponse) {
        if self.shutting_down {
            tracing::debug!("apply_config: ignored, node is shutting down");
            return;
        }

        // ── Step 1: recover dead listeners ──
        let dead_raw: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|(_, m)| m.handle.is_finished())
            .map(|(k, _)| *k)
            .collect();
        let mut dead_rule_ids: Vec<i64> = Vec::new();
        for key in &dead_raw {
            let (port, proto) = *key;
            tracing::warn!(
                "listener {:?} on port {} has exited; will restart if still desired",
                proto,
                port
            );
            if let Some(m) = self.listeners.remove(key) {
                dead_rule_ids.push(m.fingerprint.rule_id);
            }
        }

        let dead_sni: Vec<u16> = self
            .sni_listeners
            .iter()
            .filter(|(_, m)| m.handle.is_finished())
            .map(|(p, _)| *p)
            .collect();
        for port in &dead_sni {
            tracing::warn!(
                "SNI shared TCP listener on port {} has exited; will restart if still desired",
                port
            );
            if let Some(m) = self.sni_listeners.remove(port) {
                dead_rule_ids.extend(m.rule_fingerprints.keys().copied());
            }
        }

        // ── Step 2: partition desired listeners into raw vs SNI shared TCP ──
        let mut raw_desired: Vec<&ListenerConfig> = Vec::new();
        let mut sni_by_port: HashMap<u16, Vec<&ListenerConfig>> = HashMap::new();
        for l in &config.listeners {
            if l.protocol == Protocol::TcpUdp {
                continue;
            }
            if is_sni_tcp(l) {
                sni_by_port.entry(l.port).or_default().push(l);
            } else {
                raw_desired.push(l);
            }
        }

        let active_raw_keys: HashSet<ListenerKey> = raw_desired
            .iter()
            .map(|l| (l.port, l.protocol))
            .collect();
        let active_sni_ports: HashSet<u16> = sni_by_port.keys().copied().collect();
        let desired_rule_ids: HashSet<i64> = config.listeners.iter().map(|l| l.rule_id).collect();

        // ── Step 3: stop raw listeners that are removed or changed, and SNI port
        // listeners whose port is no longer an SNI shared port ──
        let mut raw_to_stop: Vec<ListenerKey> = self
            .listeners
            .keys()
            .filter(|k| !active_raw_keys.contains(k))
            .copied()
            .collect();
        for listener in &raw_desired {
            let key = (listener.port, listener.protocol);
            if let Some(m) = self.listeners.get(&key) {
                if m.fingerprint != ListenerFingerprint::from_listener(listener) {
                    raw_to_stop.push(key);
                }
            }
        }
        for key in raw_to_stop {
            if let Some(m) = self.listeners.remove(&key) {
                let handle = m.handle;
                let (port, proto) = key;
                handle.abort();
                let _ = (&mut { handle }).await;
                dead_rule_ids.push(m.fingerprint.rule_id);
                tracing::info!(
                    "stopped {:?} listener on port {} for reconfiguration",
                    proto,
                    port
                );
            }
        }

        let sni_ports_to_stop: Vec<u16> = self
            .sni_listeners
            .keys()
            .filter(|p| !active_sni_ports.contains(p))
            .copied()
            .collect();
        for port in sni_ports_to_stop {
            if let Some(m) = self.sni_listeners.remove(&port) {
                let handle = m.handle;
                handle.abort();
                let _ = (&mut { handle }).await;
                dead_rule_ids.extend(m.rule_fingerprints.keys().copied());
                tracing::info!(
                    "stopped SNI shared TCP listener on port {} for reconfiguration",
                    port
                );
            }
        }

        // Also track rules removed from still-running SNI ports so their counters get pruned.
        for (port, m) in &self.sni_listeners {
            if let Some(desired_for_port) = sni_by_port.get(port) {
                let desired_port_rules: HashSet<i64> =
                    desired_for_port.iter().map(|l| l.rule_id).collect();
                for old_rid in m.rule_fingerprints.keys() {
                    if !desired_port_rules.contains(old_rid) {
                        dead_rule_ids.push(*old_rid);
                    }
                }
            }
        }

        // ── Step 4a: start new / changed raw listeners ──
        let mut rule_limiters: HashMap<i64, RateLimit> = HashMap::new();
        let ip_v4 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv4);
        let ip_v6 = crate::forwarder::outbound::parse_listen_ip(&self.listen_ipv6);

        for listener in &raw_desired {
            let key = (listener.port, listener.protocol);
            if let Some(m) = self.listeners.get(&key) {
                if m.fingerprint == ListenerFingerprint::from_listener(listener) {
                    continue;
                }
            }

            let targets = listener.targets.clone();
            let selector = Arc::new(TargetSelector::new(
                listener.load_balance_strategy,
                targets.len(),
            ));
            let rate_limit = rule_limiters
                .entry(listener.rule_id)
                .or_insert_with(|| {
                    RateLimit::with_per_ip(
                        listener.upload_limit_bps,
                        listener.download_limit_bps,
                        listener.per_ip_upload_limit_bps,
                        listener.per_ip_download_limit_bps,
                    )
                })
                .clone();
            let counter = self.counter.clone();
            let connections = self.connections.clone();
            let port = listener.port;
            let rule_id = listener.rule_id;
            let errors = self.listener_errors.clone();
            let src_ipv4 = self.source_ipv4;
            let proto_str = match listener.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::TcpUdp => "tcpudp",
            }
            .to_string();

            let handle: JoinHandle<()> = match listener.protocol {
                Protocol::Tcp => {
                    use crate::forwarder::outbound::bind_tcp_listener;
                    let mut v4_listener = None;
                    let mut v6_listener = None;
                    if let Some(ip4) = ip_v4 {
                        match bind_tcp_listener(ip4, port) {
                            Ok(l) => {
                                tracing::info!(
                                    "TCP bound {} (rule {})",
                                    SocketAddr::new(ip4, port),
                                    rule_id
                                );
                                v4_listener = Some(l);
                            }
                            Err(e) => {
                                tracing::error!("TCP IPv4 bind {}:{} failed: {}", ip4, port, e);
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv4: {}", e),
                                });
                            }
                        }
                    }
                    if let Some(ip6) = ip_v6 {
                        match bind_tcp_listener(ip6, port) {
                            Ok(l) => {
                                tracing::info!(
                                    "TCP bound {} (rule {})",
                                    SocketAddr::new(ip6, port),
                                    rule_id
                                );
                                v6_listener = Some(l);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "TCP IPv6 bind [{}]:{} failed: {} — IPv4 continues",
                                    ip6,
                                    port,
                                    e
                                );
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv6: {}", e),
                                });
                            }
                        }
                    }
                    if v4_listener.is_none() && v6_listener.is_none() {
                        tracing::error!(
                            "TCP rule {}: no listener bound on port {} (all families failed)",
                            rule_id,
                            port
                        );
                        continue;
                    }
                    let tgt = targets.clone();
                    let sel = selector.clone();
                    let rl = rate_limit.clone();
                    let ctr = counter.clone();
                    let cn = connections.clone();
                    let rid = rule_id;
                    let ipv4_src = src_ipv4;
                    let gate4 = self
                        .rule_runtime
                        .entry(rule_id)
                        .or_default()
                        .gate(listener.max_connections);
                    let gate6 = gate4.clone();
                    let pp = Arc::new(listener.proxy_protocol.clone());
                    tokio::spawn(async move {
                        type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                        let (tgt4, sel4, rl4, ctr4, cn4, pp4) = (
                            tgt.clone(),
                            sel.clone(),
                            rl.clone(),
                            ctr.clone(),
                            cn.clone(),
                            pp.clone(),
                        );
                        let v4_fut = async move {
                            if let Some(l) = v4_listener {
                                tcp::serve_tcp_listener(
                                    l, tgt4, sel4, rl4, ctr4, cn4, rid, ipv4_src, gate4, pp4,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        let v6_fut = async move {
                            if let Some(l) = v6_listener {
                                tcp::serve_tcp_listener(
                                    l, tgt, sel, rl, ctr, cn, rid, ipv4_src, gate6, pp,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        tokio::select! {
                            r = v4_fut => { if let Err(e) = r { tracing::error!("TCP v4 serve ended (rule {}): {}", rid, e); } }
                            r = v6_fut => { if let Err(e) = r { tracing::error!("TCP v6 serve ended (rule {}): {}", rid, e); } }
                        }
                    })
                }
                Protocol::Udp => {
                    use crate::forwarder::outbound::bind_udp_socket;
                    let mut v4_sock = None;
                    let mut v6_sock = None;
                    if let Some(ip4) = ip_v4 {
                        match bind_udp_socket(ip4, port) {
                            Ok(s) => {
                                tracing::info!(
                                    "UDP bound {} (rule {})",
                                    SocketAddr::new(ip4, port),
                                    rule_id
                                );
                                v4_sock = Some(Arc::new(s));
                            }
                            Err(e) => {
                                tracing::error!("UDP IPv4 bind {}:{} failed: {}", ip4, port, e);
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv4: {}", e),
                                });
                            }
                        }
                    }
                    if let Some(ip6) = ip_v6 {
                        match bind_udp_socket(ip6, port) {
                            Ok(s) => {
                                tracing::info!(
                                    "UDP bound {} (rule {})",
                                    SocketAddr::new(ip6, port),
                                    rule_id
                                );
                                v6_sock = Some(Arc::new(s));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "UDP IPv6 bind [{}]:{} failed: {} — IPv4 continues",
                                    ip6,
                                    port,
                                    e
                                );
                                errors.lock().await.push(ListenerError {
                                    port,
                                    protocol: proto_str.clone(),
                                    error: format!("IPv6: {}", e),
                                });
                            }
                        }
                    }
                    if v4_sock.is_none() && v6_sock.is_none() {
                        tracing::error!(
                            "UDP rule {}: no listener bound on port {} (all families failed)",
                            rule_id,
                            port
                        );
                        continue;
                    }
                    let tgt = targets.clone();
                    let sel = selector.clone();
                    let rl = rate_limit.clone();
                    let ctr = counter.clone();
                    let cn = connections.clone();
                    let rid = rule_id;
                    let ipv4_src = src_ipv4;
                    tokio::spawn(async move {
                        type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                        let (tgt4, sel4, rl4, ctr4, cn4) = (
                            tgt.clone(),
                            sel.clone(),
                            rl.clone(),
                            ctr.clone(),
                            cn.clone(),
                        );
                        let v4_fut = async move {
                            if let Some(s) = v4_sock {
                                udp::serve_udp_listener(
                                    s, tgt4, sel4, rl4, ctr4, cn4, rid, ipv4_src,
                                )
                                .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        let v6_fut = async move {
                            if let Some(s) = v6_sock {
                                udp::serve_udp_listener(s, tgt, sel, rl, ctr, cn, rid, ipv4_src)
                                    .await
                            } else {
                                std::future::pending::<SrvResult>().await
                            }
                        };
                        tokio::select! {
                            r = v4_fut => { if let Err(e) = r { tracing::error!("UDP v4 serve ended (rule {}): {}", rid, e); } }
                            r = v6_fut => { if let Err(e) = r { tracing::error!("UDP v6 serve ended (rule {}): {}", rid, e); } }
                        }
                    })
                }
                Protocol::TcpUdp => continue,
            };

            self.listeners.insert(
                key,
                ManagedListener {
                    handle,
                    fingerprint: ListenerFingerprint::from_listener(listener),
                },
            );
        }

        // ── Step 4b: start or hot-update shared SNI TCP listeners ──
        for (port, sni_configs) in sni_by_port {
            let mut new_fps: HashMap<i64, ListenerFingerprint> = HashMap::new();
            for lc in &sni_configs {
                new_fps.insert(lc.rule_id, ListenerFingerprint::from_listener(lc));
            }

            // If already running on this port and every rule's fingerprint matches, keep as-is.
            if let Some(existing) = self.sni_listeners.get(&port) {
                if existing.rule_fingerprints == new_fps {
                    continue;
                }
            }

            // Build the new SniRouteTable, reusing existing routes for rules whose fingerprint
            // did not change so their round-robin cursor and rate-limiter buckets stay intact.
            let prev_routes: HashMap<i64, SniRouteEntry> = self
                .sni_listeners
                .get(&port)
                .map(|m| {
                    let guard = m.table.read().unwrap();
                    guard
                        .routes
                        .iter()
                        .filter(|r| {
                            m.rule_fingerprints.get(&r.rule_id) == new_fps.get(&r.rule_id)
                        })
                        .map(|r| (r.rule_id, r.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let fallback_addr = sni_configs
                .first()
                .map(|l| l.sni_fallback_addr.clone())
                .unwrap_or_else(relay_shared::models::default_sni_fallback_addr);
            let loop_bypass_ips = sni_configs
                .first()
                .map(|l| l.sni_loop_bypass_ips.clone())
                .unwrap_or_default();

            let mut routes: Vec<SniRouteEntry> = Vec::with_capacity(sni_configs.len());
            for lc in &sni_configs {
                if let Some(reused) = prev_routes.get(&lc.rule_id) {
                    routes.push(reused.clone());
                    continue;
                }
                let sni_domain = lc
                    .sni
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let targets = lc.targets.clone();
                let selector = Arc::new(TargetSelector::new(
                    lc.load_balance_strategy,
                    targets.len(),
                ));
                let rate_limit = rule_limiters
                    .entry(lc.rule_id)
                    .or_insert_with(|| {
                        RateLimit::with_per_ip(
                            lc.upload_limit_bps,
                            lc.download_limit_bps,
                            lc.per_ip_upload_limit_bps,
                            lc.per_ip_download_limit_bps,
                        )
                    })
                    .clone();
                let gate = self
                    .rule_runtime
                    .entry(lc.rule_id)
                    .or_default()
                    .gate(lc.max_connections);
                let proxy_protocol = Arc::new(lc.proxy_protocol.clone());
                routes.push(SniRouteEntry {
                    rule_id: lc.rule_id,
                    sni: sni_domain,
                    targets,
                    selector,
                    rate_limit,
                    gate,
                    proxy_protocol,
                });
            }

            // If the listener task is already running on `port`, hot-swap its table in-place!
            if let Some(existing) = self.sni_listeners.get_mut(&port) {
                {
                    let mut guard = existing.table.write().unwrap();
                    guard.routes = routes;
                    guard.fallback_addr = fallback_addr;
                    guard.loop_bypass_ips = loop_bypass_ips;
                }
                existing.rule_fingerprints = new_fps;
                tracing::info!(
                    "SNI shared TCP listener on port {} updated in-place ({} route(s))",
                    port,
                    existing.rule_fingerprints.len()
                );
                continue;
            }

            // Otherwise, bind dual-stack TCP listeners on `port` and spawn `serve_sni_tcp_listener`.
            use crate::forwarder::outbound::bind_tcp_listener;
            let mut v4_listener = None;
            let mut v6_listener = None;
            let errors = self.listener_errors.clone();
            if let Some(ip4) = ip_v4 {
                match bind_tcp_listener(ip4, port) {
                    Ok(l) => {
                        tracing::info!(
                            "SNI TCP bound {} ({} route(s))",
                            SocketAddr::new(ip4, port),
                            routes.len()
                        );
                        v4_listener = Some(l);
                    }
                    Err(e) => {
                        tracing::error!("SNI TCP IPv4 bind {}:{} failed: {}", ip4, port, e);
                        errors.lock().await.push(ListenerError {
                            port,
                            protocol: "tcp".into(),
                            error: format!("IPv4: {}", e),
                        });
                    }
                }
            }
            if let Some(ip6) = ip_v6 {
                match bind_tcp_listener(ip6, port) {
                    Ok(l) => {
                        tracing::info!(
                            "SNI TCP bound {} ({} route(s))",
                            SocketAddr::new(ip6, port),
                            routes.len()
                        );
                        v6_listener = Some(l);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "SNI TCP IPv6 bind [{}]:{} failed: {} — IPv4 continues",
                            ip6,
                            port,
                            e
                        );
                        errors.lock().await.push(ListenerError {
                            port,
                            protocol: "tcp".into(),
                            error: format!("IPv6: {}", e),
                        });
                    }
                }
            }
            if v4_listener.is_none() && v6_listener.is_none() {
                tracing::error!(
                    "SNI TCP port {}: no listener bound (all families failed)",
                    port
                );
                continue;
            }

            let table = Arc::new(RwLock::new(SniRouteTable::new(
                routes,
                fallback_addr,
                loop_bypass_ips,
            )));
            let tbl4 = table.clone();
            let tbl6 = table.clone();
            let ctr4 = self.counter.clone();
            let ctr6 = self.counter.clone();
            let cn4 = self.connections.clone();
            let cn6 = self.connections.clone();
            let met4 = self.metrics.clone();
            let met6 = self.metrics.clone();
            let ipv4_src = self.source_ipv4;

            let handle = tokio::spawn(async move {
                type SrvResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
                let v4_fut = async move {
                    if let Some(l) = v4_listener {
                        sni::serve_sni_tcp_listener(l, tbl4, ctr4, cn4, met4, ipv4_src).await
                    } else {
                        std::future::pending::<SrvResult>().await
                    }
                };
                let v6_fut = async move {
                    if let Some(l) = v6_listener {
                        sni::serve_sni_tcp_listener(l, tbl6, ctr6, cn6, met6, ipv4_src).await
                    } else {
                        std::future::pending::<SrvResult>().await
                    }
                };
                tokio::select! {
                    r = v4_fut => { if let Err(e) = r { tracing::error!("SNI TCP v4 serve ended (port {}): {}", port, e); } }
                    r = v6_fut => { if let Err(e) = r { tracing::error!("SNI TCP v6 serve ended (port {}): {}", port, e); } }
                }
            });

            self.sni_listeners.insert(
                port,
                ManagedSniListener {
                    handle,
                    table,
                    rule_fingerprints: new_fps,
                },
            );
        }

        // ── Step 5: prune counters and runtime state for removed rules ──
        for rule_id in dead_rule_ids {
            if !desired_rule_ids.contains(&rule_id) && !self.rule_still_referenced(rule_id) {
                self.counter.prune_rule(rule_id).await;
            }
        }
        self.rule_runtime
            .retain(|rule_id, _| desired_rule_ids.contains(rule_id));
        self.last_config = Some(config.clone());
    }

    pub async fn restart_rule(&mut self, rule_id: i64) -> (u64, usize) {
        let dropped = self
            .rule_runtime
            .get(&rule_id)
            .map(|rt| rt.cancel_all())
            .unwrap_or(0);

        let raw_keys: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|(_, m)| m.fingerprint.rule_id == rule_id)
            .map(|(k, _)| *k)
            .collect();

        let sni_ports: Vec<u16> = self
            .sni_listeners
            .iter()
            .filter(|(_, m)| m.rule_fingerprints.contains_key(&rule_id))
            .map(|(p, _)| *p)
            .collect();

        if raw_keys.is_empty() && sni_ports.is_empty() {
            return (dropped, 0);
        }

        for key in &raw_keys {
            if let Some(m) = self.listeners.remove(key) {
                let handle = m.handle;
                handle.abort();
                let _ = (&mut { handle }).await;
            }
        }

        // For an SNI rule on a shared port, remove its fingerprint entry so
        // `apply_config` below rebuilds its SniRouteEntry (fresh gate + selector)
        // in-place WITHOUT tearing down the shared port listener or interrupting
        // sibling SNI rules on the same port.
        for port in &sni_ports {
            if let Some(m) = self.sni_listeners.get_mut(port) {
                m.rule_fingerprints.remove(&rule_id);
            }
        }

        let restarted = raw_keys.len() + sni_ports.len();
        if restarted > 0 {
            if let Some(cfg) = self.last_config.clone() {
                self.apply_config(&cfg).await;
            } else {
                tracing::warn!(
                    "rule {}: restart tore down {} listener(s) but no cached config exists",
                    rule_id,
                    restarted
                );
            }
        }

        tracing::info!(
            "rule {}: restarted — dropped {} connection(s), rebuilt {} listener(s)",
            rule_id,
            dropped,
            restarted
        );
        (dropped, restarted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::{ConnectionTracker, NodeMetrics, TrafficCounter};
    use relay_shared::models::default_sni_fallback_addr;
    use relay_shared::protocol::{ListenerConfig, NodeConfigResponse, Protocol};
    use std::sync::Arc;
    use std::time::Duration;

    impl ForwarderManager {
        fn listener_keys(&self) -> Vec<ListenerKey> {
            self.listeners.keys().copied().collect()
        }
    }

    fn one_rule(port: u16, proto: Protocol) -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port,
                protocol: proto,
                targets: vec!["127.0.0.1:1".into()],
                sni: None,
                sni_fallback_addr: default_sni_fallback_addr(),
                sni_loop_bypass_ips: Vec::new(),
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                per_ip_upload_limit_bps: None,
                per_ip_download_limit_bps: None,
                max_connections: None,
                proxy_protocol: Default::default(),
            }],
        }
    }

    fn cfg(port: u16, proto: Protocol, targets: Vec<&str>) -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port,
                protocol: proto,
                targets: targets.into_iter().map(String::from).collect(),
                sni: None,
                sni_fallback_addr: default_sni_fallback_addr(),
                sni_loop_bypass_ips: Vec::new(),
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                per_ip_upload_limit_bps: None,
                per_ip_download_limit_bps: None,
                max_connections: None,
                proxy_protocol: Default::default(),
            }],
        }
    }

    fn fresh_mgr() -> ForwarderManager {
        ForwarderManager::new(
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            Arc::new(NodeMetrics::new("auto")),
        )
    }

    #[test]
    fn rate_limit_change_alters_fingerprint() {
        let mut l = one_rule(40050, Protocol::Tcp).listeners.pop().unwrap();
        let unlimited = ListenerFingerprint::from_listener(&l);

        l.upload_limit_bps = Some(1_000_000);
        let up_limited = ListenerFingerprint::from_listener(&l);
        assert_ne!(unlimited, up_limited);

        l.upload_limit_bps = None;
        l.download_limit_bps = Some(2_000_000);
        let down_limited = ListenerFingerprint::from_listener(&l);
        assert_ne!(up_limited, down_limited);
        assert_ne!(unlimited, down_limited);

        l.download_limit_bps = None;
        l.per_ip_download_limit_bps = Some(10_000_000);
        let per_ip_limited = ListenerFingerprint::from_listener(&l);
        assert_ne!(unlimited, per_ip_limited);
        assert_ne!(down_limited, per_ip_limited);
    }

    #[test]
    fn max_connections_change_alters_fingerprint() {
        let mut l = one_rule(40051, Protocol::Tcp).listeners.pop().unwrap();
        let uncapped = ListenerFingerprint::from_listener(&l);

        l.max_connections = Some(100);
        let capped = ListenerFingerprint::from_listener(&l);
        assert_ne!(uncapped, capped);

        l.max_connections = Some(200);
        assert_ne!(capped, ListenerFingerprint::from_listener(&l));
    }

    async fn echo_target() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut b = [0u8; 256];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn restart_rule_drops_live_connections_and_rebuilds_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = echo_target().await;
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let port = 40561;
        let c = cfg(port, Protocol::Tcp, vec![&target.to_string()]);
        mgr.apply_config(&c).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener must be up");
        client.write_all(b"before").await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before");

        let (dropped, restarted) = mgr.restart_rule(1).await;
        assert_eq!(dropped, 1);
        assert_eq!(restarted, 1);

        let r = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!(
                "restart did NOT drop the connection — it echoed {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(_) => panic!("restart did NOT drop the connection — the read is still hanging"),
        }

        let mut fresh = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener must be re-bound after restart");
        fresh.write_all(b"after").await.unwrap();
        let n = fresh.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after");
    }

    #[tokio::test]
    async fn stop_accepting_refuses_new_connections_but_keeps_live_ones_forwarding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target = echo_target().await;
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let port = 40581;
        let c = cfg(port, Protocol::Tcp, vec![&target.to_string()]);
        mgr.apply_config(&c).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener must be up");
        client.write_all(b"before").await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before");

        assert_eq!(mgr.stop_accepting().await, 1);

        client.write_all(b"during").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("a live connection must keep forwarding after stop_accepting")
            .unwrap();
        assert_eq!(&buf[..n], b"during");

        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        );

        mgr.apply_config(&c).await;
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn restart_unknown_rule_is_a_noop() {
        let mut mgr = fresh_mgr();
        assert_eq!(mgr.restart_rule(999).await, (0, 0));
        assert!(mgr.rule_runtime.is_empty());
    }

    #[tokio::test]
    async fn restart_udp_only_rule_rebuilds_its_listener() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let c = cfg(40571, Protocol::Udp, vec!["127.0.0.1:9"]);
        mgr.apply_config(&c).await;
        assert_eq!(mgr.listener_keys().len(), 1);

        let (dropped, restarted) = mgr.restart_rule(1).await;
        assert_eq!(restarted, 1);
        assert_eq!(dropped, 0);
        assert_eq!(mgr.listener_keys().len(), 1);
    }

    #[tokio::test]
    async fn shared_port_sni_rules_coexist_and_diagnose_or_restart_per_rule() {
        let mut mgr = fresh_mgr();
        mgr.listen_ipv6 = String::new();
        let port = 40591;
        let c = NodeConfigResponse {
            listeners: vec![
                ListenerConfig {
                    rule_id: 101,
                    port,
                    protocol: Protocol::Tcp,
                    targets: vec!["127.0.0.1:8001".into()],
                    sni: Some("a.example.com".into()),
                    sni_fallback_addr: default_sni_fallback_addr(),
                    sni_loop_bypass_ips: Vec::new(),
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    per_ip_upload_limit_bps: None,
                    per_ip_download_limit_bps: None,
                    max_connections: None,
                    proxy_protocol: Default::default(),
                },
                ListenerConfig {
                    rule_id: 102,
                    port,
                    protocol: Protocol::Tcp,
                    targets: vec!["127.0.0.1:8002".into()],
                    sni: Some("b.example.com".into()),
                    sni_fallback_addr: default_sni_fallback_addr(),
                    sni_loop_bypass_ips: Vec::new(),
                    load_balance_strategy: LoadBalanceStrategy::First,
                    upload_limit_bps: None,
                    download_limit_bps: None,
                    per_ip_upload_limit_bps: None,
                    per_ip_download_limit_bps: None,
                    max_connections: None,
                    proxy_protocol: Default::default(),
                },
            ],
        };
        mgr.apply_config(&c).await;
        assert_eq!(mgr.sni_listeners.len(), 1);

        let info1 = mgr.listener_info_for_rule_tcp(101).unwrap();
        assert_eq!(info1.port, port);
        assert_eq!(info1.transport, "sni");
        assert_eq!(info1.targets, vec!["127.0.0.1:8001".to_string()]);
        assert!(info1.running);

        let info2 = mgr.listener_info_for_rule_tcp(102).unwrap();
        assert_eq!(info2.targets, vec!["127.0.0.1:8002".to_string()]);
        assert!(info2.running);

        let (_, restarted) = mgr.restart_rule(101).await;
        assert_eq!(restarted, 1);
        assert!(mgr.listener_info_for_rule_tcp(101).unwrap().running);
        assert!(mgr.listener_info_for_rule_tcp(102).unwrap().running);
    }

    #[tokio::test]
    async fn deleted_rule_prunes_traffic_counter() {
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let metrics = Arc::new(NodeMetrics::new("auto"));
        let mut mgr = ForwarderManager::new(counter.clone(), connections, metrics);

        mgr.apply_config(&one_rule(40003, Protocol::Tcp)).await;
        counter.add(1, 100, 50).await;
        assert!(counter.has_rule(1).await);

        mgr.apply_config(&NodeConfigResponse {
            listeners: Vec::new(),
        })
        .await;

        assert!(
            !counter.has_rule(1).await,
            "orphan rule_id must be pruned after rule deletion"
        );
    }
}
