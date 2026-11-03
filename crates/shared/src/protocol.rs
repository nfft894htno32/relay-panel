use crate::models::default_sni_fallback_addr;
use serde::{Deserialize, Serialize};

pub const CONFIG_PROTOCOL_VERSION: u32 = 4;

// === Auth ===
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfigRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfigResponse {
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub rule_id: i64,
    pub port: u16,
    pub protocol: Protocol,
    pub targets: Vec<String>,
    /// Optional TLS SNI hostname (or `*.example.com` wildcard) for single-port
    /// multi-SNI routing on TCP rules. `None` = raw port-level forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Fallback target address when a shared SNI port receives non-TLS, missing
    /// SNI, unmatched SNI, or an anti-loop connection (default `127.0.0.1:10443`).
    #[serde(default = "default_sni_fallback_addr")]
    pub sni_fallback_addr: String,
    /// Optional extra IPs or CIDRs treated as anti-loop sources on a shared SNI
    /// port (in addition to loopback, node's own public IPs, and rule target IPs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni_loop_bypass_ips: Vec<String>,
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,
    #[serde(default)]
    pub upload_limit_bps: Option<u64>,
    #[serde(default)]
    pub download_limit_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_ip_upload_limit_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_ip_download_limit_bps: Option<u64>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "ProxyProtocolConfig::is_off")]
    pub proxy_protocol: ProxyProtocolConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolVersion {
    #[default]
    Off,
    V1,
    V2,
}

impl ProxyProtocolVersion {
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "v1" => Self::V1,
            "v2" => Self::V2,
            _ => Self::Off,
        }
    }

    pub fn to_db_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct ProxyProtocolConfig {
    #[serde(default)]
    pub send: ProxyProtocolVersion,
    #[serde(default)]
    pub accept: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted: Vec<String>,
}

impl ProxyProtocolConfig {
    pub fn is_off(&self) -> bool {
        self.send == ProxyProtocolVersion::Off && !self.accept
    }

    pub fn from_rule(send: &str, accept: bool, trusted: &str) -> Self {
        Self {
            send: ProxyProtocolVersion::from_db_str(send),
            accept,
            trusted: trusted
                .split([',', ' ', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }
}

pub fn mbps_to_bps(mbps: i32) -> Option<u64> {
    if mbps <= 0 {
        return None;
    }
    Some(mbps as u64 * 125_000)
}

pub fn expand_protocols(protocol: &str) -> Vec<Protocol> {
    match protocol {
        "udp" => vec![Protocol::Udp],
        "tcp_udp" => vec![Protocol::Tcp, Protocol::Udp],
        _ => vec![Protocol::Tcp],
    }
}

pub fn build_listeners_for_rule(
    rule: &crate::models::ForwardRule,
    targets: Vec<String>,
) -> Vec<ListenerConfig> {
    let normalized_sni = rule
        .sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    expand_protocols(&rule.protocol)
        .into_iter()
        .map(|proto| ListenerConfig {
            rule_id: rule.id,
            port: rule.listen_port as u16,
            protocol: proto,
            targets: targets.clone(),
            sni: if proto == Protocol::Tcp {
                normalized_sni.clone()
            } else {
                None
            },
            sni_fallback_addr: default_sni_fallback_addr(),
            sni_loop_bypass_ips: Vec::new(),
            load_balance_strategy: LoadBalanceStrategy::from_db_str(&rule.load_balance_strategy),
            upload_limit_bps: mbps_to_bps(rule.upload_limit_mbps),
            download_limit_bps: mbps_to_bps(rule.download_limit_mbps),
            per_ip_upload_limit_bps: mbps_to_bps(rule.per_ip_upload_limit_mbps),
            per_ip_download_limit_bps: mbps_to_bps(rule.per_ip_download_limit_mbps),
            max_connections: if rule.max_connections > 0 {
                Some(rule.max_connections as u32)
            } else {
                None
            },
            proxy_protocol: if proto == Protocol::Tcp {
                ProxyProtocolConfig::from_rule(
                    &rule.proxy_protocol_send,
                    rule.proxy_protocol_accept,
                    &rule.proxy_protocol_trusted,
                )
            } else {
                ProxyProtocolConfig::default()
            },
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    #[serde(rename = "tcp_udp")]
    TcpUdp,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    First,
    RoundRobin,
    Failover,
}

impl LoadBalanceStrategy {
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "round_robin" => LoadBalanceStrategy::RoundRobin,
            "failover" => LoadBalanceStrategy::Failover,
            _ => LoadBalanceStrategy::First,
        }
    }
    pub fn to_db_str(self) -> &'static str {
        match self {
            LoadBalanceStrategy::First => "first",
            LoadBalanceStrategy::RoundRobin => "round_robin",
            LoadBalanceStrategy::Failover => "failover",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficReport {
    pub reports: Vec<TrafficEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_batch_id: Option<String>,
}

pub const MAX_TRAFFIC_BATCH_ID_LEN: usize = 64;

pub fn valid_traffic_batch_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_TRAFFIC_BATCH_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub rule_id: i64,
    pub upload: u64,
    pub download: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub cpu_usage: f32,
    pub mem_usage: f32,
    pub active_connections: u32,
    pub uptime_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_usage_percent: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_upload_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_download_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_uptime_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_protocol_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_errors: Option<Vec<ListenerError>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount: String,
    pub fs_type: String,
    pub total: u64,
    pub used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerError {
    pub port: u16,
    pub protocol: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseRuleMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub request_id: String,
    pub rule_id: i64,
    #[serde(default)]
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeNodeMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub node_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResult {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub node_id: String,
    pub from_version: String,
    pub target_version: String,
    pub error: String,
}

impl UpgradeResult {
    pub fn new(node_id: String, from_version: String, target_version: String, error: &str) -> Self {
        Self {
            msg_type: "upgrade_result".into(),
            node_id,
            from_version,
            target_version,
            error: sanitize_upgrade_error(error),
        }
    }
}

pub const MAX_UPGRADE_ERROR_LEN: usize = 300;

pub fn sanitize_upgrade_error(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_UPGRADE_ERROR_LEN));
    let mut last_was_space = false;
    for ch in raw.chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch == ' ' {
            if last_was_space {
                continue;
            }
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        out.push(ch);
    }
    let out = out.trim();
    if out.chars().count() > MAX_UPGRADE_ERROR_LEN {
        let kept: String = out.chars().take(MAX_UPGRADE_ERROR_LEN).collect();
        format!("{kept}...")
    } else {
        out.to_string()
    }
}

pub const LIVE_RATE_INTERVAL_SECS: u64 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRateMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub upload_bps: u64,
    pub download_bps: u64,
}

impl NodeRateMessage {
    pub const TYPE: &'static str = "node_rate";

    pub fn new(upload_bps: u64, download_bps: u64) -> Self {
        Self {
            msg_type: Self::TYPE.into(),
            upload_bps,
            download_bps,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLiveRate {
    pub group_id: i64,
    pub node_id: String,
    pub upload_bps: u64,
    pub download_bps: u64,
}

impl DiagnoseRuleMessage {
    pub fn new(request_id: String, rule_id: i64, challenge: String) -> Self {
        Self {
            msg_type: "diagnose_rule".into(),
            request_id,
            rule_id,
            challenge,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartRuleMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub node_id: String,
    pub rule_id: i64,
    pub request_id: String,
}

impl RestartRuleMessage {
    pub fn new(node_id: String, rule_id: i64, request_id: String) -> Self {
        Self {
            msg_type: "restart_rule".into(),
            node_id,
            rule_id,
            request_id,
        }
    }
}

pub fn node_supports_restart_rule(version: Option<&str>) -> bool {
    node_version_at_least(version, (1, 2, 0))
}

pub fn node_supports_proxy_protocol(version: Option<&str>) -> bool {
    node_version_at_least(version, (1, 2, 9))
}

fn node_version_at_least(version: Option<&str>, min: (u32, u32, u32)) -> bool {
    let Some(v) = version else {
        return false;
    };
    let base = v.split('-').next().unwrap_or("");
    let mut parts = base.split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch) >= min
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProbeOutcome {
    Reachable { elapsed_ms: u64 },
    Failed { error: String },
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseTargetResult {
    pub address: String,
    pub outcome: TargetProbeOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseResult {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub request_id: String,
    pub rule_id: i64,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub challenge: String,
    pub listener_running: bool,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub results: Vec<DiagnoseTargetResult>,
}

pub fn node_supports_secure_diagnose(version: Option<&str>) -> bool {
    node_version_at_least(version, (0, 4, 9))
}

pub fn node_supports_directed_diagnose(version: Option<&str>) -> bool {
    node_version_at_least(version, (0, 4, 14))
}

// === Admin API — Rules ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTargetRequest {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_target_enabled")]
    pub enabled: bool,
}

fn default_target_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    /// If None, the server auto-assigns a free port from 10000-65535.
    pub listen_port: Option<u16>,
    pub protocol: Protocol,
    pub device_group_in: i64,
    #[serde(default)]
    pub device_group_out: Option<i64>,
    #[serde(default = "default_forward_mode")]
    pub forward_mode: String,
    /// Optional TLS SNI hostname (or `*.example.com` wildcard) for single-port
    /// multi-SNI routing on TCP rules.
    #[serde(default)]
    pub sni: Option<String>,
    pub target_addr: String,
    pub target_port: u16,
    #[serde(default)]
    pub targets: Option<Vec<RuleTargetRequest>>,
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,
    #[serde(default)]
    pub upload_limit_mbps: Option<i32>,
    #[serde(default)]
    pub download_limit_mbps: Option<i32>,
    #[serde(default)]
    pub per_ip_upload_limit_mbps: Option<i32>,
    #[serde(default)]
    pub per_ip_download_limit_mbps: Option<i32>,
    /// Cap on concurrent TCP connections PER NODE (0 / omitted = unlimited).
    #[serde(default)]
    pub max_connections: Option<i32>,
    /// Restart the rule every N minutes (0 / omitted = off).
    #[serde(default)]
    pub auto_restart_minutes: Option<i32>,
    #[serde(default)]
    pub proxy_protocol_send: ProxyProtocolVersion,
    #[serde(default)]
    pub proxy_protocol_accept: bool,
    #[serde(default)]
    pub proxy_protocol_trusted: String,
}

fn default_forward_mode() -> String {
    "direct".to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub listen_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub device_group_in: Option<i64>,
    pub device_group_out: Option<i64>,
    pub forward_mode: Option<String>,
    /// Update SNI hostname (`Some(Some("sub.example.com"))` sets SNI,
    /// `Some(None)` / `Some(Some(""))` clears SNI back to raw TCP, `None` leaves current).
    #[serde(default, deserialize_with = "deserialize_optional_sni")]
    pub sni: Option<Option<String>>,
    pub target_addr: Option<String>,
    pub target_port: Option<u16>,
    #[serde(default)]
    pub targets: Option<Vec<RuleTargetRequest>>,
    #[serde(default)]
    pub load_balance_strategy: Option<LoadBalanceStrategy>,
    #[serde(default)]
    pub upload_limit_mbps: Option<i32>,
    #[serde(default)]
    pub download_limit_mbps: Option<i32>,
    #[serde(default)]
    pub per_ip_upload_limit_mbps: Option<i32>,
    #[serde(default)]
    pub per_ip_download_limit_mbps: Option<i32>,
    #[serde(default)]
    pub paused: Option<bool>,
    #[serde(default)]
    pub max_connections: Option<i32>,
    #[serde(default)]
    pub auto_restart_minutes: Option<i32>,
    #[serde(default)]
    pub proxy_protocol_send: Option<ProxyProtocolVersion>,
    #[serde(default)]
    pub proxy_protocol_accept: Option<bool>,
    #[serde(default)]
    pub proxy_protocol_trusted: Option<String>,
}

fn deserialize_optional_sni<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

// === Admin API — Groups ===
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub group_type: GroupType,
    pub connect_host: String,
    pub port_range: String,
    #[serde(default)]
    pub sni_fallback_addr: Option<String>,
    #[serde(default)]
    pub sni_loop_bypass_ips: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub group_type: Option<GroupType>,
    pub connect_host: Option<String>,
    pub port_range: Option<String>,
    #[serde(default)]
    pub sni_fallback_addr: Option<String>,
    #[serde(default)]
    pub sni_loop_bypass_ips: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReorderGroupsRequest {
    pub ids: Vec<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum GroupType {
    #[serde(rename = "in")]
    In,
    #[serde(rename = "out")]
    Out,
    #[serde(rename = "monitor")]
    Monitor,
}

// === Common ===
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "ok".into(),
            data: Some(data),
        }
    }
    pub fn error(code: i32, message: &str) -> ApiResponse<()> {
        ApiResponse {
            code: code,
            message: message.into(),
            data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, protocol: &str, sni: Option<&str>) -> crate::models::ForwardRule {
        crate::models::ForwardRule {
            id,
            name: format!("rule-{id}"),
            uid: 1,
            paused: false,
            listen_port: 443,
            protocol: protocol.into(),
            device_group_in: 1,
            device_group_out: None,
            forward_mode: "direct".into(),
            sni: sni.map(str::to_string),
            target_addr: "127.0.0.1".into(),
            target_port: 8443,
            targets: Vec::new(),
            load_balance_strategy: "first".into(),
            upload_limit_mbps: 0,
            download_limit_mbps: 0,
            per_ip_upload_limit_mbps: 0,
            per_ip_download_limit_mbps: 0,
            max_connections: 0,
            auto_restart_minutes: 0,
            proxy_protocol_send: "off".into(),
            proxy_protocol_accept: false,
            proxy_protocol_trusted: String::new(),
            config: "{}".into(),
            traffic_used: 0,
            status: "active".into(),
            created_at: String::new(),
        }
    }

    #[test]
    fn expand_protocols_splits_tcp_udp() {
        assert_eq!(expand_protocols("tcp"), vec![Protocol::Tcp]);
        assert_eq!(expand_protocols("udp"), vec![Protocol::Udp]);
        assert_eq!(
            expand_protocols("tcp_udp"),
            vec![Protocol::Tcp, Protocol::Udp]
        );
    }

    #[test]
    fn build_listeners_for_rule_normalizes_sni_for_tcp_only() {
        let mut r = rule(1, "tcp_udp", Some("  Sub.Example.COM "));
        r.per_ip_upload_limit_mbps = 80;
        r.per_ip_download_limit_mbps = 80;
        let listeners = build_listeners_for_rule(&r, vec!["10.0.0.1:443".into()]);
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].protocol, Protocol::Tcp);
        assert_eq!(listeners[0].sni.as_deref(), Some("sub.example.com"));
        assert_eq!(listeners[0].sni_fallback_addr, "127.0.0.1:10443");
        assert_eq!(listeners[0].per_ip_upload_limit_bps, Some(10_000_000));
        assert_eq!(listeners[0].per_ip_download_limit_bps, Some(10_000_000));
        assert_eq!(listeners[1].protocol, Protocol::Udp);
        assert_eq!(listeners[1].sni, None);
        assert_eq!(listeners[1].per_ip_upload_limit_bps, Some(10_000_000));
        assert_eq!(listeners[1].per_ip_download_limit_bps, Some(10_000_000));
    }
}
