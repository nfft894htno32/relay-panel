use serde::{Deserialize, Serialize};

fn default_load_balance_strategy() -> String {
    "first".to_string()
}

pub fn default_sni_fallback_addr() -> String {
    "127.0.0.1:10443".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub traffic_used: i64,
    pub admin: bool,
    pub created_at: String,
    #[serde(default)]
    pub must_change_password: bool,
    #[serde(default)]
    pub token_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ForwardRuleTarget {
    pub id: i64,
    pub rule_id: i64,
    pub host: String,
    pub port: i32,
    pub position: i32,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ForwardRule {
    pub id: i64,
    pub name: String,
    pub uid: i64,
    pub paused: bool,
    pub listen_port: i32,
    pub protocol: String,
    pub device_group_in: i64,
    pub device_group_out: Option<i64>,
    pub forward_mode: String,
    /// Optional TLS SNI hostname (or `*.example.com` wildcard) for single-port
    /// multi-SNI routing on TCP rules. `None` = raw port-level forwarding.
    #[serde(default)]
    #[sqlx(default)]
    pub sni: Option<String>,
    pub target_addr: String,
    pub target_port: i32,
    #[serde(default)]
    #[sqlx(skip)]
    pub targets: Vec<ForwardRuleTarget>,
    #[serde(default = "default_load_balance_strategy")]
    pub load_balance_strategy: String,
    #[serde(default)]
    pub upload_limit_mbps: i32,
    #[serde(default)]
    pub download_limit_mbps: i32,
    #[serde(default)]
    #[sqlx(default)]
    pub per_ip_upload_limit_mbps: i32,
    #[serde(default)]
    #[sqlx(default)]
    pub per_ip_download_limit_mbps: i32,
    #[serde(default)]
    pub max_connections: i32,
    #[serde(default)]
    pub auto_restart_minutes: i32,
    #[serde(default = "default_proxy_protocol_send")]
    #[sqlx(default)]
    pub proxy_protocol_send: String,
    #[serde(default)]
    #[sqlx(default)]
    pub proxy_protocol_accept: bool,
    #[serde(default)]
    #[sqlx(default)]
    pub proxy_protocol_trusted: String,
    pub config: String,
    pub traffic_used: i64,
    pub status: String,
    pub created_at: String,
}

fn default_proxy_protocol_send() -> String {
    "off".to_string()
}

pub const MIN_AUTO_RESTART_MINUTES: i32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeviceGroup {
    pub id: i64,
    pub name: String,
    pub group_type: String,
    pub token: String,
    pub uid: i64,
    pub connect_host: String,
    pub port_range: String,
    pub fallback_group: Option<i64>,
    pub config: String,
    #[serde(default)]
    #[sqlx(default)]
    pub capabilities: String,
    #[serde(default)]
    #[sqlx(default)]
    pub region: Option<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub line_type: Option<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub remark: Option<String>,
    #[serde(default = "default_sni_fallback_addr")]
    #[sqlx(default)]
    pub sni_fallback_addr: String,
    #[serde(default)]
    #[sqlx(default)]
    pub sni_loop_bypass_ips: String,
    #[serde(default)]
    pub sort_order: i32,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Statistic {
    pub id: i64,
    pub stat_type: String,
    pub stat_key: String,
    pub time: String,
    pub number: i64,
}
