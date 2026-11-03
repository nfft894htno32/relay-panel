// Repository trait layer.
#![allow(dead_code)]

use async_trait::async_trait;
use relay_shared::models::{DeviceGroup, ForwardRule, ForwardRuleTarget, Statistic, User};
use relay_shared::protocol::{RuleTargetRequest, TrafficEntry};

use super::error::DbError;

/// The ownership scope a resource query is restricted to.
#[derive(Debug, Clone, Copy)]
pub enum ResourceScope {
    All,
    Owner(i64),
}

impl ResourceScope {
    pub fn owner_id(&self) -> Option<i64> {
        match self {
            ResourceScope::All => None,
            ResourceScope::Owner(uid) => Some(*uid),
        }
    }
}

/// A rule's PROXY protocol settings as stored (see `ForwardRule::proxy_protocol_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleProxyProtocol {
    /// "off" | "v1" | "v2"
    pub send: String,
    pub accept: bool,
    /// Comma-separated IPs/CIDRs, already validated; empty = any.
    pub trusted: String,
}

impl Default for RuleProxyProtocol {
    fn default() -> Self {
        Self {
            send: "off".into(),
            accept: false,
            trusted: String::new(),
        }
    }
}

/// One rule edit, for [`RuleRepository::update_rule_full`]. `None` leaves a
/// field as it is; for nullable columns, `Some(None)` clears it.
#[derive(Debug, Default, Clone, Copy)]
pub struct RuleUpdate<'a> {
    pub name: Option<&'a str>,
    pub listen_port: Option<i32>,
    pub protocol: Option<&'a str>,
    pub sni: Option<Option<&'a str>>,
    pub device_group_in: Option<i64>,
    pub device_group_out: Option<Option<i64>>,
    pub forward_mode: Option<&'a str>,
    pub target_addr: Option<&'a str>,
    pub target_port: Option<i32>,
    pub paused: Option<bool>,
    /// Replaces the whole target list.
    pub targets: Option<&'a [RuleTargetRequest]>,
    pub load_balance_strategy: Option<&'a str>,
    pub upload_limit_mbps: Option<i32>,
    pub download_limit_mbps: Option<i32>,
    pub per_ip_upload_limit_mbps: Option<i32>,
    pub per_ip_download_limit_mbps: Option<i32>,
    pub max_connections: Option<i32>,
    pub auto_restart_minutes: Option<i32>,
    pub proxy_protocol_send: Option<&'a str>,
    pub proxy_protocol_accept: Option<bool>,
    pub proxy_protocol_trusted: Option<&'a str>,
}

impl RuleUpdate<'_> {
    pub fn has_columns(&self) -> bool {
        self.name.is_some()
            || self.listen_port.is_some()
            || self.protocol.is_some()
            || self.sni.is_some()
            || self.device_group_in.is_some()
            || self.device_group_out.is_some()
            || self.forward_mode.is_some()
            || self.target_addr.is_some()
            || self.target_port.is_some()
            || self.paused.is_some()
            || self.load_balance_strategy.is_some()
            || self.upload_limit_mbps.is_some()
            || self.download_limit_mbps.is_some()
            || self.per_ip_upload_limit_mbps.is_some()
            || self.per_ip_download_limit_mbps.is_some()
            || self.max_connections.is_some()
            || self.auto_restart_minutes.is_some()
            || self.proxy_protocol_send.is_some()
            || self.proxy_protocol_accept.is_some()
            || self.proxy_protocol_trusted.is_some()
    }
}

// ── User ──

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError>;
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError>;
    async fn find_password_by_id(&self, id: i64) -> Result<Option<String>, DbError>;
    /// The auth state the middleware needs in ONE query —
    /// (token_version, must_change_password, admin). None = user deleted.
    async fn find_auth_state_by_id(
        &self,
        id: i64,
    ) -> Result<Option<(i64, bool, bool)>, DbError>;
    async fn is_admin(&self, id: i64) -> Result<bool, DbError>;
    async fn exists_by_id(&self, id: i64) -> Result<bool, DbError>;
    async fn update_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError>;
    async fn change_own_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError>;
    async fn admin_reset_password(
        &self,
        id: i64,
        new_hash: &str,
        must_change_password: bool,
    ) -> Result<u64, DbError>;
    async fn increment_user_traffic(&self, id: i64, delta: i64) -> Result<(), DbError>;
    async fn reset_traffic(&self, id: i64) -> Result<(), DbError>;
    async fn count_placeholder_admin_password(&self) -> Result<i64, DbError>;
    async fn replace_placeholder_admin_password(&self, hash: &str) -> Result<(), DbError>;
}

// ── Rule (forward_rules) ──

#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn list_rules(&self, scope: &ResourceScope) -> Result<Vec<ForwardRule>, DbError>;
    async fn find_rule_by_id(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<ForwardRule>, DbError>;
    async fn list_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError>;
    async fn list_enabled_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError>;
    async fn list_enabled_targets_for_rules(
        &self,
        rule_ids: &[i64],
    ) -> Result<Vec<ForwardRuleTarget>, DbError>;
    async fn replace_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        targets: &[RuleTargetRequest],
    ) -> Result<(), DbError>;
    async fn set_rule_load_balance_strategy(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        strategy: &str,
    ) -> Result<u64, DbError>;
    async fn set_rule_rate_limits(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
    ) -> Result<u64, DbError>;
    async fn set_rule_connection_controls(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        max_connections: i32,
        auto_restart_minutes: i32,
    ) -> Result<u64, DbError>;
    async fn list_auto_restart_rules(&self) -> Result<Vec<(i64, i64, i32)>, DbError>;
    async fn list_group_port_protocols(
        &self,
        device_group_in: i64,
    ) -> Result<Vec<(i32, String)>, DbError>;
    async fn group_port_range(&self, group_id: i64) -> Result<Option<String>, DbError>;
    async fn count_by_uid(&self, uid: i64) -> Result<i64, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn create_rule_full(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        protocol: &str,
        sni: Option<&str>,
        device_group_in: i64,
        device_group_out: Option<i64>,
        forward_mode: &str,
        target_addr: &str,
        target_port: i32,
        targets: &[RuleTargetRequest],
        load_balance_strategy: &str,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
        per_ip_upload_limit_mbps: i32,
        per_ip_download_limit_mbps: i32,
        max_connections: i32,
        auto_restart_minutes: i32,
        proxy_protocol: &RuleProxyProtocol,
    ) -> Result<i64, DbError>;
    async fn find_device_group_out_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<Option<i64>>, DbError>;
    async fn update_rule_full(
        &self,
        id: i64,
        scope: &ResourceScope,
        update: &RuleUpdate<'_>,
    ) -> Result<u64, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn update_rule_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        listen_port: Option<i32>,
        protocol: Option<&str>,
        sni: Option<Option<&str>>,
        device_group_in: Option<i64>,
        device_group_out: Option<Option<i64>>,
        forward_mode: Option<&str>,
        target_addr: Option<&str>,
        target_port: Option<i32>,
        paused: Option<bool>,
    ) -> Result<u64, DbError> {
        let update = RuleUpdate {
            name,
            listen_port,
            protocol,
            sni,
            device_group_in,
            device_group_out,
            forward_mode,
            target_addr,
            target_port,
            paused,
            ..RuleUpdate::default()
        };
        if !update.has_columns() {
            return Ok(0);
        }
        self.update_rule_full(id, scope, &update).await
    }
    async fn increment_rule_traffic(
        &self,
        id: i64,
        upload: u64,
        download: u64,
    ) -> Result<(), DbError>;
    async fn find_rule_owner(
        &self,
        rule_id: i64,
        device_group_in: i64,
    ) -> Result<Option<(i64, i64)>, DbError>;
    async fn delete_rule(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
    async fn reset_rule_traffic(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
    async fn delete_rules_by_uid(&self, uid: i64) -> Result<u64, DbError>;
    async fn list_active_for_config(&self, group_id: i64) -> Result<Vec<ForwardRule>, DbError>;
}

// ── Group (device_groups) ──

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn list_groups(&self, scope: &ResourceScope) -> Result<Vec<DeviceGroup>, DbError>;
    async fn find_by_token(&self, token: &str) -> Result<Option<DeviceGroup>, DbError>;
    async fn find_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<DeviceGroup>, DbError>;
    async fn find_name_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<String>, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn insert_group(
        &self,
        name: &str,
        group_type: &str,
        token: &str,
        uid: i64,
        connect_host: &str,
        port_range: &str,
        sni_fallback_addr: &str,
        sni_loop_bypass_ips: &str,
    ) -> Result<(), DbError>;
    async fn find_by_token_after_insert(&self, token: &str)
        -> Result<Option<DeviceGroup>, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn update_group_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        group_type: Option<&str>,
        connect_host: Option<&str>,
        port_range: Option<&str>,
        sni_fallback_addr: Option<&str>,
        sni_loop_bypass_ips: Option<&str>,
    ) -> Result<u64, DbError>;
    async fn update_group_token(
        &self,
        id: i64,
        scope: &ResourceScope,
        new_token: &str,
    ) -> Result<u64, DbError>;
    async fn count_rules_by_group(&self, id: i64) -> Result<i64, DbError>;
    async fn delete_group(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
    async fn delete_groups_by_uid(&self, uid: i64) -> Result<u64, DbError>;
    async fn reorder_groups(&self, ids: &[i64]) -> Result<(), DbError>;
}

/// The ids in `current` (already in display order) that `listed` leaves out,
/// in that same order. Shared by both backends' `reorder_groups`.
pub(crate) fn unlisted_ids(current: &[(i64,)], listed: &[i64]) -> Vec<i64> {
    let listed: std::collections::HashSet<i64> = listed.iter().copied().collect();
    current
        .iter()
        .map(|(id,)| *id)
        .filter(|id| !listed.contains(id))
        .collect()
}

// ── Traffic (atomic batch) ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficEntryResult {
    Ok,
    Unavailable,
    Overflow,
    AlreadyApplied,
}

#[async_trait]
pub trait TrafficRepository: Send + Sync {
    async fn apply_traffic_batch_with_id(
        &self,
        group_id: i64,
        batch_id: Option<&str>,
        acked_batch_id: Option<&str>,
        entries: &[TrafficEntry],
    ) -> Result<Vec<TrafficEntryResult>, DbError>;

    async fn apply_traffic_batch(
        &self,
        group_id: i64,
        entries: &[TrafficEntry],
    ) -> Result<Vec<TrafficEntryResult>, DbError> {
        self.apply_traffic_batch_with_id(group_id, None, None, entries)
            .await
    }

    async fn prune_traffic_batches(
        &self,
        confirmed_before: &str,
        recorded_before: &str,
    ) -> Result<u64, DbError>;

    async fn query_traffic_history(
        &self,
        uid: Option<i64>,
        rule_id: Option<i64>,
        since: &str,
        daily: bool,
    ) -> Result<Vec<TrafficHistoryBucket>, DbError>;

    async fn prune_traffic_history(&self, cutoff: &str) -> Result<u64, DbError>;

    async fn record_node_metrics(&self, m: &NodeMetricSample) -> Result<(), DbError>;

    async fn query_node_metrics(
        &self,
        since: &str,
        daily: bool,
    ) -> Result<Vec<NodeMetricBucket>, DbError>;

    async fn prune_node_metrics(&self, cutoff: &str) -> Result<u64, DbError>;

    async fn record_audit(&self, e: &NewAuditEntry) -> Result<(), DbError>;

    async fn query_audit_log(
        &self,
        action: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEntry>, DbError>;

    async fn count_audit_log(&self, action: Option<&str>) -> Result<i64, DbError>;

    async fn prune_audit_log(&self, cutoff: &str) -> Result<u64, DbError>;
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Announcement {
    pub id: i64,
    pub title: String,
    pub content: String,
    pub kind: String,
    pub pinned: bool,
    pub published_at: String,
    pub expires_at: Option<String>,
    pub author_id: Option<i64>,
    pub author_name: String,
}

#[derive(Debug, Clone)]
pub struct NewAnnouncement {
    pub title: String,
    pub content: String,
    pub kind: String,
    pub pinned: bool,
    pub published_at: String,
    pub expires_at: Option<String>,
    pub author_id: Option<i64>,
    pub author_name: String,
}

// ── Announcements ──

#[async_trait]
pub trait AnnouncementRepository: Send + Sync {
    async fn active_announcement(&self, now: &str) -> Result<Option<Announcement>, DbError>;

    async fn list_announcements(
        &self,
        include_expired: bool,
        now: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Announcement>, DbError>;

    async fn count_announcements(&self, include_expired: bool, now: &str) -> Result<i64, DbError>;

    async fn find_announcement(&self, id: i64) -> Result<Option<Announcement>, DbError>;

    async fn create_announcement(&self, a: &NewAnnouncement) -> Result<i64, DbError>;

    async fn update_announcement(&self, id: i64, a: &NewAnnouncement) -> Result<u64, DbError>;

    async fn delete_announcement(&self, id: i64) -> Result<u64, DbError>;

    async fn latest_announcement_id(&self) -> Result<i64, DbError>;
}

#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub ts: String,
    pub actor_id: Option<i64>,
    pub actor_name: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub actor_id: Option<i64>,
    pub actor_name: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct NodeMetricSample {
    pub node_id: String,
    pub group_id: i64,
    pub hour_ts: String,
    pub cpu: f64,
    pub mem: f64,
    pub connections: i64,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct NodeMetricBucket {
    pub bucket: String,
    pub node_id: String,
    pub group_id: i64,
    pub group_name: String,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub mem_avg: f64,
    pub mem_max: f64,
    pub conn_avg: f64,
    pub conn_max: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct TrafficHistoryBucket {
    pub bucket: String,
    pub group_id: i64,
    pub group_name: String,
    pub real_upload: i64,
    pub real_download: i64,
    pub billed_total: i64,
}

// ── KVS (generic key-value) ──

#[async_trait]
pub trait KvsRepository: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, DbError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), DbError>;
    async fn delete(&self, key: &str) -> Result<u64, DbError>;
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, DbError>;
}

// ── Statistics ──

#[async_trait]
pub trait StatisticsRepository: Send + Sync {
    async fn query_stats(
        &self,
        stat_type: Option<&str>,
        stat_key: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<Statistic>, DbError>;
}

// ── Aggregate ──

#[async_trait]
pub trait Repository:
    UserRepository
    + RuleRepository
    + GroupRepository
    + TrafficRepository
    + KvsRepository
    + StatisticsRepository
    + AnnouncementRepository
    + Send
    + Sync
{
}
