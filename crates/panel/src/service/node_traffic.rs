//! Per-node NIC traffic accounting, monthly quota management, and Telegram/email alerting.
//!
//! Each physical node (`{group_id}:{node_id}`, or legacy `{group_id}`) periodically reports
//! cumulative OS NIC counters (`boot_upload_bytes`, `boot_download_bytes`) in
//! `POST /api/v1/node/report_status`. Because OS counters reset on server reboot, this
//! service tracks reboot-safe deltas in KVS under `node_traffic:{node_key}`, lets admins
//! configure a total quota, calibrate used traffic, choose billing direction, configure
//! multi-level warning thresholds + monthly reset day, and dispatches alerts via
//! `service::notify` when thresholds or 100% exhaustion are reached.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::KvsRepository;
use crate::service::notify::{self, NotifyConfig};

/// KVS key prefix for per-node traffic quota & accounting records.
pub const NODE_TRAFFIC_PREFIX: &str = "node_traffic:";

/// Maximum number of warning thresholds allowed per node (excluding the built-in 100% exhaustion alert).
pub const MAX_WARN_THRESHOLDS: usize = 5;

/// Default warning thresholds when a record is initialized.
fn default_warn_thresholds() -> Vec<u8> {
    vec![80]
}

/// Billing direction for counting a node's NIC traffic against its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    /// Bidirectional: upload + download (common for Asian/domestic relay VPS).
    #[default]
    Both,
    /// Outbound / TX only.
    Upload,
    /// Inbound / RX only.
    Download,
    /// Whichever of cumulative upload or download is larger in the cycle.
    Max,
}

impl TrafficDirection {
    pub fn label_zh(self) -> &'static str {
        match self {
            TrafficDirection::Both => "双向计费（上行 + 下行）",
            TrafficDirection::Upload => "仅出站（上行）",
            TrafficDirection::Download => "仅入站（下行）",
            TrafficDirection::Max => "取上/下行较大值",
        }
    }
}

/// Lightweight per-`node_key` async mutex pool stored on `AppState` to serialize
/// concurrent KVS read-modify-write cycles between `report_status` heartbeats,
/// admin quota edits/resets, and scheduled billing-day resets.
#[derive(Clone, Default)]
pub struct NodeTrafficLocks {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl NodeTrafficLocks {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn lock(&self, node_key: &str) -> OwnedMutexGuard<()> {
        let entry = {
            let mut map = self.inner.lock().await;
            map.entry(node_key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        entry.lock_owned().await
    }

    pub async fn remove(&self, node_key: &str) {
        self.inner.lock().await.remove(node_key);
    }
}

/// Persisted per-node traffic accounting & quota record in KVS (`node_traffic:{node_key}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeTrafficRecord {
    /// Total quota in bytes. `0` = unlimited (still tracks usage, no alerts).
    pub total_bytes: u64,
    /// Manually calibrated base usage in bytes (reset to 0 on cycle reset).
    pub base_bytes: u64,
    /// Upload bytes accumulated from NIC heartbeats since last calibration or reset.
    pub period_upload_bytes: u64,
    /// Download bytes accumulated from NIC heartbeats since last calibration or reset.
    pub period_download_bytes: u64,
    /// Billing direction used to compute effective `used_bytes`.
    pub direction: TrafficDirection,
    /// Sorted, deduplicated warning thresholds in `1..=99`. 100% exhaustion is always built in.
    #[serde(default = "default_warn_thresholds")]
    pub warn_thresholds: Vec<u8>,
    /// Optional monthly auto-reset day (`1..=31`). `None` = manual reset only.
    pub reset_day: Option<u8>,
    /// RFC3339 UTC timestamp of the last reset (or initialization of `reset_day`).
    pub last_reset_at: Option<String>,
    /// Last observed cumulative OS NIC upload counter (since OS boot).
    pub last_boot_upload_bytes: Option<u64>,
    /// Last observed cumulative OS NIC download counter (since OS boot).
    pub last_boot_download_bytes: Option<u64>,
    /// Last observed NIC name (e.g. `eth0`); switching NICs re-baselines without injecting a jump.
    pub last_network_interface: Option<String>,
    /// Warning thresholds already alerted in the current billing cycle.
    pub notified_thresholds: Vec<u8>,
    /// Whether the 100% exhaustion alert has been sent in the current billing cycle.
    pub notified_exhausted: bool,
}

impl Default for NodeTrafficRecord {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            base_bytes: 0,
            period_upload_bytes: 0,
            period_download_bytes: 0,
            direction: TrafficDirection::Both,
            warn_thresholds: default_warn_thresholds(),
            reset_day: None,
            last_reset_at: None,
            last_boot_upload_bytes: None,
            last_boot_download_bytes: None,
            last_network_interface: None,
            notified_thresholds: Vec::new(),
            notified_exhausted: false,
        }
    }
}

/// Public API representation attached to `GET /api/v1/nodes` rows and returned by
/// quota update/reset endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct NodeTrafficSummary {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub base_bytes: u64,
    pub period_upload_bytes: u64,
    pub period_download_bytes: u64,
    pub direction: TrafficDirection,
    pub warn_thresholds: Vec<u8>,
    pub reset_day: Option<u8>,
    pub last_reset_at: Option<String>,
    pub next_reset_date: Option<String>,
    pub usage_percent: Option<f64>,
    pub notified_thresholds: Vec<u8>,
    pub notified_exhausted: bool,
    /// `"unlimited"` | `"normal"` | `"warning"` | `"exhausted"`
    pub status: &'static str,
}

/// Alert transition produced by [`NodeTrafficRecord::evaluate_alert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficAlert {
    Threshold {
        threshold_pct: u8,
        used_bytes: u64,
        total_bytes: u64,
    },
    Exhausted {
        used_bytes: u64,
        total_bytes: u64,
    },
}

/// Build the KVS key for one node's traffic quota record.
pub fn traffic_key(node_key: &str) -> String {
    format!("{NODE_TRAFFIC_PREFIX}{node_key}")
}

/// Exact integer comparison for `used / total >= pct / 100` without floating-point rounding drift.
pub fn reached_threshold(used: u64, total: u64, pct: u8) -> bool {
    total > 0 && (used as u128).saturating_mul(100) >= (total as u128).saturating_mul(pct as u128)
}

/// Validate and normalize warning thresholds.
///
/// Accepts percentages in `1..=100`; `100` is silently folded into the built-in exhaustion
/// check so users who enter `80, 90, 100` aren't rejected or double-notified.
pub fn normalize_thresholds(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for &v in raw {
        if v == 0 || v > 100 {
            return Err("告警阈值必须在 1% 到 99% 之间".into());
        }
        if v == 100 {
            continue;
        }
        out.push(v);
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_WARN_THRESHOLDS {
        return Err(format!("告警阈值最多设置 {MAX_WARN_THRESHOLDS} 个"));
    }
    Ok(out)
}

/// Validate and normalize an optional monthly reset day (`None` or `Some(0)` -> `None`, `1..=31` -> `Some(d)`).
pub fn normalize_reset_day(raw: Option<u8>) -> Result<Option<u8>, String> {
    match raw {
        None | Some(0) => Ok(None),
        Some(d @ 1..=31) => Ok(Some(d)),
        Some(_) => Err("每月重置日必须在 1 到 31 之间".into()),
    }
}

/// Number of calendar days in `(year, month)`.
pub fn days_in_month(year: i32, month: u32) -> u8 {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let first_of_next = NaiveDate::from_ymd_opt(next_year, next_month, 1).expect("valid date");
    first_of_next.pred_opt().expect("valid prev date").day() as u8
}

fn clamped_date(year: i32, month: u32, day: u8) -> NaiveDate {
    let d = day.min(days_in_month(year, month)) as u32;
    NaiveDate::from_ymd_opt(year, month, d).expect("valid clamped date")
}

/// Start date of the billing cycle containing `today` for a monthly `reset_day` (`1..=31`).
pub fn current_cycle_start(today: NaiveDate, reset_day: u8) -> NaiveDate {
    let this_month = clamped_date(today.year(), today.month(), reset_day);
    if today >= this_month {
        this_month
    } else {
        let (prev_year, prev_month) = if today.month() == 1 {
            (today.year() - 1, 12)
        } else {
            (today.year(), today.month() - 1)
        };
        clamped_date(prev_year, prev_month, reset_day)
    }
}

/// Next upcoming billing reset date strictly after `today`.
pub fn next_reset_date(today: NaiveDate, reset_day: u8) -> NaiveDate {
    let this_month = clamped_date(today.year(), today.month(), reset_day);
    if today < this_month {
        this_month
    } else {
        let (next_year, next_month) = if today.month() == 12 {
            (today.year() + 1, 1)
        } else {
            (today.year(), today.month() + 1)
        };
        clamped_date(next_year, next_month, reset_day)
    }
}

/// Format bytes using 1024-based binary units matching frontend `formatBytes`.
pub fn format_bytes_human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", v, UNITS[i])
    }
}

impl NodeTrafficRecord {
    /// Bytes counted by panel heartbeats in the current cycle according to [`Self::direction`].
    pub fn tracked_period_bytes(&self) -> u64 {
        match self.direction {
            TrafficDirection::Both => self
                .period_upload_bytes
                .saturating_add(self.period_download_bytes),
            TrafficDirection::Upload => self.period_upload_bytes,
            TrafficDirection::Download => self.period_download_bytes,
            TrafficDirection::Max => self.period_upload_bytes.max(self.period_download_bytes),
        }
    }

    /// Effective used traffic in bytes (calibrated base + tracked period bytes).
    pub fn used_bytes(&self) -> u64 {
        self.base_bytes.saturating_add(self.tracked_period_bytes())
    }

    /// Usage percentage (`0.0..=inf`) when a quota is set (`total_bytes > 0`).
    pub fn usage_percent(&self) -> Option<f64> {
        if self.total_bytes == 0 {
            None
        } else {
            Some((self.used_bytes() as f64 / self.total_bytes as f64) * 100.0)
        }
    }

    /// High-level quota status for UI badges and progress bar styling.
    pub fn status(&self) -> &'static str {
        if self.total_bytes == 0 {
            return "unlimited";
        }
        let used = self.used_bytes();
        if used >= self.total_bytes {
            return "exhausted";
        }
        if self
            .warn_thresholds
            .iter()
            .any(|&pct| reached_threshold(used, self.total_bytes, pct))
        {
            return "warning";
        }
        "normal"
    }

    pub fn summary(&self, today_local: NaiveDate) -> NodeTrafficSummary {
        NodeTrafficSummary {
            total_bytes: self.total_bytes,
            used_bytes: self.used_bytes(),
            base_bytes: self.base_bytes,
            period_upload_bytes: self.period_upload_bytes,
            period_download_bytes: self.period_download_bytes,
            direction: self.direction,
            warn_thresholds: self.warn_thresholds.clone(),
            reset_day: self.reset_day,
            last_reset_at: self.last_reset_at.clone(),
            next_reset_date: self
                .reset_day
                .map(|d| next_reset_date(today_local, d).format("%Y-%m-%d").to_string()),
            usage_percent: self.usage_percent(),
            notified_thresholds: self.notified_thresholds.clone(),
            notified_exhausted: self.notified_exhausted,
            status: self.status(),
        }
    }

    /// Seed the OS NIC baseline from an existing `node_status:*` JSON blob when the admin
    /// configures a quota before the next heartbeat arrives. Does NOT add any usage.
    pub fn seed_baseline_from_status_json(&mut self, status_json: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(status_json) else {
            return;
        };
        if self.last_boot_upload_bytes.is_none() {
            self.last_boot_upload_bytes = v.get("boot_upload_bytes").and_then(|x| x.as_u64());
        }
        if self.last_boot_download_bytes.is_none() {
            self.last_boot_download_bytes = v.get("boot_download_bytes").and_then(|x| x.as_u64());
        }
        if self.last_network_interface.is_none() {
            self.last_network_interface = v
                .get("network_interface")
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
    }

    /// Fold one heartbeat's OS boot NIC counters into this record.
    ///
    /// - First observation seeds `last_boot_*` with zero delta so existing uptime traffic
    ///   isn't retroactively billed as new usage.
    /// - Switching `network_interface` re-baselines cleanly with zero delta.
    /// - When a counter drops below the previous sample (OS reboot / NIC reset), the new
    ///   value itself is counted as the delta since reboot.
    ///
    /// Returns `true` if any persisted field changed.
    pub fn apply_nic_sample(
        &mut self,
        upload: Option<u64>,
        download: Option<u64>,
        iface: Option<&str>,
    ) -> bool {
        if upload.is_none() && download.is_none() {
            return false;
        }
        let clean_iface = iface.map(str::trim).filter(|s| !s.is_empty());

        // If the reporting NIC changed (e.g. eth0 -> ens3), re-baseline without injecting
        // the new interface's pre-existing boot counter.
        if let (Some(prev), Some(cur)) = (self.last_network_interface.as_deref(), clean_iface) {
            if prev != cur {
                self.last_network_interface = Some(cur.to_string());
                if upload.is_some() {
                    self.last_boot_upload_bytes = upload;
                }
                if download.is_some() {
                    self.last_boot_download_bytes = download;
                }
                return true;
            }
        }

        let mut changed = false;
        if self.last_network_interface.is_none() {
            if let Some(cur) = clean_iface {
                self.last_network_interface = Some(cur.to_string());
                changed = true;
            }
        }

        if let Some(cur_up) = upload {
            match self.last_boot_upload_bytes {
                Some(prev_up) => {
                    let delta = if cur_up >= prev_up {
                        cur_up - prev_up
                    } else {
                        cur_up
                    };
                    if delta > 0 {
                        self.period_upload_bytes = self.period_upload_bytes.saturating_add(delta);
                        changed = true;
                    }
                    if cur_up != prev_up {
                        self.last_boot_upload_bytes = Some(cur_up);
                        changed = true;
                    }
                }
                None => {
                    self.last_boot_upload_bytes = Some(cur_up);
                    changed = true;
                }
            }
        }

        if let Some(cur_down) = download {
            match self.last_boot_download_bytes {
                Some(prev_down) => {
                    let delta = if cur_down >= prev_down {
                        cur_down - prev_down
                    } else {
                        cur_down
                    };
                    if delta > 0 {
                        self.period_download_bytes =
                            self.period_download_bytes.saturating_add(delta);
                        changed = true;
                    }
                    if cur_down != prev_down {
                        self.last_boot_download_bytes = Some(cur_down);
                        changed = true;
                    }
                }
                None => {
                    self.last_boot_download_bytes = Some(cur_down);
                    changed = true;
                }
            }
        }

        changed
    }

    /// Reset current billing cycle usage and alert state while keeping quota settings
    /// and the NIC boot-counter baseline intact.
    pub fn reset_usage(&mut self, now_utc: DateTime<Utc>) {
        self.base_bytes = 0;
        self.period_upload_bytes = 0;
        self.period_download_bytes = 0;
        self.notified_thresholds.clear();
        self.notified_exhausted = false;
        self.last_reset_at = Some(now_utc.to_rfc3339());
    }

    /// Apply monthly auto-reset if `reset_day` is configured and the last reset fell
    /// before the start of the current local billing cycle.
    pub fn maybe_apply_monthly_reset_at(
        &mut self,
        now_utc: DateTime<Utc>,
        today_local: NaiveDate,
        tz_offset: FixedOffset,
    ) -> bool {
        let Some(reset_day) = self.reset_day else {
            return false;
        };
        let cycle_start = current_cycle_start(today_local, reset_day);
        let last_reset_date = self.last_reset_at.as_deref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&tz_offset).date_naive())
        });
        match last_reset_date {
            Some(last_date) if last_date < cycle_start => {
                self.reset_usage(now_utc);
                true
            }
            Some(_) => false,
            None => {
                // Missing anchor timestamp on an already-configured reset_day: anchor it
                // to now without wiping existing usage unexpectedly.
                self.last_reset_at = Some(now_utc.to_rfc3339());
                true
            }
        }
    }

    /// Reconcile persisted notification markers after an admin edits quota / used traffic /
    /// billing direction / thresholds. Clears any notified flag that is no longer crossed
    /// so future growth past that level alerts again cleanly.
    pub fn reconcile_notified_state(&mut self) {
        if self.total_bytes == 0 {
            self.notified_thresholds.clear();
            self.notified_exhausted = false;
            return;
        }
        let used = self.used_bytes();
        let total = self.total_bytes;
        let active_thresholds = self.warn_thresholds.clone();
        self.notified_thresholds
            .retain(|t| active_thresholds.contains(t) && reached_threshold(used, total, *t));
        if used < total {
            self.notified_exhausted = false;
        }
    }

    /// Decide whether the current usage triggers a new alert.
    ///
    /// - Exhaustion (`used >= total`) takes precedence over warning thresholds; if a burst
    ///   jumps directly from 50% to 105%, only one Exhausted alert is emitted and all lower
    ///   warning thresholds are marked notified.
    /// - If multiple warning thresholds are crossed at once (e.g. 50% -> 92% with `[80, 90]`),
    ///   only one Threshold alert for the highest crossed threshold (90%) is emitted, and all
    ///   crossed thresholds are marked notified.
    pub fn evaluate_alert(&mut self, mark_notified: bool) -> Option<TrafficAlert> {
        if self.total_bytes == 0 {
            return None;
        }
        let used = self.used_bytes();
        let total = self.total_bytes;

        if used >= total {
            if self.notified_exhausted {
                return None;
            }
            if mark_notified {
                self.notified_exhausted = true;
                for &t in &self.warn_thresholds {
                    if !self.notified_thresholds.contains(&t) {
                        self.notified_thresholds.push(t);
                    }
                }
                self.notified_thresholds.sort_unstable();
            }
            return Some(TrafficAlert::Exhausted {
                used_bytes: used,
                total_bytes: total,
            });
        }

        let crossed: Vec<u8> = self
            .warn_thresholds
            .iter()
            .copied()
            .filter(|&t| reached_threshold(used, total, t) && !self.notified_thresholds.contains(&t))
            .collect();

        if crossed.is_empty() {
            return None;
        }
        let highest = *crossed.iter().max().expect("non-empty crossed");
        if mark_notified {
            self.notified_thresholds.extend(crossed);
            self.notified_thresholds.sort_unstable();
            self.notified_thresholds.dedup();
        }
        Some(TrafficAlert::Threshold {
            threshold_pct: highest,
            used_bytes: used,
            total_bytes: total,
        })
    }
}

pub async fn load_record<R: KvsRepository + ?Sized>(
    db: &R,
    node_key: &str,
) -> Result<Option<NodeTrafficRecord>, DbError> {
    let raw = db.get(&traffic_key(node_key)).await?;
    Ok(raw.and_then(|s| serde_json::from_str::<NodeTrafficRecord>(&s).ok()))
}

pub async fn save_record<R: KvsRepository + ?Sized>(
    db: &R,
    node_key: &str,
    record: &NodeTrafficRecord,
) -> Result<(), DbError> {
    let raw = serde_json::to_string(record)
        .map_err(|e| DbError::Other(sqlx::Error::Protocol(e.to_string())))?;
    db.set(&traffic_key(node_key), &raw).await
}

pub async fn delete_record<R: KvsRepository + ?Sized>(
    db: &R,
    node_key: &str,
) -> Result<u64, DbError> {
    db.delete(&traffic_key(node_key)).await
}

/// Load all persisted node traffic records keyed by `node_key` (`{group_id}:{node_id}`).
pub async fn all_records<R: KvsRepository + ?Sized>(
    db: &R,
) -> Result<HashMap<String, NodeTrafficRecord>, DbError> {
    Ok(db
        .scan_prefix(NODE_TRAFFIC_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(k, v)| {
            let node_key = k.strip_prefix(NODE_TRAFFIC_PREFIX)?.to_string();
            let rec = serde_json::from_str::<NodeTrafficRecord>(&v).ok()?;
            Some((node_key, rec))
        })
        .collect())
}

/// Delete every `node_traffic:*` row belonging to `group_id` (both per-node and legacy keys).
pub async fn remove_group_records<R: KvsRepository + ?Sized>(
    db: &R,
    group_id: i64,
) -> Result<u64, DbError> {
    let legacy_key = format!("{NODE_TRAFFIC_PREFIX}{group_id}");
    let per_node_prefix = format!("{legacy_key}:");
    let mut removed = 0;
    for (key, _) in db.scan_prefix(&legacy_key).await? {
        if key == legacy_key || key.starts_with(&per_node_prefix) {
            removed += db.delete(&key).await?;
        }
    }
    Ok(removed)
}

/// Context passed to alert formatting and async delivery.
#[derive(Debug, Clone)]
pub struct TrafficAlertContext {
    pub group_name: String,
    pub node_key: String,
    pub status_json: String,
    pub direction: TrafficDirection,
    pub reset_day: Option<u8>,
    pub next_reset: Option<String>,
    pub alert: TrafficAlert,
}

/// Format alert `(event_type, email_subject, message_body)` for Telegram / email delivery.
pub fn format_alert_message(
    ctx: &TrafficAlertContext,
    label: Option<&str>,
) -> (&'static str, &'static str, String) {
    let v: serde_json::Value = serde_json::from_str(&ctx.status_json).unwrap_or_default();
    let ip = v
        .get("public_ipv4")
        .or_else(|| v.get("public_ip"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let node_name = format!(
        "{} (IP: {ip})",
        crate::service::node_labels::display_name(label, &ctx.node_key)
    );
    let reset_line = match (ctx.reset_day, ctx.next_reset.as_deref()) {
        (Some(day), Some(date)) => format!("重置周期：每月 {day} 日（下次重置 {date}）"),
        (Some(day), None) => format!("重置周期：每月 {day} 日"),
        (None, _) => "重置周期：手动重置".to_string(),
    };

    match ctx.alert {
        TrafficAlert::Threshold {
            threshold_pct,
            used_bytes,
            total_bytes,
        } => {
            let pct = if total_bytes > 0 {
                (used_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            let remaining = total_bytes.saturating_sub(used_bytes);
            let body = format!(
                "⚠️ 中转机流量告警（已达 {threshold_pct}% 阈值）\n\n\
                 节点：{node_name}\n\
                 分组：{}\n\
                 计费方式：{}\n\
                 已用 / 总额：{} / {}（{pct:.1}%）\n\
                 剩余流量：{}\n\
                 {reset_line}",
                ctx.group_name,
                ctx.direction.label_zh(),
                format_bytes_human(used_bytes),
                format_bytes_human(total_bytes),
                format_bytes_human(remaining),
            );
            ("traffic_threshold", "RelayPanel 中转机流量阈值告警", body)
        }
        TrafficAlert::Exhausted {
            used_bytes,
            total_bytes,
        } => {
            let pct = if total_bytes > 0 {
                (used_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                100.0
            };
            let body = format!(
                "🚨 中转机流量已用尽（已达 100%）\n\n\
                 节点：{node_name}\n\
                 分组：{}\n\
                 计费方式：{}\n\
                 已用 / 总额：{} / {}（{pct:.1}%）\n\
                 剩余流量：0 B\n\
                 {reset_line}\n\n\
                 提示：当前仅发送通知，节点转发规则未自动暂停，请及时关注账单或调整线路。",
                ctx.group_name,
                ctx.direction.label_zh(),
                format_bytes_human(used_bytes),
                format_bytes_human(total_bytes),
            );
            ("traffic_exhausted", "RelayPanel 中转机流量已用尽告警", body)
        }
    }
}

/// Dispatch a traffic quota alert asynchronously on a detached task so neither
/// `report_status` nor admin API calls ever block on external Telegram/SMTP latency.
pub fn spawn_alert_delivery(state: AppState, cfg: NotifyConfig, ctx: TrafficAlertContext) {
    tokio::spawn(async move {
        let label = crate::service::node_labels::all_labels(state.db.as_ref())
            .await
            .ok()
            .and_then(|m| m.get(&ctx.node_key).cloned());
        let (event, subject, body) = format_alert_message(&ctx, label.as_deref());
        let report = notify::send_all(&cfg, subject, &body).await;
        notify::record_report(state.db.as_ref(), event, Some(&ctx.node_key), &report).await;
        if let Some(Err(e)) = &report.telegram {
            tracing::error!("node-traffic: {} {event} telegram failed: {e}", ctx.node_key);
        }
        if let Some(Err(e)) = &report.email {
            tracing::error!("node-traffic: {} {event} email failed: {e}", ctx.node_key);
        }
        if matches!(report.telegram, Some(Ok(()))) || matches!(report.email, Some(Ok(()))) {
            tracing::info!("node-traffic: {} {event} alert sent", ctx.node_key);
        }
    });
}

/// Called from `POST /api/v1/node/report_status` after persisting the status snapshot.
/// Best-effort: database errors are logged and never fail the status report.
#[allow(clippy::too_many_arguments)]
pub async fn on_status_report(
    state: &AppState,
    group_name: &str,
    node_key: &str,
    boot_upload_bytes: Option<u64>,
    boot_download_bytes: Option<u64>,
    network_interface: Option<&str>,
    status_json: &str,
) {
    let now_local = Local::now();
    let now_utc = now_local.with_timezone(&Utc);
    let today_local = now_local.date_naive();
    let tz_offset = *now_local.offset();

    let _guard = state.node_traffic_locks.lock(node_key).await;

    let mut record = match load_record(state.db.as_ref(), node_key).await {
        Ok(Some(r)) => r,
        Ok(None) => NodeTrafficRecord::default(),
        Err(e) => {
            tracing::warn!("node-traffic: load {node_key} failed: {e}");
            return;
        }
    };

    let reset_applied = record.maybe_apply_monthly_reset_at(now_utc, today_local, tz_offset);
    let sample_changed =
        record.apply_nic_sample(boot_upload_bytes, boot_download_bytes, network_interface);

    let mut pending_delivery: Option<(NotifyConfig, TrafficAlert, Option<String>)> = None;
    let mut alert_marked = false;
    if record.total_bytes > 0 {
        let raw_cfg = state.db.get(notify::NOTIFY_CONFIG_KEY).await.ok().flatten();
        let cfg = NotifyConfig::from_json(raw_cfg.as_deref());
        if cfg.any_channel_enabled() && cfg.notify_traffic {
            if let Some(alert) = record.evaluate_alert(true) {
                alert_marked = true;
                let next_reset = record
                    .reset_day
                    .map(|d| next_reset_date(today_local, d).format("%Y-%m-%d").to_string());
                pending_delivery = Some((cfg, alert, next_reset));
            }
        }
    }

    if reset_applied || sample_changed || alert_marked {
        if let Err(e) = save_record(state.db.as_ref(), node_key, &record).await {
            tracing::warn!("node-traffic: save {node_key} failed: {e}");
            return;
        }
    }

    let direction = record.direction;
    let reset_day = record.reset_day;
    drop(_guard);

    if let Some((cfg, alert, next_reset)) = pending_delivery {
        spawn_alert_delivery(
            state.clone(),
            cfg,
            TrafficAlertContext {
                group_name: group_name.to_string(),
                node_key: node_key.to_string(),
                status_json: status_json.to_string(),
                direction,
                reset_day,
                next_reset,
                alert,
            },
        );
    }
}

/// Periodic sweep invoked by `node_watch::tick` so even offline or idle nodes reset
/// cleanly on their configured monthly billing day.
pub async fn run_scheduled_resets(state: &AppState) {
    let rows = match state.db.scan_prefix(NODE_TRAFFIC_PREFIX).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("node-traffic: scanning records for monthly reset failed: {e}");
            return;
        }
    };
    let now_local = Local::now();
    let now_utc = now_local.with_timezone(&Utc);
    let today_local = now_local.date_naive();
    let tz_offset = *now_local.offset();

    for (key, raw) in rows {
        let Some(node_key) = key.strip_prefix(NODE_TRAFFIC_PREFIX) else {
            continue;
        };
        let Ok(preview) = serde_json::from_str::<NodeTrafficRecord>(&raw) else {
            continue;
        };
        if preview.reset_day.is_none() {
            continue;
        }
        // Quick unsynchronized check before acquiring the per-node lock.
        let mut check = preview;
        if !check.maybe_apply_monthly_reset_at(now_utc, today_local, tz_offset) {
            continue;
        }

        let _guard = state.node_traffic_locks.lock(node_key).await;
        if let Ok(Some(mut record)) = load_record(state.db.as_ref(), node_key).await {
            if record.maybe_apply_monthly_reset_at(now_utc, today_local, tz_offset) {
                if let Err(e) = save_record(state.db.as_ref(), node_key, &record).await {
                    tracing::warn!("node-traffic: monthly reset save {node_key} failed: {e}");
                } else {
                    tracing::info!("node-traffic: monthly auto-reset applied for {node_key}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const GB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn first_sample_seeds_baseline_without_billing_prior_boot_traffic() {
        let mut r = NodeTrafficRecord::default();
        assert!(r.apply_nic_sample(Some(500 * GB), Some(400 * GB), Some("eth0")));
        assert_eq!(r.used_bytes(), 0);
        assert_eq!(r.last_boot_upload_bytes, Some(500 * GB));
        assert_eq!(r.last_boot_download_bytes, Some(400 * GB));

        // Second heartbeat: +2 GB up, +3 GB down -> 5 GB total (Both)
        assert!(r.apply_nic_sample(Some(502 * GB), Some(403 * GB), Some("eth0")));
        assert_eq!(r.period_upload_bytes, 2 * GB);
        assert_eq!(r.period_download_bytes, 3 * GB);
        assert_eq!(r.used_bytes(), 5 * GB);
    }

    #[test]
    fn reboot_counter_drop_counts_post_reboot_bytes_as_delta() {
        let mut r = NodeTrafficRecord::default();
        r.apply_nic_sample(Some(100 * GB), Some(200 * GB), Some("eth0"));
        r.apply_nic_sample(Some(105 * GB), Some(210 * GB), Some("eth0"));
        assert_eq!(r.used_bytes(), 15 * GB);

        // OS rebooted: NIC counters reset to small values (1 GB up, 2 GB down)
        r.apply_nic_sample(Some(GB), Some(2 * GB), Some("eth0"));
        assert_eq!(r.period_upload_bytes, 6 * GB);
        assert_eq!(r.period_download_bytes, 12 * GB);
        assert_eq!(r.used_bytes(), 18 * GB);
    }

    #[test]
    fn nic_interface_change_rebaselines_without_fake_jump() {
        let mut r = NodeTrafficRecord::default();
        r.apply_nic_sample(Some(10 * GB), Some(20 * GB), Some("eth0"));
        r.apply_nic_sample(Some(12 * GB), Some(23 * GB), Some("eth0"));
        assert_eq!(r.used_bytes(), 5 * GB);

        // Switched to ens3 which already has 500 GB since boot -> must not add 500 GB
        r.apply_nic_sample(Some(500 * GB), Some(600 * GB), Some("ens3"));
        assert_eq!(r.used_bytes(), 5 * GB);
        assert_eq!(r.last_network_interface.as_deref(), Some("ens3"));

        // Subsequent traffic on ens3 accumulates normally
        r.apply_nic_sample(Some(501 * GB), Some(602 * GB), Some("ens3"));
        assert_eq!(r.used_bytes(), 8 * GB);
    }

    #[test]
    fn billing_directions_and_manual_base_calibration() {
        let mut r = NodeTrafficRecord {
            base_bytes: 100 * GB,
            period_upload_bytes: 10 * GB,
            period_download_bytes: 25 * GB,
            ..Default::default()
        };

        r.direction = TrafficDirection::Both;
        assert_eq!(r.used_bytes(), 135 * GB);

        r.direction = TrafficDirection::Upload;
        assert_eq!(r.used_bytes(), 110 * GB);

        r.direction = TrafficDirection::Download;
        assert_eq!(r.used_bytes(), 125 * GB);

        r.direction = TrafficDirection::Max;
        assert_eq!(r.used_bytes(), 125 * GB);
    }

    #[test]
    fn threshold_normalization_sorts_dedups_drops_100_and_rejects_invalid() {
        assert_eq!(normalize_thresholds(&[90, 80, 90, 100]), Ok(vec![80, 90]));
        assert_eq!(normalize_thresholds(&[]), Ok(vec![]));
        assert!(normalize_thresholds(&[0]).is_err());
        assert!(normalize_thresholds(&[101]).is_err());
        assert!(normalize_thresholds(&[10, 20, 30, 40, 50, 60]).is_err());
    }

    #[test]
    fn multi_threshold_and_exhausted_state_machine_never_duplicates() {
        let mut r = NodeTrafficRecord {
            total_bytes: 1000 * GB,
            warn_thresholds: vec![80, 90],
            ..Default::default()
        };

        // 79% -> silent
        r.base_bytes = 790 * GB;
        assert_eq!(r.evaluate_alert(true), None);

        // 80% -> fires 80% once
        r.base_bytes = 800 * GB;
        assert_eq!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Threshold {
                threshold_pct: 80,
                used_bytes: 800 * GB,
                total_bytes: 1000 * GB,
            })
        );
        // 85% -> stays silent
        r.base_bytes = 850 * GB;
        assert_eq!(r.evaluate_alert(true), None);

        // 90% -> fires 90% once
        r.base_bytes = 900 * GB;
        assert_eq!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Threshold {
                threshold_pct: 90,
                used_bytes: 900 * GB,
                total_bytes: 1000 * GB,
            })
        );
        assert_eq!(r.evaluate_alert(true), None);

        // 100% -> fires Exhausted once
        r.base_bytes = 1000 * GB;
        assert_eq!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Exhausted {
                used_bytes: 1000 * GB,
                total_bytes: 1000 * GB,
            })
        );
        // 105% -> stays silent
        r.base_bytes = 1050 * GB;
        assert_eq!(r.evaluate_alert(true), None);
    }

    #[test]
    fn burst_jump_emits_only_single_highest_alert() {
        // Jump 0% -> 95% with [80, 90] -> only 90% fires, both 80 & 90 marked
        let mut r = NodeTrafficRecord {
            total_bytes: 1000 * GB,
            base_bytes: 950 * GB,
            warn_thresholds: vec![80, 90],
            ..Default::default()
        };
        assert_eq!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Threshold {
                threshold_pct: 90,
                used_bytes: 950 * GB,
                total_bytes: 1000 * GB,
            })
        );
        assert_eq!(r.notified_thresholds, vec![80, 90]);
        assert_eq!(r.evaluate_alert(true), None);

        // Jump 0% -> 110% -> only Exhausted fires, all warn thresholds marked
        let mut r2 = NodeTrafficRecord {
            total_bytes: 1000 * GB,
            base_bytes: 1100 * GB,
            warn_thresholds: vec![80, 90],
            ..Default::default()
        };
        assert_eq!(
            r2.evaluate_alert(true),
            Some(TrafficAlert::Exhausted {
                used_bytes: 1100 * GB,
                total_bytes: 1000 * GB,
            })
        );
        assert!(r2.notified_exhausted);
        assert_eq!(r2.notified_thresholds, vec![80, 90]);
        assert_eq!(r2.evaluate_alert(true), None);
    }

    #[test]
    fn increasing_quota_reconciles_notified_flags_so_future_crossings_re_alert() {
        let mut r = NodeTrafficRecord {
            total_bytes: 1000 * GB,
            base_bytes: 1050 * GB,
            warn_thresholds: vec![80, 90],
            ..Default::default()
        };
        assert!(matches!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Exhausted { .. })
        ));

        // Admin doubles quota to 2000 GB -> usage drops to 52.5%
        r.total_bytes = 2000 * GB;
        r.reconcile_notified_state();
        assert!(!r.notified_exhausted);
        assert!(r.notified_thresholds.is_empty());

        // Later grows to 1600 GB (80%) -> fires 80% again
        r.base_bytes = 1600 * GB;
        assert_eq!(
            r.evaluate_alert(true),
            Some(TrafficAlert::Threshold {
                threshold_pct: 80,
                used_bytes: 1600 * GB,
                total_bytes: 2000 * GB,
            })
        );
    }

    #[test]
    fn monthly_reset_handles_billing_day_and_short_month_clamping() {
        let tz = FixedOffset::east_opt(8 * 3600).unwrap();

        // Configured on 2026-01-31 with reset_day = 31 and 400 GB used
        let jan31 = tz.with_ymd_and_hms(2026, 1, 31, 12, 0, 0).unwrap();
        let mut r = NodeTrafficRecord {
            total_bytes: 1000 * GB,
            base_bytes: 400 * GB,
            reset_day: Some(31),
            last_reset_at: Some(jan31.with_timezone(&Utc).to_rfc3339()),
            notified_thresholds: vec![80],
            ..Default::default()
        };

        // Same day -> must NOT reset
        assert!(!r.maybe_apply_monthly_reset_at(
            jan31.with_timezone(&Utc),
            jan31.date_naive(),
            tz
        ));
        assert_eq!(r.used_bytes(), 400 * GB);

        // Feb 27 (non-leap 2026) -> cycle start is still Jan 31 -> must NOT reset
        let feb27 = tz.with_ymd_and_hms(2026, 2, 27, 23, 0, 0).unwrap();
        assert!(!r.maybe_apply_monthly_reset_at(
            feb27.with_timezone(&Utc),
            feb27.date_naive(),
            tz
        ));
        assert_eq!(r.used_bytes(), 400 * GB);

        // Feb 28 (clamped from 31) -> resets!
        let feb28 = tz.with_ymd_and_hms(2026, 2, 28, 0, 5, 0).unwrap();
        assert!(r.maybe_apply_monthly_reset_at(
            feb28.with_timezone(&Utc),
            feb28.date_naive(),
            tz
        ));
        assert_eq!(r.used_bytes(), 0);
        assert!(r.notified_thresholds.is_empty());

        // Later on Feb 28 -> must NOT double-reset
        r.period_upload_bytes = 5 * GB;
        let feb28_late = tz.with_ymd_and_hms(2026, 2, 28, 18, 0, 0).unwrap();
        assert!(!r.maybe_apply_monthly_reset_at(
            feb28_late.with_timezone(&Utc),
            feb28_late.date_naive(),
            tz
        ));
        assert_eq!(r.used_bytes(), 5 * GB);

        // Next reset date after Feb 28 with reset_day=31 is Mar 31
        assert_eq!(
            next_reset_date(feb28.date_naive(), 31),
            NaiveDate::from_ymd_opt(2026, 3, 31).unwrap()
        );
    }

    #[test]
    fn format_bytes_matches_binary_units() {
        assert_eq!(format_bytes_human(0), "0 B");
        assert_eq!(format_bytes_human(512), "512 B");
        assert_eq!(format_bytes_human(1024), "1.00 KB");
        assert_eq!(format_bytes_human(GB), "1.00 GB");
        assert_eq!(format_bytes_human(1024 * GB), "1.00 TB");
    }

    #[test]
    fn alert_message_formats_threshold_and_exhausted_cleanly() {
        let status = r#"{"public_ipv4":"1.2.3.4"}"#;
        let (ev, subj, body) = format_alert_message(
            &TrafficAlertContext {
                group_name: "HK-Entry".into(),
                node_key: "1:n1".into(),
                status_json: status.into(),
                direction: TrafficDirection::Both,
                reset_day: Some(1),
                next_reset: Some("2026-12-01".into()),
                alert: TrafficAlert::Threshold {
                    threshold_pct: 80,
                    used_bytes: 820 * GB,
                    total_bytes: 1000 * GB,
                },
            },
            Some("香港 HK-1"),
        );
        assert_eq!(ev, "traffic_threshold");
        assert!(subj.contains("阈值"));
        assert!(body.contains("香港 HK-1 (IP: 1.2.3.4)"));
        assert!(body.contains("80%"));
        assert!(body.contains("820.00 GB / 1000.00 GB"));
        assert!(body.contains("2026-12-01"));

        let (ev2, subj2, body2) = format_alert_message(
            &TrafficAlertContext {
                group_name: "HK-Entry".into(),
                node_key: "1:n1".into(),
                status_json: status.into(),
                direction: TrafficDirection::Upload,
                reset_day: None,
                next_reset: None,
                alert: TrafficAlert::Exhausted {
                    used_bytes: 1005 * GB,
                    total_bytes: 1000 * GB,
                },
            },
            None,
        );
        assert_eq!(ev2, "traffic_exhausted");
        assert!(subj2.contains("用尽"));
        assert!(body2.contains("1:n1 (IP: 1.2.3.4)"));
        assert!(body2.contains("仅出站"));
        assert!(body2.contains("手动重置"));
    }
}
