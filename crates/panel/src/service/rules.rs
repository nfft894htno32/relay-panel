//! Rule + shared rule/group validation service.

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope, RuleUpdate};
use relay_shared::protocol::{
    CreateRuleRequest, GroupType, Protocol, ProxyProtocolVersion, RuleTargetRequest,
    UpdateRuleRequest,
};

#[allow(dead_code)]
pub fn validate_forward_mode(mode: &str) -> bool {
    matches!(mode, "group" | "direct")
}

/// Map Protocol enum to stable DB string.
pub fn protocol_to_str(p: &Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::TcpUdp => "tcp_udp",
    }
}

pub fn is_plausible_target_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.contains("://") || h.contains('/') || h.chars().any(char::is_whitespace) {
        return false;
    }
    h.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

fn is_valid_domain_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Validate and normalize an optional SNI domain (exact hostname or `*.example.com`).
/// Returns `Ok(None)` when `raw` is `None` or empty after trimming.
pub fn normalize_sni(raw: Option<&str>, protocol: &str) -> Result<Option<String>, String> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let trimmed = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if protocol != "tcp" {
        return Err("SNI 分流域名仅支持 TCP 协议规则".to_string());
    }
    if trimmed.len() > 253 {
        return Err("SNI 域名长度不能超过 253 个字符".to_string());
    }

    let domain_part = if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.is_empty() || !rest.contains('.') {
            return Err("通配符 SNI 域名格式无效（示例：*.example.com）".to_string());
        }
        rest
    } else {
        if trimmed.contains('*') {
            return Err("通配符 SNI 仅支持最左侧 *.example.com 形式".to_string());
        }
        trimmed.as_str()
    };

    if domain_part.parse::<std::net::IpAddr>().is_ok() {
        return Err("SNI 必须是域名，不能填写纯 IP 地址".to_string());
    }

    let labels: Vec<&str> = domain_part.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|l| is_valid_domain_label(l)) {
        return Err(format!("SNI 域名格式无效: {trimmed}"));
    }

    Ok(Some(trimmed))
}

pub fn normalize_rule_targets(
    targets: Option<Vec<RuleTargetRequest>>,
    legacy_host: &str,
    legacy_port: u16,
) -> Result<Vec<RuleTargetRequest>, &'static str> {
    let mut out = targets.unwrap_or_else(|| {
        vec![RuleTargetRequest {
            host: legacy_host.to_string(),
            port: legacy_port,
            enabled: true,
        }]
    });
    if out.is_empty() {
        return Err("At least one target is required");
    }
    if out.len() > 32 {
        return Err("A rule can have at most 32 targets");
    }
    let mut enabled = 0usize;
    for target in &mut out {
        target.host = target.host.trim().to_string();
        if !is_plausible_target_host(&target.host) {
            return Err("Target host must be an IP address or domain without scheme/path/spaces");
        }
        if target.port == 0 {
            return Err("Target port must be between 1 and 65535");
        }
        if target.enabled {
            enabled += 1;
        }
    }
    if enabled == 0 {
        return Err("At least one target must be enabled");
    }
    Ok(out)
}

/// Map GroupType enum to stable DB string.
pub fn group_type_to_str(gt: &GroupType) -> &'static str {
    match gt {
        GroupType::In => "in",
        GroupType::Out => "out",
        GroupType::Monitor => "monitor",
    }
}

const DEFAULT_AUTO_PORT_LO: u16 = 10000;
const DEFAULT_AUTO_PORT_HI: u16 = 65535;

pub fn resolve_auto_port_range(raw: &str) -> (u16, u16) {
    const DEFAULT: (u16, u16) = (DEFAULT_AUTO_PORT_LO, DEFAULT_AUTO_PORT_HI);
    let s = raw.trim();
    if s.is_empty() || s == "1-65535" {
        return DEFAULT;
    }
    let Some((a, b)) = s.split_once('-') else {
        return DEFAULT;
    };
    let (Ok(start), Ok(end)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) else {
        return DEFAULT;
    };
    if start < 1 || end > 65535 || start > end {
        return DEFAULT;
    }
    (start as u16, end as u16)
}

fn pseudo_random_offset(span: u32) -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % span
}

pub async fn auto_assign_port(
    db: &dyn Repository,
    device_group_in: i64,
    protocol: &str,
) -> Result<u16, String> {
    let needs_tcp = matches!(protocol, "tcp" | "tcp_udp" | "both");
    let needs_udp = matches!(protocol, "udp" | "tcp_udp" | "both");

    let range_raw = db
        .group_port_range(device_group_in)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let (lo, hi) = resolve_auto_port_range(&range_raw);

    let group_ports: Vec<(i32, String)> = db
        .list_group_port_protocols(device_group_in)
        .await
        .map_err(|e| e.to_string())?;

    let used: std::collections::HashSet<u16> = group_ports
        .into_iter()
        .filter_map(|(p, proto)| {
            let occupies_tcp = matches!(proto.as_str(), "tcp" | "tcp_udp" | "both");
            let occupies_udp = matches!(proto.as_str(), "udp" | "tcp_udp" | "both");
            let conflicts = (needs_tcp && occupies_tcp) || (needs_udp && occupies_udp);
            if conflicts {
                u16::try_from(p).ok()
            } else {
                None
            }
        })
        .collect();

    let span = (hi as u32) - (lo as u32) + 1;
    let start_offset = pseudo_random_offset(span);
    for i in 0..span {
        let candidate = (lo as u32 + (start_offset + i) % span) as u16;
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!(
        "设备组端口范围 {}-{} 已全部占用,请扩大该组端口范围或删除已有规则后重试",
        lo, hi
    ))
}

#[derive(Debug)]
pub enum CreateRuleError {
    BadRequest(String),
    PortConflict(u16),
    Database(DbError),
}

#[derive(Debug)]
pub enum UpdateRuleError {
    BadRequest(String),
    NotFound,
    PortConflict,
    Database(DbError),
}

async fn validate_inbound_group(
    db: &dyn Repository,
    gid: i64,
    context: &str,
) -> Result<(), CreateRuleError> {
    match GroupRepository::find_by_id(db, gid, &ResourceScope::All).await {
        Ok(Some(g)) => {
            if g.group_type != "in" {
                return Err(CreateRuleError::BadRequest(
                    "device_group_in not found".into(),
                ));
            }
            Ok(())
        }
        Ok(None) => Err(CreateRuleError::BadRequest(
            "device_group_in not found".into(),
        )),
        Err(e) => {
            tracing::error!("{}: group_in find_by_id failed: {}", context, e);
            Err(CreateRuleError::Database(e))
        }
    }
}

pub async fn validate_proxy_protocol(
    db: &dyn Repository,
    protocol: &str,
    device_group_in: i64,
    send: ProxyProtocolVersion,
    accept: bool,
    trusted: &str,
    check_nodes: bool,
) -> Result<crate::db::repo::RuleProxyProtocol, CreateRuleError> {
    if send == ProxyProtocolVersion::Off && !accept {
        return Ok(crate::db::repo::RuleProxyProtocol::default());
    }
    if protocol == "udp" {
        return Err(CreateRuleError::BadRequest(
            "PROXY protocol 只用于 TCP，UDP 规则不能开启".into(),
        ));
    }
    let mut sources = Vec::new();
    if accept {
        for entry in trusted
            .split([',', '，', ' ', '\n', '\r', '\t'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !is_ip_or_cidr(entry) {
                return Err(CreateRuleError::BadRequest(format!(
                    "信任来源格式不对：{entry}（要写 IP 或 CIDR，如 203.0.113.7 或 10.0.0.0/8）"
                )));
            }
            sources.push(entry.to_string());
        }
    }
    if check_nodes {
        let prefix = format!("node_status:{}:", device_group_in);
        let rows = db
            .scan_prefix(&prefix)
            .await
            .map_err(CreateRuleError::Database)?;
        let now = chrono::Utc::now();
        let mut old = Vec::new();
        let mut any_offline = false;
        for (key, value) in rows {
            let v: serde_json::Value = serde_json::from_str(&value).unwrap_or_default();
            let version = v.get("node_version").and_then(|x| x.as_str());
            if !relay_shared::protocol::node_supports_proxy_protocol(version) {
                let label = v
                    .get("public_ipv4")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| key.trim_start_matches(&prefix).chars().take(8).collect());
                if crate::api::stats::status_is_online(&value, now) {
                    old.push(format!("{} ({})", label, version.unwrap_or("?")));
                } else {
                    any_offline = true;
                    old.push(format!("{} ({}, 离线)", label, version.unwrap_or("?")));
                }
            }
        }
        if !old.is_empty() {
            let hint = if any_offline {
                "；已经不用的离线节点可以在节点状态页删除"
            } else {
                ""
            };
            return Err(CreateRuleError::BadRequest(format!(
                "入口分组里有节点不支持 PROXY protocol，请先升级到 node-v1.2.9 或更新：{}{}",
                old.join(", "),
                hint
            )));
        }
    }
    Ok(crate::db::repo::RuleProxyProtocol {
        send: send.to_db_str().to_string(),
        accept,
        trusted: sources.join(","),
    })
}

fn is_ip_or_cidr(s: &str) -> bool {
    match s.split_once('/') {
        None => s.parse::<std::net::IpAddr>().is_ok(),
        Some((ip, bits)) => match (ip.parse::<std::net::IpAddr>(), bits.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(b)) => b <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(b)) => b <= 128,
            _ => false,
        },
    }
}

pub async fn create_rule(
    db: &dyn Repository,
    caller_user_id: i64,
    req: &CreateRuleRequest,
) -> Result<(), CreateRuleError> {
    if req.listen_port == Some(0) {
        return Err(CreateRuleError::BadRequest(
            "listen_port: must be between 1 and 65535".into(),
        ));
    }

    if req.forward_mode != "direct" {
        return Err(CreateRuleError::BadRequest(
            "forward_mode: only 'direct' is supported; group/chain forwarding is no longer available"
                .into(),
        ));
    }
    if req.device_group_out.is_some() {
        return Err(CreateRuleError::BadRequest(
            "device_group_out: outbound-group forwarding is no longer supported; remove device_group_out"
                .into(),
        ));
    }

    validate_inbound_group(db, req.device_group_in, "create_rule").await?;

    let protocol_str = protocol_to_str(&req.protocol);
    let sni = normalize_sni(req.sni.as_deref(), protocol_str)
        .map_err(CreateRuleError::BadRequest)?;

    let targets = normalize_rule_targets(req.targets.clone(), &req.target_addr, req.target_port)
        .map_err(|msg| CreateRuleError::BadRequest(msg.into()))?;
    let primary_target = &targets[0];

    let lb_db = req.load_balance_strategy.to_db_str();
    let up_mbps = req.upload_limit_mbps.unwrap_or(0).max(0);
    let down_mbps = req.download_limit_mbps.unwrap_or(0).max(0);
    let per_ip_up_mbps = req.per_ip_upload_limit_mbps.unwrap_or(0).max(0);
    let per_ip_down_mbps = req.per_ip_download_limit_mbps.unwrap_or(0).max(0);
    let max_connections = req.max_connections.unwrap_or(0).max(0);
    let auto_restart_minutes = req.auto_restart_minutes.unwrap_or(0).max(0);
    if auto_restart_minutes != 0
        && auto_restart_minutes < relay_shared::models::MIN_AUTO_RESTART_MINUTES
    {
        return Err(CreateRuleError::BadRequest(format!(
            "自动重启间隔最小 {} 分钟（0 = 关闭）",
            relay_shared::models::MIN_AUTO_RESTART_MINUTES
        )));
    }

    let proxy_protocol = validate_proxy_protocol(
        db,
        protocol_str,
        req.device_group_in,
        req.proxy_protocol_send,
        req.proxy_protocol_accept,
        &req.proxy_protocol_trusted,
        true,
    )
    .await?;

    let mut attempt = 0u32;
    let max_attempts = if req.listen_port.is_some() { 1 } else { 8 };
    let mut last_port: Option<u16> = req.listen_port;
    let result: Result<i64, DbError> = loop {
        let port = match last_port {
            Some(p) => p,
            None => match auto_assign_port(db, req.device_group_in, protocol_str).await {
                Ok(p) => p,
                Err(e) => return Err(CreateRuleError::BadRequest(e)),
            },
        };
        last_port = Some(port);

        match db
            .create_rule_full(
                &req.name,
                caller_user_id,
                port as i32,
                protocol_str,
                sni.as_deref(),
                req.device_group_in,
                req.device_group_out,
                &req.forward_mode,
                &primary_target.host,
                primary_target.port as i32,
                &targets,
                lb_db,
                up_mbps,
                down_mbps,
                per_ip_up_mbps,
                per_ip_down_mbps,
                max_connections,
                auto_restart_minutes,
                &proxy_protocol,
            )
            .await
        {
            Ok(id) => break Ok(id),
            Err(DbError::PortConflict | DbError::UniqueViolation)
                if req.listen_port.is_some() =>
            {
                break Err(DbError::PortConflict);
            }
            Err(DbError::PortConflict | DbError::UniqueViolation)
                if attempt + 1 < max_attempts =>
            {
                attempt += 1;
                last_port = None;
                continue;
            }
            Err(e) => break Err(e),
        }
    };

    match result {
        Ok(_) => Ok(()),
        Err(DbError::PortConflict | DbError::UniqueViolation) => {
            Err(CreateRuleError::PortConflict(last_port.unwrap_or(0)))
        }
        Err(e) => {
            tracing::error!("create_rule: create_rule_full failed: {}", e);
            Err(CreateRuleError::Database(e))
        }
    }
}

fn map_create_rule_validation_error(err: CreateRuleError) -> UpdateRuleError {
    match err {
        CreateRuleError::BadRequest(msg) => UpdateRuleError::BadRequest(msg),
        CreateRuleError::PortConflict(_) => UpdateRuleError::PortConflict,
        CreateRuleError::Database(e) => UpdateRuleError::Database(e),
    }
}

pub async fn update_rule(
    db: &dyn Repository,
    id: i64,
    scope: &ResourceScope,
    req: &UpdateRuleRequest,
) -> Result<(), UpdateRuleError> {
    if req.listen_port == Some(0) {
        return Err(UpdateRuleError::BadRequest(
            "listen_port: must be between 1 and 65535".into(),
        ));
    }

    if let Some(ref mode) = req.forward_mode {
        if mode != "direct" {
            return Err(UpdateRuleError::BadRequest(
                "forward_mode: only 'direct' is supported; group/chain forwarding is no longer available"
                    .into(),
            ));
        }
    }
    if req.device_group_out.is_some() {
        return Err(UpdateRuleError::BadRequest(
            "device_group_out: outbound-group forwarding is no longer supported; remove device_group_out"
                .into(),
        ));
    }

    let existing = match db.find_rule_by_id(id, scope).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(UpdateRuleError::NotFound),
        Err(e) => {
            tracing::error!("update_rule {}: find_rule_by_id failed: {}", id, e);
            return Err(UpdateRuleError::Database(e));
        }
    };

    if let Some(gid_in) = req.device_group_in {
        validate_inbound_group(db, gid_in, "update_rule")
            .await
            .map_err(map_create_rule_validation_error)?;
    }

    let effective_protocol = req
        .protocol
        .as_ref()
        .map(protocol_to_str)
        .unwrap_or(existing.protocol.as_str());

    let normalized_sni: Option<Option<String>> = match &req.sni {
        Some(opt) => {
            let norm = normalize_sni(opt.as_deref(), effective_protocol)
                .map_err(UpdateRuleError::BadRequest)?;
            Some(norm)
        }
        None => {
            if let Some(ref existing_sni) = existing.sni {
                if effective_protocol != "tcp" && !existing_sni.trim().is_empty() {
                    return Err(UpdateRuleError::BadRequest(
                        "SNI 分流域名仅支持 TCP 协议规则，请先清空 SNI 再切换协议".into(),
                    ));
                }
            }
            None
        }
    };

    let switching_to_direct =
        req.forward_mode.as_deref() == Some("direct") && req.device_group_out.is_none();
    let device_group_out_arg: Option<Option<i64>> = if switching_to_direct {
        Some(None)
    } else {
        req.device_group_out.map(Some)
    };

    let has_field = req.name.is_some()
        || req.listen_port.is_some()
        || req.protocol.is_some()
        || req.sni.is_some()
        || req.device_group_in.is_some()
        || req.device_group_out.is_some()
        || req.forward_mode.is_some()
        || req.target_addr.is_some()
        || req.target_port.is_some()
        || req.targets.is_some()
        || req.load_balance_strategy.is_some()
        || req.upload_limit_mbps.is_some()
        || req.download_limit_mbps.is_some()
        || req.per_ip_upload_limit_mbps.is_some()
        || req.per_ip_download_limit_mbps.is_some()
        || req.max_connections.is_some()
        || req.auto_restart_minutes.is_some()
        || req.paused.is_some()
        || req.proxy_protocol_send.is_some()
        || req.proxy_protocol_accept.is_some()
        || req.proxy_protocol_trusted.is_some();
    if !has_field {
        return Err(UpdateRuleError::BadRequest("No fields to update".into()));
    }

    let normalized_targets = if let Some(targets) = req.targets.clone() {
        let legacy_host = req.target_addr.as_deref().unwrap_or("127.0.0.1");
        let legacy_port = req.target_port.unwrap_or(1);
        Some(
            normalize_rule_targets(Some(targets), legacy_host, legacy_port)
                .map_err(|msg| UpdateRuleError::BadRequest(msg.into()))?,
        )
    } else {
        None
    };

    let max_connections = req.max_connections.map(|v| v.max(0));
    let auto_restart_minutes = req.auto_restart_minutes.map(|v| v.max(0));
    if let Some(minutes) = auto_restart_minutes {
        if minutes != 0 && minutes < relay_shared::models::MIN_AUTO_RESTART_MINUTES {
            return Err(UpdateRuleError::BadRequest(format!(
                "自动重启间隔最小 {} 分钟（0 = 关闭）",
                relay_shared::models::MIN_AUTO_RESTART_MINUTES
            )));
        }
    }

    let pp_touched = req.proxy_protocol_send.is_some()
        || req.proxy_protocol_accept.is_some()
        || req.proxy_protocol_trusted.is_some();
    let proxy_protocol = if pp_touched
        || req.protocol.is_some()
        || req.device_group_in.is_some()
    {
        let eff_group = req.device_group_in.unwrap_or(existing.device_group_in);
        let eff_send = req
            .proxy_protocol_send
            .unwrap_or_else(|| ProxyProtocolVersion::from_db_str(&existing.proxy_protocol_send));
        let eff_accept = req
            .proxy_protocol_accept
            .unwrap_or(existing.proxy_protocol_accept);
        let eff_trusted = req
            .proxy_protocol_trusted
            .as_deref()
            .unwrap_or(existing.proxy_protocol_trusted.as_str());
        let checked = validate_proxy_protocol(
            db,
            effective_protocol,
            eff_group,
            eff_send,
            eff_accept,
            eff_trusted,
            pp_touched || req.device_group_in.is_some(),
        )
        .await
        .map_err(map_create_rule_validation_error)?;
        Some(checked)
    } else {
        None
    };

    let sni_ref: Option<Option<&str>> = normalized_sni.as_ref().map(|o| o.as_deref());
    let update = RuleUpdate {
        name: req.name.as_deref(),
        listen_port: req.listen_port.map(|p| p as i32),
        protocol: req.protocol.as_ref().map(protocol_to_str),
        sni: sni_ref,
        device_group_in: req.device_group_in,
        device_group_out: device_group_out_arg,
        forward_mode: req.forward_mode.as_deref(),
        target_addr: req.target_addr.as_deref(),
        target_port: req.target_port.map(|p| p as i32),
        paused: req.paused,
        targets: normalized_targets.as_deref(),
        load_balance_strategy: req.load_balance_strategy.map(|s| s.to_db_str()),
        upload_limit_mbps: req.upload_limit_mbps.map(|v| v.max(0)),
        download_limit_mbps: req.download_limit_mbps.map(|v| v.max(0)),
        per_ip_upload_limit_mbps: req.per_ip_upload_limit_mbps.map(|v| v.max(0)),
        per_ip_download_limit_mbps: req.per_ip_download_limit_mbps.map(|v| v.max(0)),
        max_connections,
        auto_restart_minutes,
        proxy_protocol_send: proxy_protocol.as_ref().map(|p| p.send.as_str()),
        proxy_protocol_accept: proxy_protocol.as_ref().map(|p| p.accept),
        proxy_protocol_trusted: proxy_protocol.as_ref().map(|p| p.trusted.as_str()),
    };

    match db.update_rule_full(id, scope, &update).await {
        Ok(0) => Err(UpdateRuleError::NotFound),
        Ok(_) => Ok(()),
        Err(DbError::UniqueViolation | DbError::PortConflict) => Err(UpdateRuleError::PortConflict),
        Err(e) => {
            tracing::error!("update_rule {}: update_rule_full failed: {}", id, e);
            Err(UpdateRuleError::Database(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::RuleRepository;

    #[test]
    fn normalize_sni_validates_exact_and_wildcard_domains() {
        assert_eq!(normalize_sni(None, "tcp").unwrap(), None);
        assert_eq!(normalize_sni(Some("   "), "tcp").unwrap(), None);
        assert_eq!(
            normalize_sni(Some("Sub.Example.COM."), "tcp").unwrap(),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            normalize_sni(Some("*.Example.com"), "tcp").unwrap(),
            Some("*.example.com".to_string())
        );
        assert!(normalize_sni(Some("a.example.com"), "udp").is_err());
        assert!(normalize_sni(Some("1.2.3.4"), "tcp").is_err());
        assert!(normalize_sni(Some("*.com"), "tcp").is_err());
        assert!(normalize_sni(Some("a.*.example.com"), "tcp").is_err());
        assert!(normalize_sni(Some("-bad.example.com"), "tcp").is_err());
    }

    #[test]
    fn target_normalization_rules() {
        let out = normalize_rule_targets(None, "1.2.3.4", 80).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].host, "1.2.3.4");
        assert_eq!(out[0].port, 80);

        assert!(normalize_rule_targets(Some(vec![]), "1.2.3.4", 80).is_err());

        let many: Vec<RuleTargetRequest> = (0..33)
            .map(|_| RuleTargetRequest {
                host: "1.2.3.4".into(),
                port: 80,
                enabled: true,
            })
            .collect();
        assert!(normalize_rule_targets(Some(many), "x", 1).is_err());

        let disabled = vec![RuleTargetRequest {
            host: "1.2.3.4".into(),
            port: 80,
            enabled: false,
        }];
        assert!(normalize_rule_targets(Some(disabled), "x", 1).is_err());

        let bad = vec![RuleTargetRequest {
            host: "http://x".into(),
            port: 80,
            enabled: true,
        }];
        assert!(normalize_rule_targets(Some(bad), "x", 1).is_err());
    }

    #[test]
    fn resolve_auto_port_range_sentinel_and_default() {
        let def = (DEFAULT_AUTO_PORT_LO, DEFAULT_AUTO_PORT_HI);
        assert_eq!(resolve_auto_port_range("1-65535"), def);
        assert_eq!(resolve_auto_port_range(""), def);
        assert_eq!(resolve_auto_port_range("   "), def);
        assert_eq!(resolve_auto_port_range("garbage"), def);
        assert_eq!(resolve_auto_port_range("65000-100"), def);
    }

    #[test]
    fn resolve_auto_port_range_explicit_is_honored() {
        assert_eq!(resolve_auto_port_range("65000-65100"), (65000, 65100));
        assert_eq!(resolve_auto_port_range("5000-65535"), (5000, 65535));
        assert_eq!(resolve_auto_port_range("  5000 - 6000  "), (5000, 6000));
    }

    async fn test_db() -> (sqlx::SqlitePool, crate::db::sqlite_repo::SqliteRepository) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET admin = 1 WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'entry', 'in', 'unused', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let repo = crate::db::sqlite_repo::SqliteRepository::new(pool.clone());
        (pool, repo)
    }

    #[tokio::test]
    async fn multiple_sni_rules_can_share_port_443_while_duplicate_sni_conflicts() {
        let (_pool, repo) = test_db().await;
        let req1: CreateRuleRequest = serde_json::from_value(serde_json::json!({
            "name": "site-a",
            "listen_port": 443,
            "protocol": "tcp",
            "sni": "a.example.com",
            "device_group_in": 1,
            "target_addr": "10.0.0.1",
            "target_port": 443,
            "max_connections": 256,
            "auto_restart_minutes": 60
        }))
        .unwrap();
        create_rule(&repo, 1, &req1).await.unwrap();

        let req2: CreateRuleRequest = serde_json::from_value(serde_json::json!({
            "name": "site-b",
            "listen_port": 443,
            "protocol": "tcp",
            "sni": "*.b.example.com",
            "device_group_in": 1,
            "target_addr": "10.0.0.2",
            "target_port": 8443
        }))
        .unwrap();
        create_rule(&repo, 1, &req2).await.unwrap();

        // Duplicate SNI on same port must conflict
        let dup: CreateRuleRequest = serde_json::from_value(serde_json::json!({
            "name": "site-a-dup",
            "listen_port": 443,
            "protocol": "tcp",
            "sni": "A.Example.com",
            "device_group_in": 1,
            "target_addr": "10.0.0.3",
            "target_port": 443
        }))
        .unwrap();
        assert!(matches!(
            create_rule(&repo, 1, &dup).await,
            Err(CreateRuleError::PortConflict(443))
        ));

        // Raw TCP (no SNI) on same port 443 must also conflict with existing SNI rules
        let raw_tcp: CreateRuleRequest = serde_json::from_value(serde_json::json!({
            "name": "raw-443",
            "listen_port": 443,
            "protocol": "tcp",
            "device_group_in": 1,
            "target_addr": "10.0.0.4",
            "target_port": 443
        }))
        .unwrap();
        assert!(matches!(
            create_rule(&repo, 1, &raw_tcp).await,
            Err(CreateRuleError::PortConflict(443))
        ));

        // Verify max_connections and auto_restart_minutes persisted on creation
        let rules = repo.list_rules(&ResourceScope::All).await.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].sni.as_deref(), Some("a.example.com"));
        assert_eq!(rules[0].max_connections, 256);
        assert_eq!(rules[0].auto_restart_minutes, 60);
        assert_eq!(rules[1].sni.as_deref(), Some("*.b.example.com"));
    }
}
