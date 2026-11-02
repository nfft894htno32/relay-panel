//! Device group + rule deletion service.

use crate::db::error::DbError;
use crate::db::repo::ResourceScope;
use crate::db::Repository;
use crate::service::rules::group_type_to_str;
use relay_shared::models::DeviceGroup;
use relay_shared::protocol::GroupType;
use std::net::IpAddr;

pub const DEFAULT_SNI_FALLBACK_ADDR: &str = "127.0.0.1:10443";

#[derive(Debug)]
pub enum CreateGroupError {
    /// INSERT succeeded but the follow-up SELECT-by-token found nothing.
    FetchFailed,
    Database(DbError),
}

#[derive(Debug)]
pub enum UpdateGroupError {
    NotFound,
    NoFields,
    Database(DbError),
}

/// Validate and normalize `sni_fallback_addr` (`host:port`). Empty input falls
/// back to `DEFAULT_SNI_FALLBACK_ADDR`.
pub fn validate_sni_fallback_addr(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_SNI_FALLBACK_ADDR.to_string());
    }
    let Some((host, port_str)) = trimmed.rsplit_once(':') else {
        return Err("sni_fallback_addr 必须是 host:port 格式（例如 127.0.0.1:10443）");
    };
    if host.trim().is_empty() {
        return Err("sni_fallback_addr 主机地址不能为空");
    }
    let Ok(port) = port_str.parse::<u16>() else {
        return Err("sni_fallback_addr 端口必须是 1..=65535 的有效整数");
    };
    if port == 0 {
        return Err("sni_fallback_addr 端口必须在 1..=65535 之间");
    }
    Ok(trimmed.to_string())
}

/// Validate and normalize comma/whitespace-separated IP addresses or CIDR ranges
/// in `sni_loop_bypass_ips` (e.g. `203.0.113.10,198.51.100.0/24`).
pub fn validate_sni_loop_bypass_ips(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut normalized = Vec::new();
    for part in trimmed.split(|c: char| c == ',' || c == '，' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        match p.split_once('/') {
            None => {
                let ip: IpAddr = p
                    .parse()
                    .map_err(|_| format!("sni_loop_bypass_ips 包含无效 IP 或 CIDR: {p}"))?;
                normalized.push(ip.to_string());
            }
            Some((ip_part, prefix_part)) => {
                let ip: IpAddr = ip_part
                    .parse()
                    .map_err(|_| format!("sni_loop_bypass_ips 包含无效 IP 或 CIDR: {p}"))?;
                let bits: u8 = prefix_part
                    .parse()
                    .map_err(|_| format!("sni_loop_bypass_ips 包含无效 CIDR 掩码: {p}"))?;
                let max_bits = if ip.is_ipv4() { 32 } else { 128 };
                if bits > max_bits {
                    return Err(format!("sni_loop_bypass_ips 包含无效 CIDR 掩码: {p}"));
                }
                normalized.push(format!("{ip}/{bits}"));
            }
        }
    }
    Ok(normalized.join(","))
}

#[allow(clippy::too_many_arguments)]
pub async fn create_group(
    db: &dyn Repository,
    name: &str,
    group_type: &GroupType,
    owner_uid: i64,
    connect_host: &str,
    port_range: &str,
    sni_fallback_addr: &str,
    sni_loop_bypass_ips: &str,
) -> Result<DeviceGroup, CreateGroupError> {
    let token = uuid::Uuid::new_v4().to_string();
    let group_type = group_type_to_str(group_type);
    db.insert_group(
        name,
        group_type,
        &token,
        owner_uid,
        connect_host,
        port_range,
        sni_fallback_addr,
        sni_loop_bypass_ips,
    )
    .await
    .map_err(CreateGroupError::Database)?;

    match db.find_by_token_after_insert(&token).await {
        Ok(Some(g)) => Ok(g),
        Ok(None) => Err(CreateGroupError::FetchFailed),
        Err(e) => Err(CreateGroupError::Database(e)),
    }
}

pub async fn rotate_group_token(db: &dyn Repository, id: i64) -> Result<Option<String>, DbError> {
    let new_token = uuid::Uuid::new_v4().to_string();
    match db
        .update_group_token(id, &ResourceScope::All, &new_token)
        .await?
    {
        0 => Ok(None),
        _ => Ok(Some(new_token)),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn update_group(
    db: &dyn Repository,
    id: i64,
    name: Option<&str>,
    group_type: Option<&GroupType>,
    connect_host: Option<&str>,
    port_range: Option<&str>,
    sni_fallback_addr: Option<&str>,
    sni_loop_bypass_ips: Option<&str>,
) -> Result<(), UpdateGroupError> {
    if name.is_none()
        && group_type.is_none()
        && connect_host.is_none()
        && port_range.is_none()
        && sni_fallback_addr.is_none()
        && sni_loop_bypass_ips.is_none()
    {
        return Err(UpdateGroupError::NoFields);
    }

    match db
        .update_group_fields(
            id,
            &ResourceScope::All,
            name,
            group_type.map(group_type_to_str),
            connect_host,
            port_range,
            sni_fallback_addr,
            sni_loop_bypass_ips,
        )
        .await
        .map_err(UpdateGroupError::Database)?
    {
        0 => Err(UpdateGroupError::NotFound),
        _ => Ok(()),
    }
}

#[derive(Debug)]
pub enum ReorderGroupsError {
    Invalid,
    UnknownGroup,
    Database(DbError),
}

pub async fn reorder_groups(db: &dyn Repository, ids: &[i64]) -> Result<(), ReorderGroupsError> {
    let distinct: std::collections::HashSet<i64> = ids.iter().copied().collect();
    if ids.is_empty() || distinct.len() != ids.len() {
        return Err(ReorderGroupsError::Invalid);
    }
    db.reorder_groups(ids).await.map_err(|e| match e {
        DbError::NotFound => ReorderGroupsError::UnknownGroup,
        other => ReorderGroupsError::Database(other),
    })
}

#[derive(Debug)]
pub struct GroupInUseError {
    pub group_id: i64,
    pub rule_count: i64,
}

impl std::fmt::Display for GroupInUseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "group {} still referenced by {} rule(s)",
            self.group_id, self.rule_count
        )
    }
}

impl std::error::Error for GroupInUseError {}

pub async fn delete_group(
    db: &dyn Repository,
    id: i64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let count = db.count_rules_by_group(id).await?;
    if count > 0 {
        return Err(Box::new(GroupInUseError {
            group_id: id,
            rule_count: count,
        }));
    }
    Ok(db.delete_group(id, &ResourceScope::All).await? > 0)
}

pub async fn delete_rule(
    db: &dyn Repository,
    id: i64,
    scope: &ResourceScope,
) -> Result<bool, DbError> {
    Ok(db.delete_rule(id, scope).await? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sni_fallback_addr_defaults_and_checks_port() {
        assert_eq!(validate_sni_fallback_addr("  ").unwrap(), "127.0.0.1:10443");
        assert_eq!(
            validate_sni_fallback_addr("127.0.0.1:18443").unwrap(),
            "127.0.0.1:18443"
        );
        assert!(validate_sni_fallback_addr("127.0.0.1").is_err());
        assert!(validate_sni_fallback_addr("127.0.0.1:0").is_err());
        assert!(validate_sni_fallback_addr(":10443").is_err());
    }

    #[test]
    fn validate_sni_loop_bypass_ips_accepts_ip_and_cidr() {
        assert_eq!(validate_sni_loop_bypass_ips(" ").unwrap(), "");
        assert_eq!(
            validate_sni_loop_bypass_ips("11.22.33.44/32, 198.51.100.0/24，2001:db8::1/128\n203.0.113.10")
                .unwrap(),
            "11.22.33.44/32,198.51.100.0/24,2001:db8::1/128,203.0.113.10"
        );
        assert!(validate_sni_loop_bypass_ips("11.22.33.44/33").is_err());
        assert!(validate_sni_loop_bypass_ips("2001:db8::1/129").is_err());
        assert!(validate_sni_loop_bypass_ips("not-an-ip").is_err());
    }
}
