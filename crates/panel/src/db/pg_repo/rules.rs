use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::{ForwardRule, ForwardRuleTarget};
use relay_shared::protocol::RuleTargetRequest;
use std::collections::HashMap;

const RULE_COLS: &str =
    "id, name, uid, paused, listen_port, protocol, device_group_in, device_group_out, \
     forward_mode, NULLIF(sni, '') AS sni, target_addr, target_port, load_balance_strategy, upload_limit_mbps, \
     download_limit_mbps, max_connections, auto_restart_minutes, proxy_protocol_send, \
     proxy_protocol_accept, proxy_protocol_trusted, config, traffic_used, status, created_at";

async fn check_port_conflict_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    exclude_rule_id: Option<i64>,
    device_group_in: i64,
    listen_port: i32,
    protocol: &str,
    sni: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(device_group_in)
        .execute(&mut **tx)
        .await?;

    let uses_tcp = protocol == "tcp" || protocol == "tcp_udp" || protocol == "both";
    let uses_udp = protocol == "udp" || protocol == "tcp_udp" || protocol == "both";
    let exclude_id = exclude_rule_id.unwrap_or(-1);

    if uses_udp {
        let udp_conflict: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM forward_rules \
             WHERE device_group_in = $1 AND listen_port = $2 AND id != $3 \
               AND protocol IN ('udp', 'tcp_udp', 'both') \
             LIMIT 1",
        )
        .bind(device_group_in)
        .bind(listen_port)
        .bind(exclude_id)
        .fetch_optional(&mut **tx)
        .await?;
        if udp_conflict.is_some() {
            return Err(DbError::PortConflict);
        }
    }

    if uses_tcp {
        let tcp_conflict: Option<(i64,)> = match sni {
            None => {
                sqlx::query_as(
                    "SELECT id FROM forward_rules \
                     WHERE device_group_in = $1 AND listen_port = $2 AND id != $3 \
                       AND protocol IN ('tcp', 'tcp_udp', 'both') \
                     LIMIT 1",
                )
                .bind(device_group_in)
                .bind(listen_port)
                .bind(exclude_id)
                .fetch_optional(&mut **tx)
                .await?
            }
            Some(sni_val) => {
                sqlx::query_as(
                    "SELECT id FROM forward_rules \
                     WHERE device_group_in = $1 AND listen_port = $2 AND id != $3 \
                       AND protocol IN ('tcp', 'tcp_udp', 'both') \
                       AND (sni IS NULL OR sni = '' OR LOWER(sni) = LOWER($4)) \
                     LIMIT 1",
                )
                .bind(device_group_in)
                .bind(listen_port)
                .bind(exclude_id)
                .bind(sni_val)
                .fetch_optional(&mut **tx)
                .await?
            }
        };
        if tcp_conflict.is_some() {
            return Err(DbError::PortConflict);
        }
    }

    Ok(())
}

async fn batch_load_targets_pg(
    pool: &sqlx::PgPool,
    rule_ids: &[i64],
    enabled_only: bool,
) -> Result<Vec<ForwardRuleTarget>, DbError> {
    if rule_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut all_targets = Vec::new();
    for chunk in rule_ids.chunks(500) {
        let placeholders = (1..=chunk.len())
            .map(|i| format!("${i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let enabled_clause = if enabled_only {
            " AND enabled = TRUE"
        } else {
            ""
        };
        let sql = format!(
            "SELECT * FROM forward_rule_targets \
             WHERE rule_id IN ({placeholders}){enabled_clause} \
             ORDER BY rule_id, position, id"
        );
        let mut q = sqlx::query_as::<_, ForwardRuleTarget>(&sql);
        for &id in chunk {
            q = q.bind(id);
        }
        let mut rows = q.fetch_all(pool).await?;
        all_targets.append(&mut rows);
    }
    Ok(all_targets)
}

// ── RuleRepository ──

#[async_trait]
impl RuleRepository for PgRepository {
    async fn list_rules(&self, scope: &ResourceScope) -> Result<Vec<ForwardRule>, DbError> {
        let mut rules: Vec<ForwardRule> = match scope.owner_id() {
            None => sqlx::query_as(&format!("SELECT {RULE_COLS} FROM forward_rules ORDER BY id"))
                .fetch_all(&self.pool)
                .await?,
            Some(uid) => sqlx::query_as(&format!(
                "SELECT {RULE_COLS} FROM forward_rules WHERE uid = $1 ORDER BY id"
            ))
            .bind(uid)
            .fetch_all(&self.pool)
            .await?,
        };
        let rule_ids: Vec<i64> = rules.iter().map(|r| r.id).collect();
        let targets = batch_load_targets_pg(&self.pool, &rule_ids, false).await?;
        let mut by_rule: HashMap<i64, Vec<ForwardRuleTarget>> = HashMap::new();
        for t in targets {
            by_rule.entry(t.rule_id).or_default().push(t);
        }
        for rule in &mut rules {
            if let Some(ts) = by_rule.remove(&rule.id) {
                rule.targets = ts;
            }
        }
        Ok(rules)
    }

    async fn find_rule_by_id(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<ForwardRule>, DbError> {
        let rule: Option<ForwardRule> = match scope.owner_id() {
            None => sqlx::query_as(&format!(
                "SELECT {RULE_COLS} FROM forward_rules WHERE id = $1"
            ))
            .bind(rule_id)
            .fetch_optional(&self.pool)
            .await?,
            Some(uid) => sqlx::query_as(&format!(
                "SELECT {RULE_COLS} FROM forward_rules WHERE id = $1 AND uid = $2"
            ))
            .bind(rule_id)
            .bind(uid)
            .fetch_optional(&self.pool)
            .await?,
        };
        let Some(mut rule) = rule else {
            return Ok(None);
        };
        rule.targets = sqlx::query_as(
            "SELECT * FROM forward_rule_targets WHERE rule_id = $1 ORDER BY position, id",
        )
        .bind(rule.id)
        .fetch_all(&self.pool)
        .await?;
        Ok(Some(rule))
    }

    async fn list_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError> {
        let targets: Vec<ForwardRuleTarget> = match scope.owner_id() {
            None => sqlx::query_as(
                "SELECT t.* FROM forward_rule_targets t \
                 JOIN forward_rules r ON r.id = t.rule_id \
                 WHERE t.rule_id = $1 \
                 ORDER BY t.position, t.id",
            )
            .bind(rule_id)
            .fetch_all(&self.pool)
            .await?,
            Some(uid) => sqlx::query_as(
                "SELECT t.* FROM forward_rule_targets t \
                 JOIN forward_rules r ON r.id = t.rule_id \
                 WHERE t.rule_id = $1 AND r.uid = $2 \
                 ORDER BY t.position, t.id",
            )
            .bind(rule_id)
            .bind(uid)
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(targets)
    }

    async fn list_enabled_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError> {
        let targets: Vec<ForwardRuleTarget> = match scope.owner_id() {
            None => sqlx::query_as(
                "SELECT t.* FROM forward_rule_targets t \
                 JOIN forward_rules r ON r.id = t.rule_id \
                 WHERE t.rule_id = $1 AND t.enabled = TRUE \
                 ORDER BY t.position, t.id",
            )
            .bind(rule_id)
            .fetch_all(&self.pool)
            .await?,
            Some(uid) => sqlx::query_as(
                "SELECT t.* FROM forward_rule_targets t \
                 JOIN forward_rules r ON r.id = t.rule_id \
                 WHERE t.rule_id = $1 AND r.uid = $2 AND t.enabled = TRUE \
                 ORDER BY t.position, t.id",
            )
            .bind(rule_id)
            .bind(uid)
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(targets)
    }

    async fn list_enabled_targets_for_rules(
        &self,
        rule_ids: &[i64],
    ) -> Result<Vec<ForwardRuleTarget>, DbError> {
        batch_load_targets_pg(&self.pool, rule_ids, true).await
    }

    async fn replace_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        targets: &[RuleTargetRequest],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let exists: Option<(i64,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT id FROM forward_rules WHERE id = $1")
                .bind(rule_id)
                .fetch_optional(&mut *tx)
                .await?,
            Some(uid) => sqlx::query_as("SELECT id FROM forward_rules WHERE id = $1 AND uid = $2")
                .bind(rule_id)
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await?,
        };
        if exists.is_none() {
            return Err(DbError::NotFound);
        }

        sqlx::query("DELETE FROM forward_rule_targets WHERE rule_id = $1")
            .bind(rule_id)
            .execute(&mut *tx)
            .await?;

        for (pos, t) in targets.iter().enumerate() {
            sqlx::query(
                "INSERT INTO forward_rule_targets \
                 (rule_id, host, port, position, enabled) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(rule_id)
            .bind(&t.host)
            .bind(t.port as i32)
            .bind((pos + 1) as i32)
            .bind(t.enabled)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(primary) = targets.iter().find(|t| t.enabled).or(targets.first()) {
            sqlx::query("UPDATE forward_rules SET target_addr = $1, target_port = $2 WHERE id = $3")
                .bind(&primary.host)
                .bind(primary.port as i32)
                .bind(rule_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn set_rule_load_balance_strategy(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        strategy: &str,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE forward_rules SET load_balance_strategy = $1 WHERE id = $2",
            )
            .bind(strategy)
            .bind(rule_id)
            .execute(&self.pool)
            .await?,
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET load_balance_strategy = $1 WHERE id = $2 AND uid = $3",
            )
            .bind(strategy)
            .bind(rule_id)
            .bind(uid)
            .execute(&self.pool)
            .await?,
        };
        Ok(result.rows_affected())
    }

    async fn set_rule_rate_limits(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE forward_rules \
                 SET upload_limit_mbps = $1, download_limit_mbps = $2 \
                 WHERE id = $3",
            )
            .bind(upload_limit_mbps)
            .bind(download_limit_mbps)
            .bind(rule_id)
            .execute(&self.pool)
            .await?,
            Some(uid) => sqlx::query(
                "UPDATE forward_rules \
                 SET upload_limit_mbps = $1, download_limit_mbps = $2 \
                 WHERE id = $3 AND uid = $4",
            )
            .bind(upload_limit_mbps)
            .bind(download_limit_mbps)
            .bind(rule_id)
            .bind(uid)
            .execute(&self.pool)
            .await?,
        };
        Ok(result.rows_affected())
    }

    async fn set_rule_connection_controls(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        max_connections: i32,
        auto_restart_minutes: i32,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query(
                "UPDATE forward_rules \
                 SET max_connections = $1, auto_restart_minutes = $2 \
                 WHERE id = $3",
            )
            .bind(max_connections)
            .bind(auto_restart_minutes)
            .bind(rule_id)
            .execute(&self.pool)
            .await?,
            Some(uid) => sqlx::query(
                "UPDATE forward_rules \
                 SET max_connections = $1, auto_restart_minutes = $2 \
                 WHERE id = $3 AND uid = $4",
            )
            .bind(max_connections)
            .bind(auto_restart_minutes)
            .bind(rule_id)
            .bind(uid)
            .execute(&self.pool)
            .await?,
        };
        Ok(result.rows_affected())
    }

    async fn list_auto_restart_rules(&self) -> Result<Vec<(i64, i64, i32)>, DbError> {
        let rows: Vec<(i64, i64, i32)> = sqlx::query_as(
            "SELECT id, device_group_in, auto_restart_minutes FROM forward_rules \
             WHERE auto_restart_minutes > 0 AND paused = FALSE \
             ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn list_group_port_protocols(
        &self,
        device_group_in: i64,
    ) -> Result<Vec<(i32, String)>, DbError> {
        let used: Vec<(i32, String)> = sqlx::query_as(
            "SELECT listen_port, protocol FROM forward_rules WHERE device_group_in = $1",
        )
        .bind(device_group_in)
        .fetch_all(&self.pool)
        .await?;
        Ok(used)
    }

    async fn group_port_range(&self, group_id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT port_range FROM device_groups WHERE id = $1")
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(r,)| r))
    }

    async fn count_by_uid(&self, uid: i64) -> Result<i64, DbError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forward_rules WHERE uid = $1 AND paused = FALSE",
        )
        .bind(uid)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

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
        max_connections: i32,
        auto_restart_minutes: i32,
        proxy_protocol: &RuleProxyProtocol,
    ) -> Result<i64, DbError> {
        let mut tx = self.pool.begin().await?;

        check_port_conflict_pg(
            &mut tx,
            None,
            device_group_in,
            listen_port,
            protocol,
            sni,
        )
        .await?;

        let (rule_id,): (i64,) = sqlx::query_as(
            "INSERT INTO forward_rules \
             (name, uid, listen_port, protocol, sni, device_group_in, device_group_out, \
              forward_mode, target_addr, target_port, load_balance_strategy, \
              upload_limit_mbps, download_limit_mbps, max_connections, auto_restart_minutes, \
              proxy_protocol_send, proxy_protocol_accept, proxy_protocol_trusted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
             RETURNING id",
        )
        .bind(name)
        .bind(uid)
        .bind(listen_port)
        .bind(protocol)
        .bind(sni.unwrap_or(""))
        .bind(device_group_in)
        .bind(device_group_out)
        .bind(forward_mode)
        .bind(target_addr)
        .bind(target_port)
        .bind(load_balance_strategy)
        .bind(upload_limit_mbps)
        .bind(download_limit_mbps)
        .bind(max_connections)
        .bind(auto_restart_minutes)
        .bind(&proxy_protocol.send)
        .bind(proxy_protocol.accept)
        .bind(&proxy_protocol.trusted)
        .fetch_one(&mut *tx)
        .await?;

        for (pos, t) in targets.iter().enumerate() {
            sqlx::query(
                "INSERT INTO forward_rule_targets \
                 (rule_id, host, port, position, enabled) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(rule_id)
            .bind(&t.host)
            .bind(t.port as i32)
            .bind((pos + 1) as i32)
            .bind(t.enabled)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(primary) = targets.iter().find(|t| t.enabled).or(targets.first()) {
            sqlx::query("UPDATE forward_rules SET target_addr = $1, target_port = $2 WHERE id = $3")
                .bind(&primary.host)
                .bind(primary.port as i32)
                .bind(rule_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(rule_id)
    }

    async fn find_device_group_out_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<Option<i64>>, DbError> {
        let row: Option<(Option<i64>,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT device_group_out FROM forward_rules WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
            Some(uid) => sqlx::query_as(
                "SELECT device_group_out FROM forward_rules WHERE id = $1 AND uid = $2",
            )
            .bind(id)
            .bind(uid)
            .fetch_optional(&self.pool)
            .await?,
        };
        Ok(row.map(|(g,)| g))
    }

    async fn update_rule_full(
        &self,
        id: i64,
        scope: &ResourceScope,
        update: &RuleUpdate<'_>,
    ) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;

        let current: Option<(i32, String, Option<String>, i64)> = match scope.owner_id() {
            None => sqlx::query_as(
                "SELECT listen_port, protocol, NULLIF(sni, '') AS sni, device_group_in \
                 FROM forward_rules WHERE id = $1 \
                 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?,
            Some(uid) => sqlx::query_as(
                "SELECT listen_port, protocol, NULLIF(sni, '') AS sni, device_group_in \
                 FROM forward_rules WHERE id = $1 AND uid = $2 \
                 FOR UPDATE",
            )
            .bind(id)
            .bind(uid)
            .fetch_optional(&mut *tx)
            .await?,
        };
        let Some((cur_port, cur_proto, cur_sni, cur_group_in)) = current else {
            return Ok(0);
        };

        let eff_port = update.listen_port.unwrap_or(cur_port);
        let eff_proto = update.protocol.unwrap_or(cur_proto.as_str());
        let eff_sni: Option<&str> = match update.sni {
            Some(s) => s,
            None => cur_sni.as_deref(),
        };
        let eff_group_in = update.device_group_in.unwrap_or(cur_group_in);

        if update.listen_port.is_some()
            || update.protocol.is_some()
            || update.sni.is_some()
            || update.device_group_in.is_some()
        {
            check_port_conflict_pg(
                &mut tx,
                Some(id),
                eff_group_in,
                eff_port,
                eff_proto,
                eff_sni,
            )
            .await?;
        }

        if update.has_columns() {
            let mut sets: Vec<&str> = Vec::new();
            if update.name.is_some() {
                sets.push("name = ");
            }
            if update.listen_port.is_some() {
                sets.push("listen_port = ");
            }
            if update.protocol.is_some() {
                sets.push("protocol = ");
            }
            if update.sni.is_some() {
                sets.push("sni = ");
            }
            if update.device_group_in.is_some() {
                sets.push("device_group_in = ");
            }
            if update.device_group_out.is_some() {
                sets.push("device_group_out = ");
            }
            if update.forward_mode.is_some() {
                sets.push("forward_mode = ");
            }
            if update.target_addr.is_some() {
                sets.push("target_addr = ");
            }
            if update.target_port.is_some() {
                sets.push("target_port = ");
            }
            if update.paused.is_some() {
                sets.push("paused = ");
            }
            if update.load_balance_strategy.is_some() {
                sets.push("load_balance_strategy = ");
            }
            if update.upload_limit_mbps.is_some() {
                sets.push("upload_limit_mbps = ");
            }
            if update.download_limit_mbps.is_some() {
                sets.push("download_limit_mbps = ");
            }
            if update.max_connections.is_some() {
                sets.push("max_connections = ");
            }
            if update.auto_restart_minutes.is_some() {
                sets.push("auto_restart_minutes = ");
            }
            if update.proxy_protocol_send.is_some() {
                sets.push("proxy_protocol_send = ");
            }
            if update.proxy_protocol_accept.is_some() {
                sets.push("proxy_protocol_accept = ");
            }
            if update.proxy_protocol_trusted.is_some() {
                sets.push("proxy_protocol_trusted = ");
            }

            let mut ph = 1;
            let sets_with_ph: Vec<String> = sets
                .iter()
                .map(|s| {
                    let p = format!("{s}${ph}");
                    ph += 1;
                    p
                })
                .collect();
            let sql = format!(
                "UPDATE forward_rules SET {} WHERE id = ${ph}",
                sets_with_ph.join(", ")
            );
            let mut q = sqlx::query(&sql);
            if let Some(v) = update.name {
                q = q.bind(v);
            }
            if let Some(v) = update.listen_port {
                q = q.bind(v);
            }
            if let Some(v) = update.protocol {
                q = q.bind(v);
            }
            if let Some(v) = update.sni {
                q = q.bind(v.unwrap_or(""));
            }
            if let Some(v) = update.device_group_in {
                q = q.bind(v);
            }
            if let Some(v) = update.device_group_out {
                q = q.bind(v);
            }
            if let Some(v) = update.forward_mode {
                q = q.bind(v);
            }
            if let Some(v) = update.target_addr {
                q = q.bind(v);
            }
            if let Some(v) = update.target_port {
                q = q.bind(v);
            }
            if let Some(v) = update.paused {
                q = q.bind(v);
            }
            if let Some(v) = update.load_balance_strategy {
                q = q.bind(v);
            }
            if let Some(v) = update.upload_limit_mbps {
                q = q.bind(v);
            }
            if let Some(v) = update.download_limit_mbps {
                q = q.bind(v);
            }
            if let Some(v) = update.max_connections {
                q = q.bind(v);
            }
            if let Some(v) = update.auto_restart_minutes {
                q = q.bind(v);
            }
            if let Some(v) = update.proxy_protocol_send {
                q = q.bind(v);
            }
            if let Some(v) = update.proxy_protocol_accept {
                q = q.bind(v);
            }
            if let Some(v) = update.proxy_protocol_trusted {
                q = q.bind(v);
            }
            q = q.bind(id);
            q.execute(&mut *tx).await?;
        }

        if let Some(targets) = update.targets {
            sqlx::query("DELETE FROM forward_rule_targets WHERE rule_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for (pos, t) in targets.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO forward_rule_targets \
                     (rule_id, host, port, position, enabled) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(id)
                .bind(&t.host)
                .bind(t.port as i32)
                .bind((pos + 1) as i32)
                .bind(t.enabled)
                .execute(&mut *tx)
                .await?;
            }
            if let Some(primary) = targets.iter().find(|t| t.enabled).or(targets.first()) {
                sqlx::query(
                    "UPDATE forward_rules SET target_addr = $1, target_port = $2 WHERE id = $3",
                )
                .bind(&primary.host)
                .bind(primary.port as i32)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(1)
    }

    async fn increment_rule_traffic(
        &self,
        id: i64,
        upload: u64,
        download: u64,
    ) -> Result<(), DbError> {
        let delta = i64::try_from(upload)
            .ok()
            .and_then(|u| i64::try_from(download).ok().and_then(|d| u.checked_add(d)))
            .ok_or_else(|| {
                DbError::Other(sqlx::Error::Protocol(
                    "traffic delta overflows i64".to_string(),
                ))
            })?;
        sqlx::query("UPDATE forward_rules SET traffic_used = traffic_used + $1 WHERE id = $2")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_rule_owner(
        &self,
        rule_id: i64,
        device_group_in: i64,
    ) -> Result<Option<(i64, i64)>, DbError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT id, uid FROM forward_rules WHERE id = $1 AND device_group_in = $2",
        )
        .bind(rule_id)
        .bind(device_group_in)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete_rule(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("DELETE FROM forward_rules WHERE id = $1").bind(id),
            Some(uid) => sqlx::query("DELETE FROM forward_rules WHERE id = $1 AND uid = $2")
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn reset_rule_traffic(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => {
                sqlx::query("UPDATE forward_rules SET traffic_used = 0 WHERE id = $1").bind(id)
            }
            Some(uid) => sqlx::query(
                "UPDATE forward_rules SET traffic_used = 0 WHERE id = $1 AND uid = $2",
            )
            .bind(id)
            .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn delete_rules_by_uid(&self, uid: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM forward_rules WHERE uid = $1")
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn list_active_for_config(&self, group_id: i64) -> Result<Vec<ForwardRule>, DbError> {
        let sql = format!(
            "SELECT {RULE_COLS} FROM forward_rules \
             WHERE device_group_in = $1 AND paused = FALSE \
             ORDER BY id"
        );
        let rules: Vec<ForwardRule> = sqlx::query_as(&sql)
            .bind(group_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rules)
    }
}
