use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::DeviceGroup;

const GROUP_COLS: &str =
    "id, name, group_type, token, uid, connect_host, port_range, fallback_group, config, \
     capabilities, region, line_type, remark, sni_fallback_addr, sni_loop_bypass_ips, \
     sort_order, created_at";

// ── GroupRepository ──

#[async_trait]
impl GroupRepository for PgRepository {
    async fn list_groups(&self, scope: &ResourceScope) -> Result<Vec<DeviceGroup>, DbError> {
        let groups: Vec<DeviceGroup> = match scope.owner_id() {
            None => {
                sqlx::query_as(&format!(
                    "SELECT {GROUP_COLS} FROM device_groups ORDER BY sort_order, id"
                ))
                .fetch_all(&self.pool)
                .await?
            }
            Some(uid) => {
                sqlx::query_as(&format!(
                    "SELECT {GROUP_COLS} FROM device_groups WHERE uid = $1 ORDER BY sort_order, id"
                ))
                .bind(uid)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(groups)
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<DeviceGroup>, DbError> {
        let group: Option<DeviceGroup> = sqlx::query_as(&format!(
            "SELECT {GROUP_COLS} FROM device_groups WHERE token = $1"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(group)
    }

    async fn find_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<DeviceGroup>, DbError> {
        let group: Option<DeviceGroup> = match scope.owner_id() {
            None => {
                sqlx::query_as(&format!(
                    "SELECT {GROUP_COLS} FROM device_groups WHERE id = $1"
                ))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
            }
            Some(uid) => {
                sqlx::query_as(&format!(
                    "SELECT {GROUP_COLS} FROM device_groups WHERE id = $1 AND uid = $2"
                ))
                .bind(id)
                .bind(uid)
                .fetch_optional(&self.pool)
                .await?
            }
        };
        Ok(group)
    }

    async fn find_name_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = match scope.owner_id() {
            None => sqlx::query_as("SELECT name FROM device_groups WHERE id = $1").bind(id),
            Some(uid) => {
                sqlx::query_as("SELECT name FROM device_groups WHERE id = $1 AND uid = $2")
                    .bind(id)
                    .bind(uid)
            }
        }
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(n,)| n))
    }

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
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO device_groups (name, group_type, token, uid, connect_host, port_range, sni_fallback_addr, sni_loop_bypass_ips, sort_order) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM device_groups))",
        )
        .bind(name)
        .bind(group_type)
        .bind(token)
        .bind(uid)
        .bind(connect_host)
        .bind(port_range)
        .bind(sni_fallback_addr)
        .bind(sni_loop_bypass_ips)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_by_token_after_insert(
        &self,
        token: &str,
    ) -> Result<Option<DeviceGroup>, DbError> {
        let group: Option<DeviceGroup> = sqlx::query_as(&format!(
            "SELECT {GROUP_COLS} FROM device_groups WHERE token = $1"
        ))
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(group)
    }

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
    ) -> Result<u64, DbError> {
        let mut sets: Vec<&str> = Vec::new();
        if name.is_some() {
            sets.push("name = ");
        }
        if group_type.is_some() {
            sets.push("group_type = ");
        }
        if connect_host.is_some() {
            sets.push("connect_host = ");
        }
        if port_range.is_some() {
            sets.push("port_range = ");
        }
        if sni_fallback_addr.is_some() {
            sets.push("sni_fallback_addr = ");
        }
        if sni_loop_bypass_ips.is_some() {
            sets.push("sni_loop_bypass_ips = ");
        }

        if sets.is_empty() {
            return Ok(0);
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
        let id_ph = ph;
        let uid_ph = ph + 1;
        let sql = match scope.owner_id() {
            None => format!(
                "UPDATE device_groups SET {} WHERE id = ${}",
                sets_with_ph.join(", "),
                id_ph
            ),
            Some(_) => format!(
                "UPDATE device_groups SET {} WHERE id = ${} AND uid = ${}",
                sets_with_ph.join(", "),
                id_ph,
                uid_ph
            ),
        };

        let mut q = sqlx::query(&sql);
        if let Some(v) = name {
            q = q.bind(v);
        }
        if let Some(v) = group_type {
            q = q.bind(v);
        }
        if let Some(v) = connect_host {
            q = q.bind(v);
        }
        if let Some(v) = port_range {
            q = q.bind(v);
        }
        if let Some(v) = sni_fallback_addr {
            q = q.bind(v);
        }
        if let Some(v) = sni_loop_bypass_ips {
            q = q.bind(v);
        }
        q = q.bind(id);
        if let Some(uid) = scope.owner_id() {
            q = q.bind(uid);
        }

        let result = q.execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn update_group_token(
        &self,
        id: i64,
        scope: &ResourceScope,
        new_token: &str,
    ) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("UPDATE device_groups SET token = $1 WHERE id = $2")
                .bind(new_token)
                .bind(id),
            Some(uid) => {
                sqlx::query("UPDATE device_groups SET token = $1 WHERE id = $2 AND uid = $3")
                    .bind(new_token)
                    .bind(id)
                    .bind(uid)
            }
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn count_rules_by_group(&self, id: i64) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forward_rules \
             WHERE device_group_in = $1 OR device_group_out = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    async fn delete_group(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError> {
        let result = match scope.owner_id() {
            None => sqlx::query("DELETE FROM device_groups WHERE id = $1").bind(id),
            Some(uid) => sqlx::query("DELETE FROM device_groups WHERE id = $1 AND uid = $2")
                .bind(id)
                .bind(uid),
        }
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn delete_groups_by_uid(&self, uid: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM device_groups WHERE uid = $1")
            .bind(uid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn reorder_groups(&self, ids: &[i64]) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let current: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM device_groups ORDER BY sort_order, id")
                .fetch_all(&mut *tx)
                .await?;
        let rest = unlisted_ids(&current, ids);
        for (pos, id) in ids.iter().chain(rest.iter()).enumerate() {
            let r = sqlx::query("UPDATE device_groups SET sort_order = $1 WHERE id = $2")
                .bind(pos as i32 + 1)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            if r.rows_affected() == 0 {
                return Err(DbError::NotFound);
            }
        }
        tx.commit().await?;
        Ok(())
    }
}
