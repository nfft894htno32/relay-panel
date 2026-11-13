use super::err;
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::service::rules::{CreateRuleError, UpdateRuleError};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

/// Query params for list_rules.
#[derive(serde::Deserialize, Default)]
pub struct ListRulesQuery {
    pub owner_uid: Option<i64>,
}

// === Forward Rules ===
pub async fn list_rules(
    user: AuthUser,
    Query(query): Query<ListRulesQuery>,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<ForwardRule>>> {
    let scope = match (user.admin, query.owner_uid) {
        (true, Some(owner_uid)) => crate::db::repo::ResourceScope::Owner(owner_uid),
        _ => user.resource_scope(),
    };
    match state.db.list_rules(&scope).await {
        Ok(rules) => Json(ApiResponse::success(rules)),
        Err(e) => {
            tracing::error!("list_rules: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Json<ApiResponse<()>> {
    match crate::service::rules::create_rule(state.db.as_ref(), user.user_id, &req).await {
        Ok(()) => {
            state
                .node_connections
                .send_group(req.device_group_in, r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(CreateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(CreateRuleError::PortConflict(port)) => Json(err(
            409,
            format!("监听端口 {} 在此入口分组上已被占用", port),
        )),
        Err(CreateRuleError::Database(e)) => {
            tracing::error!("create_rule: service failed: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn update_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleRequest>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    let old_group_id = state
        .db
        .find_rule_by_id(id, &scope)
        .await
        .ok()
        .flatten()
        .map(|r| r.device_group_in);

    match crate::service::rules::update_rule(state.db.as_ref(), id, &scope, &req).await {
        Ok(()) => {
            if let Some(old_gid) = old_group_id {
                state
                    .node_connections
                    .send_group(old_gid, r#"{"type":"config_changed"}"#)
                    .await;
            }
            if let Some(new_gid) = req.device_group_in {
                if Some(new_gid) != old_group_id {
                    state
                        .node_connections
                        .send_group(new_gid, r#"{"type":"config_changed"}"#)
                        .await;
                }
            }
            Json(ApiResponse::success(()))
        }
        Err(UpdateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(UpdateRuleError::NotFound) => Json(err(404, "规则不存在")),
        Err(UpdateRuleError::PortConflict) => Json(err(409, "监听端口在此入口分组上已被占用")),
        Err(UpdateRuleError::Database(e)) => {
            tracing::error!("update_rule {}: service failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn batch_update_rule_rate_limits(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<BatchUpdateRateLimitsRequest>,
) -> Json<ApiResponse<BatchUpdateRateLimitsResponse>> {
    let mut seen = std::collections::HashSet::with_capacity(req.rule_ids.len());
    let unique_ids: Vec<i64> = req
        .rule_ids
        .into_iter()
        .filter(|id| seen.insert(*id))
        .collect();

    if unique_ids.is_empty() {
        return Json(err(400, "请至少选择一条规则"));
    }
    if unique_ids.len() > 500 {
        return Json(err(400, "单次批量修改最多支持 500 条规则"));
    }

    let limits = [
        req.upload_limit_mbps,
        req.download_limit_mbps,
        req.per_ip_upload_limit_mbps,
        req.per_ip_download_limit_mbps,
    ];
    if limits.iter().all(Option::is_none) {
        return Json(err(400, "请至少选择一项要修改的限速配置"));
    }
    if limits.iter().flatten().any(|&v| v < 0) {
        return Json(err(400, "限速值不能小于 0"));
    }

    let partial = UpdateRuleRequest {
        upload_limit_mbps: req.upload_limit_mbps,
        download_limit_mbps: req.download_limit_mbps,
        per_ip_upload_limit_mbps: req.per_ip_upload_limit_mbps,
        per_ip_download_limit_mbps: req.per_ip_download_limit_mbps,
        ..Default::default()
    };

    let scope = user.resource_scope();
    let mut updated = 0usize;
    let mut not_found = Vec::new();
    let mut affected_groups = std::collections::BTreeSet::new();

    for id in unique_ids {
        let group_in = match state.db.find_rule_by_id(id, &scope).await {
            Ok(Some(rule)) => rule.device_group_in,
            Ok(None) => {
                not_found.push(id);
                continue;
            }
            Err(e) => {
                tracing::error!(
                    "batch_update_rule_rate_limits {}: find_rule_by_id failed: {}",
                    id,
                    e
                );
                return Json(err(500, "数据库错误"));
            }
        };

        match crate::service::rules::update_rule(state.db.as_ref(), id, &scope, &partial).await {
            Ok(()) => {
                updated += 1;
                affected_groups.insert(group_in);
            }
            Err(UpdateRuleError::NotFound) => not_found.push(id),
            Err(UpdateRuleError::BadRequest(msg)) => return Json(err(400, msg)),
            Err(UpdateRuleError::PortConflict) => {
                return Json(err(409, "监听端口在此入口分组上已被占用"))
            }
            Err(UpdateRuleError::Database(e)) => {
                tracing::error!(
                    "batch_update_rule_rate_limits {}: service failed: {}",
                    id,
                    e
                );
                return Json(err(500, "数据库错误"));
            }
        }
    }

    for gid in affected_groups {
        state
            .node_connections
            .send_group(gid, r#"{"type":"config_changed"}"#)
            .await;
    }

    if updated > 0 {
        crate::service::audit::record(
            &state,
            Some(user.user_id),
            "batch_update_rule_rate_limits",
            "rule",
            0,
            &format!("updated {updated} rules"),
        )
        .await;
    }

    Json(ApiResponse::success(BatchUpdateRateLimitsResponse {
        updated,
        not_found,
    }))
}

pub async fn reset_rule_traffic(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    let rule_name = match state.db.find_rule_by_id(id, &scope).await {
        Ok(Some(r)) => r.name,
        Ok(None) => return Json(err(404, "规则不存在")),
        Err(e) => {
            tracing::error!("reset_rule_traffic {}: find_rule_by_id failed: {}", id, e);
            return Json(err(500, "数据库错误"));
        }
    };
    match state.db.reset_rule_traffic(id, &scope).await {
        Ok(0) => Json(err(404, "规则不存在")),
        Ok(_) => {
            crate::service::audit::record(
                &state,
                Some(user.user_id),
                "reset_rule_traffic",
                "rule",
                id,
                &rule_name,
            )
            .await;
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("reset_rule_traffic {}: update failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    let (rule_name, group_id) = match state.db.find_rule_by_id(id, &scope).await {
        Ok(Some(r)) => (r.name, Some(r.device_group_in)),
        _ => (String::new(), None),
    };
    match crate::service::groups::delete_rule(state.db.as_ref(), id, &scope).await {
        Ok(false) => Json(err(404, "规则不存在")),
        Ok(true) => {
            tracing::warn!(
                action = "delete_rule",
                rule_id = id,
                actor_id = user.user_id,
                actor_admin = user.admin,
                "destructive op"
            );
            crate::service::audit::record(
                &state,
                Some(user.user_id),
                "delete_rule",
                "rule",
                id,
                &rule_name,
            )
            .await;
            if let Some(gid) = group_id {
                state
                    .node_connections
                    .send_group(gid, r#"{"type":"config_changed"}"#)
                    .await;
            }
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("delete_rule {}: delete_rule failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}
