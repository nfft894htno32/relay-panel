use super::err;
use crate::api::middleware::{AdminOnly, AuthUser};
use crate::api::AppState;
use crate::db::repo::ResourceScope;
use crate::service::groups::{
    validate_sni_fallback_addr, validate_sni_loop_bypass_ips, CreateGroupError, ReorderGroupsError,
    UpdateGroupError, DEFAULT_SNI_FALLBACK_ADDR,
};
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

// === Device Groups ===
pub async fn list_groups(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<DeviceGroup>>> {
    let scope = user.resource_scope();
    match state.db.list_groups(&scope).await {
        Ok(groups) => Json(ApiResponse::success(groups)),
        Err(e) => {
            tracing::error!("list_groups: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_group(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Json<ApiResponse<DeviceGroup>> {
    let sni_fallback_addr = match req.sni_fallback_addr.as_deref() {
        Some(addr) if !addr.trim().is_empty() => match validate_sni_fallback_addr(addr) {
            Ok(v) => v,
            Err(_) => return Json(err(400, "SNI 回落地址格式无效（示例：127.0.0.1:10443）")),
        },
        _ => DEFAULT_SNI_FALLBACK_ADDR.to_string(),
    };
    let sni_loop_bypass_ips = match req.sni_loop_bypass_ips.as_deref() {
        Some(ips) => match validate_sni_loop_bypass_ips(ips) {
            Ok(v) => v,
            Err(_) => return Json(err(400, "防回环白名单 IP 格式无效（多个 IP 用逗号分隔）")),
        },
        None => String::new(),
    };

    match crate::service::groups::create_group(
        state.db.as_ref(),
        &req.name,
        &req.group_type,
        admin.user_id,
        &req.connect_host,
        &req.port_range,
        &sni_fallback_addr,
        &sni_loop_bypass_ips,
    )
    .await
    {
        Ok(g) => Json(ApiResponse::success(g)),
        Err(CreateGroupError::FetchFailed) => Json(err(500, "Failed to fetch created group")),
        Err(CreateGroupError::Database(e)) => {
            tracing::error!("create_group: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

/// `PUT /groups/order`: set the panel-wide display order of the groups. Admin only.
pub async fn reorder_groups(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<ReorderGroupsRequest>,
) -> Json<ApiResponse<()>> {
    match crate::service::groups::reorder_groups(state.db.as_ref(), &req.ids).await {
        Ok(()) => {
            let order = match state.db.list_groups(&ResourceScope::All).await {
                Ok(groups) => groups
                    .iter()
                    .map(|g| g.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" > "),
                Err(_) => format!("{} 个分组", req.ids.len()),
            };
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "reorder_groups",
                "group",
                "-",
                &order,
            )
            .await;
            Json(ApiResponse::success(()))
        }
        Err(ReorderGroupsError::Invalid) => Json(err(400, "分组顺序无效")),
        Err(ReorderGroupsError::UnknownGroup) => Json(err(400, "包含不存在的分组")),
        Err(ReorderGroupsError::Database(e)) => {
            tracing::error!("reorder_groups: db error: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

#[derive(serde::Serialize)]
pub struct RotatedToken {
    token: String,
}

pub async fn rotate_group_token(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<RotatedToken>> {
    match crate::service::groups::rotate_group_token(state.db.as_ref(), id).await {
        Ok(None) => Json(err(404, "分组不存在")),
        Ok(Some(new_token)) => {
            let closed = state.node_connections.close_group(id).await;
            tracing::warn!(
                action = "rotate_group_token",
                group_id = id,
                closed_connections = closed,
                "admin rotated node token"
            );
            crate::service::audit::record(
                &state,
                Some(_admin.user_id),
                "rotate_group_token",
                "group",
                id,
                &format!(
                    "{} · 断开 {closed} 个节点连接",
                    crate::service::audit::group_label(&state, id).await
                ),
            )
            .await;
            Json(ApiResponse::success(RotatedToken { token: new_token }))
        }
        Err(e) => {
            tracing::error!(
                "rotate_group_token {}: update_group_token failed: {}",
                id,
                e
            );
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn update_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupRequest>,
) -> Json<ApiResponse<()>> {
    let sni_fallback_addr = match req.sni_fallback_addr.as_deref() {
        Some(addr) => match validate_sni_fallback_addr(addr) {
            Ok(v) => Some(v),
            Err(_) => return Json(err(400, "SNI 回落地址格式无效（示例：127.0.0.1:10443）")),
        },
        None => None,
    };
    let sni_loop_bypass_ips = match req.sni_loop_bypass_ips.as_deref() {
        Some(ips) => match validate_sni_loop_bypass_ips(ips) {
            Ok(v) => Some(v),
            Err(_) => return Json(err(400, "防回环白名单 IP 格式无效（多个 IP 用逗号分隔）")),
        },
        None => None,
    };

    match crate::service::groups::update_group(
        state.db.as_ref(),
        id,
        req.name.as_deref(),
        req.group_type.as_ref(),
        req.connect_host.as_deref(),
        req.port_range.as_deref(),
        sni_fallback_addr.as_deref(),
        sni_loop_bypass_ips.as_deref(),
    )
    .await
    {
        Ok(()) => {
            state
                .node_connections
                .send_group(id, r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(UpdateGroupError::NoFields) => Json(err(400, "无需要更新的字段")),
        Err(UpdateGroupError::NotFound) => Json(err(404, "Group not found")),
        Err(UpdateGroupError::Database(e)) => {
            tracing::error!("update_group {}: update_group_fields failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_group(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let label = crate::service::audit::group_label(&state, id).await;
    match crate::service::groups::delete_group(state.db.as_ref(), id).await {
        Ok(false) => Json(err(404, "分组不存在")),
        Ok(true) => {
            tracing::warn!(
                action = "delete_group",
                group_id = id,
                actor_id = admin.user_id,
                actor_admin = true,
                "destructive op"
            );
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "delete_group",
                "group",
                id,
                &label,
            )
            .await;
            state.node_connections.close_group(id).await;
            if let Err(e) =
                crate::service::traffic::remove_group_status(state.db.as_ref(), id).await
            {
                tracing::warn!(
                    "delete_group {}: removing its node records failed: {}",
                    id,
                    e
                );
            }
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            if let Some(in_use) = e.downcast_ref::<crate::service::groups::GroupInUseError>() {
                return Json(err(
                    409,
                    format!(
                        "该分组仍被 {} 条规则使用，请先迁移规则。",
                        in_use.rule_count
                    ),
                ));
            }
            tracing::error!("delete_group {}: delete_group failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}
