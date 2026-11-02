use super::{err, UserSelf};
use crate::api::auth_throttle::{run_bcrypt, AttemptLimiter};
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::service::password::{
    hash_password, validate_password, verify_password, PasswordValidationError,
};
use axum::{extract::State, Json};
use once_cell::sync::Lazy;
use relay_shared::protocol::ApiResponse;
use std::time::Duration;

/// 5 password-change attempts per user per minute. Each costs a bcrypt-12
/// check even when the current password is wrong.
static CHANGE_PASSWORD_LIMITER: Lazy<AttemptLimiter<i64>> =
    Lazy::new(|| AttemptLimiter::new(5, Duration::from_secs(60), 10_000));

fn busy<T: serde::Serialize>() -> Json<ApiResponse<T>> {
    Json(err(429, "服务器繁忙，请稍后再试"))
}

// === Change Password ===
#[derive(Debug, serde::Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// GET /user/me — the calling user's own account info (no password hash).
pub async fn get_me(user: AuthUser, State(state): State<AppState>) -> Json<ApiResponse<UserSelf>> {
    let u = match crate::db::repo::UserRepository::find_by_id(state.db.as_ref(), user.user_id).await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Json(ApiResponse {
                code: 404,
                message: "用户不存在".into(),
                data: None,
            })
        }
        Err(e) => {
            tracing::error!("get_me {}: find_by_id failed: {}", user.user_id, e);
            return Json(ApiResponse {
                code: 500,
                message: "数据库错误".into(),
                data: None,
            });
        }
    };

    let current_rules = match state.db.count_by_uid(user.user_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("get_me {}: count_by_uid failed: {}", user.user_id, e);
            return Json(ApiResponse {
                code: 500,
                message: "数据库错误".into(),
                data: None,
            });
        }
    };

    Json(ApiResponse::success(UserSelf {
        id: u.id,
        username: u.username,
        admin: u.admin,
        current_rules,
        traffic_used: u.traffic_used,
        registered_at: u.created_at,
        must_change_password: u.must_change_password,
    }))
}

/// Change the calling user's own password.
pub async fn change_password(
    user: crate::api::middleware::AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Json<ApiResponse<()>> {
    if let Err(e) = validate_password(&req.new_password) {
        return Json(err(
            400,
            match e {
                PasswordValidationError::TooShort => "New password must be at least 8 characters",
                PasswordValidationError::TooLong => "New password must be at most 72 bytes",
            },
        ));
    }

    let current_hash = match state.db.find_password_by_id(user.user_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return Json(err(404, "用户不存在")),
        Err(e) => {
            tracing::error!(
                "change_password {}: find_password_by_id failed: {}",
                user.user_id,
                e
            );
            return Json(err(500, "数据库错误"));
        }
    };

    if CHANGE_PASSWORD_LIMITER.hit(&user.user_id) {
        return Json(err(429, "尝试次数过多，请一分钟后再试"));
    }

    let current_password = req.current_password.clone();
    match run_bcrypt(move || verify_password(&current_password, &current_hash)).await {
        None => return busy(),
        Some(false) => return Json(err(401, "Current password is incorrect")),
        Some(true) => {}
    }

    let new_password = req.new_password.clone();
    let new_hash = match run_bcrypt(move || hash_password(&new_password)).await {
        None => return busy(),
        Some(Ok(h)) => h,
        Some(Err(e)) => return Json(err(500, format!("Failed to hash password: {}", e))),
    };

    match state.db.change_own_password(user.user_id, &new_hash).await {
        Ok(_) => {
            tracing::info!(
                "user {} changed their password (sessions revoked)",
                user.user_id
            );
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!(
                "change_password {}: change_own_password failed: {}",
                user.user_id,
                e
            );
            Json(err(500, "数据库错误"))
        }
    }
}
