use crate::api::auth_throttle::{
    client_ip, run_bcrypt, IP_LIMITER, MAX_LOGIN_PASSWORD, MAX_LOGIN_USERNAME, USERNAME_LIMITER,
};
use crate::api::AppState;
use crate::service::password::verify_password;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::{Extension, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use relay_shared::models::User;
use relay_shared::protocol::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn too_many() -> ApiResponse<LoginResponse> {
    ApiResponse {
        code: 429,
        message: "Too many login attempts. Please wait a minute and try again.".into(),
        data: None,
    }
}

fn busy<T: Serialize>() -> ApiResponse<T> {
    ApiResponse {
        code: 429,
        message: "The server is busy. Please try again in a moment.".into(),
        data: None,
    }
}

fn invalid_credentials() -> ApiResponse<LoginResponse> {
    ApiResponse {
        code: 401,
        message: "Invalid credentials".into(),
        data: None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64, // user id
    admin: bool,
    token_version: i64,
    exp: usize,
}

static DUMMY_HASH: &str = "$2b$12$TP5SNHPKxVJPX4LDVdMoUOyPDSwBf9JhE.WrdCmN5sMMhNhPLLsXm";

pub async fn login(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Json<ApiResponse<LoginResponse>> {
    if req.username.is_empty()
        || req.username.len() > MAX_LOGIN_USERNAME
        || req.password.len() > MAX_LOGIN_PASSWORD
    {
        return Json(invalid_credentials());
    }
    if let Some(ip) = client_ip(peer.map(|Extension(ConnectInfo(a))| a), &headers) {
        if IP_LIMITER.hit(&ip) {
            return Json(too_many());
        }
    }
    if USERNAME_LIMITER.hit(&req.username) {
        return Json(too_many());
    }

    let user: Option<User> = match state.db.find_by_username(&req.username).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("login: db lookup failed for {:?}: {}", req.username, e);
            None
        }
    };

    let hash = user
        .as_ref()
        .map_or_else(|| DUMMY_HASH.to_string(), |u| u.password.clone());
    let password = req.password.clone();
    let Some(ok) = run_bcrypt(move || verify_password(&password, &hash)).await else {
        return Json(busy());
    };
    let verified = ok && user.is_some();

    if verified {
        if let Some(user) = user {
            USERNAME_LIMITER.clear(&req.username);
            let claims = Claims {
                sub: user.id,
                admin: user.admin,
                token_version: user.token_version,
                exp: chrono::Utc::now().timestamp_millis() as usize / 1000 + 86400,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            )
            .unwrap_or_default();

            return Json(ApiResponse::success(LoginResponse {
                token,
                admin: user.admin,
            }));
        }
    }

    Json(invalid_credentials())
}

#[cfg(test)]
mod tests {
    use super::DUMMY_HASH;
    use std::str::FromStr;

    #[test]
    fn dummy_hash_costs_a_full_bcrypt() {
        let parts = bcrypt::HashParts::from_str(DUMMY_HASH).expect("a valid bcrypt hash");
        assert_eq!(parts.get_cost(), 12, "same cost as real password hashes");
        assert_eq!(
            bcrypt::verify("not-the-password", DUMMY_HASH).ok(),
            Some(false)
        );
    }
}
