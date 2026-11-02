use crate::api::middleware::AuthUser;
use crate::api::AppState;
use axum::{extract::State, Json};
use relay_shared::protocol::ApiResponse;

/// GET /api/v1/nodes/live-rates — each node's latest pushed NIC rate,
/// for the node-status page to poll while it is open.
pub async fn list_live_rates(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<relay_shared::protocol::NodeLiveRate>>> {
    let rates = state.node_connections.live_rates().await;
    Json(ApiResponse::success(rates))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[tokio::test]
    async fn list_live_rates_returns_all_connected_node_rates() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let node_connections = NodeConnections::new();
        for gid in [10, 11] {
            let (conn, rx) = node_connections
                .register(gid, Some(format!("n{gid}")))
                .await;
            std::mem::forget(rx);
            node_connections
                .record_rate(gid, conn, gid as u64 * 1000, 1)
                .await;
        }
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool)),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
            },
            release_cache: ReleaseCache::new(),
            node_connections,
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        };
        let resp = list_live_rates(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
        )
        .await;
        assert_eq!(resp.0.code, 0);
        let seen: Vec<i64> = resp.0.data.unwrap().iter().map(|r| r.group_id).collect();
        assert_eq!(seen, vec![10, 11]);
    }
}
