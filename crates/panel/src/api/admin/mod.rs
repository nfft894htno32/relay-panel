use relay_shared::protocol::ApiResponse;
use serde::Serialize;

mod auth;
mod groups;
mod nodes;
mod password;
mod rules;

pub use groups::*;
pub use password::*;
pub use rules::*;

/// A user's view of THEIR OWN account (GET /user/me).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserSelf {
    pub id: i64,
    pub username: String,
    pub admin: bool,
    pub current_rules: i64,
    pub traffic_used: i64,
    pub registered_at: String,
    pub must_change_password: bool,
}

fn err<T: Serialize, S: Into<String>>(code: i32, msg: S) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: msg.into(),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        batch_update_rule_rate_limits, change_password, create_group, create_rule, delete_group,
        delete_rule, get_me, list_groups, list_rules, reset_rule_traffic, update_group,
        update_rule, ChangePasswordRequest, ListRulesQuery,
    };
    use crate::api::middleware::{AdminOnly, AuthUser};
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::api::AppState;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::extract::{Path, Query, State};
    use axum::Json;
    use relay_shared::protocol::{
        BatchUpdateRateLimitsRequest, CreateGroupRequest, CreateRuleRequest, GroupType,
        LoadBalanceStrategy, Protocol, ProxyProtocolVersion, UpdateGroupRequest, UpdateRuleRequest,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::sync::Arc;

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect memory db");
        sqlx::query(SCHEMA_SQL)
            .execute(&pool)
            .await
            .expect("create schema");
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
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
            node_connections: NodeConnections::new(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        (state, pool)
    }

    async fn add_group(pool: &SqlitePool, id: i64, uid: i64, name: &str) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, 'in', ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(format!("token-{id}-{uid}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_rule_and_group(pool: &SqlitePool) {
        add_group(pool, 20, 1, "gin").await;
        sqlx::query(
            "INSERT INTO forward_rules (id, name, uid, paused, listen_port, protocol, \
             device_group_in, target_addr, target_port) \
             VALUES (200, 'test-rule', 1, 0, 12000, 'tcp', 20, '127.0.0.1', 80)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn expect_group_pushes(
        state: &AppState,
        group_id: i64,
        expected: usize,
        f: impl std::future::Future<Output = ()>,
    ) {
        let (_id, mut rx) = state.node_connections.register(group_id, None).await;
        f.await;
        let mut n = 0;
        for _ in 0..20 {
            while rx.try_recv().is_ok() {
                n += 1;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            n, expected,
            "expected {expected} config_changed pushes on group {group_id}, got {n}"
        );
    }

    #[tokio::test]
    async fn change_password_requires_current_password_and_updates_password() {
        let (state, pool) = test_state().await;
        let old_password = "old-password-1";
        let old_hash = bcrypt::hash(old_password, 4).unwrap();
        sqlx::query("UPDATE users SET password = ? WHERE id = 1")
            .bind(&old_hash)
            .execute(&pool)
            .await
            .unwrap();

        let Json(bad) = change_password(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: "wrong-password".into(),
                new_password: "new-password".into(),
            }),
        )
        .await;
        assert_eq!(bad.code, 401);

        let Json(ok) = change_password(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(ChangePasswordRequest {
                current_password: old_password.into(),
                new_password: "new-password".into(),
            }),
        )
        .await;
        assert_eq!(ok.code, 0, "password change should succeed: {}", ok.message);

        let (pw,): (String,) = sqlx::query_as("SELECT password FROM users WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(bcrypt::verify("new-password", &pw).unwrap());
    }

    #[tokio::test]
    async fn get_me_returns_admin_account_summary() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        let Json(resp) = get_me(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
        )
        .await;
        assert_eq!(resp.code, 0);
        let me = resp.data.unwrap();
        assert_eq!(me.id, 1);
        assert!(me.admin);
        assert_eq!(me.current_rules, 1);
    }

    #[tokio::test]
    async fn update_rule_nonexistent_returns_404_no_push() {
        let (state, _pool) = test_state().await;
        expect_group_pushes(&state, 20, 0, async {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(99999),
                Json(UpdateRuleRequest {
                    name: Some("x".into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 404);
        })
        .await;
    }

    #[tokio::test]
    async fn update_rule_existing_succeeds_and_pushes_to_group_once() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        expect_group_pushes(&state, 20, 1, async {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(200),
                Json(UpdateRuleRequest {
                    name: Some("renamed".into()),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 0, "{}", resp.message);
        })
        .await;
    }

    #[tokio::test]
    async fn update_rule_rejects_auto_restart_below_floor() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                auto_restart_minutes: Some(1),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            resp.code, 400,
            "1 minute must be rejected: {}",
            resp.message
        );

        for v in [0, relay_shared::models::MIN_AUTO_RESTART_MINUTES] {
            let Json(resp) = update_rule(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Path(200),
                Json(UpdateRuleRequest {
                    auto_restart_minutes: Some(v),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp.code, 0, "{} must be accepted: {}", v, resp.message);
        }
    }

    #[tokio::test]
    async fn update_rule_partial_conn_controls_does_not_clobber_the_other() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                auto_restart_minutes: Some(10),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let Json(resp) = update_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
            Json(UpdateRuleRequest {
                max_connections: Some(500),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);

        let (cap, restart): (i64, i64) = sqlx::query_as(
            "SELECT max_connections, auto_restart_minutes FROM forward_rules WHERE id = 200",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cap, 500, "the cap we set must be stored");
        assert_eq!(
            restart, 10,
            "setting only max_connections must NOT reset auto_restart_minutes to 0"
        );
    }

    #[tokio::test]
    async fn create_rule_persists_max_connections_auto_restart_and_sni() {
        let (state, pool) = test_state().await;
        add_group(&pool, 20, 1, "gin").await;

        let Json(r1) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                name: "sni-de01".into(),
                listen_port: Some(443),
                protocol: Protocol::Tcp,
                sni: Some("Region-DE01.Example.com".into()),
                device_group_in: 20,
                device_group_out: None,
                forward_mode: "direct".into(),
                target_addr: "10.0.0.1".into(),
                target_port: 443,
                targets: None,
                upload_limit_mbps: None,
                download_limit_mbps: None,
                per_ip_upload_limit_mbps: Some(80),
                per_ip_download_limit_mbps: Some(80),
                load_balance_strategy: LoadBalanceStrategy::First,
                proxy_protocol_send: ProxyProtocolVersion::Off,
                proxy_protocol_accept: false,
                proxy_protocol_trusted: String::new(),
                max_connections: Some(250),
                auto_restart_minutes: Some(15),
            }),
        )
        .await;
        assert_eq!(r1.code, 0, "{}", r1.message);

        // Second rule on SAME port 443 with different SNI must succeed!
        let Json(r2) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                name: "sni-de02".into(),
                listen_port: Some(443),
                protocol: Protocol::Tcp,
                sni: Some("region-de02.example.com".into()),
                device_group_in: 20,
                device_group_out: None,
                forward_mode: "direct".into(),
                target_addr: "10.0.0.2".into(),
                target_port: 443,
                targets: None,
                upload_limit_mbps: None,
                download_limit_mbps: None,
                per_ip_upload_limit_mbps: None,
                per_ip_download_limit_mbps: None,
                load_balance_strategy: LoadBalanceStrategy::First,
                proxy_protocol_send: ProxyProtocolVersion::Off,
                proxy_protocol_accept: false,
                proxy_protocol_trusted: String::new(),
                max_connections: Some(300),
                auto_restart_minutes: Some(0),
            }),
        )
        .await;
        assert_eq!(
            r2.code, 0,
            "second SNI rule on :443 should succeed: {}",
            r2.message
        );

        // Duplicate SNI on same port 443 must fail with 409!
        let Json(dup) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                name: "sni-dup".into(),
                listen_port: Some(443),
                protocol: Protocol::Tcp,
                sni: Some("region-de01.example.com".into()),
                device_group_in: 20,
                device_group_out: None,
                forward_mode: "direct".into(),
                target_addr: "10.0.0.3".into(),
                target_port: 443,
                targets: None,
                upload_limit_mbps: None,
                download_limit_mbps: None,
                per_ip_upload_limit_mbps: None,
                per_ip_download_limit_mbps: None,
                load_balance_strategy: LoadBalanceStrategy::First,
                proxy_protocol_send: ProxyProtocolVersion::Off,
                proxy_protocol_accept: false,
                proxy_protocol_trusted: String::new(),
                max_connections: None,
                auto_restart_minutes: None,
            }),
        )
        .await;
        assert_eq!(dup.code, 409, "duplicate SNI on same port must be 409");

        // Plain TCP rule (no SNI) on port 443 must also fail with 409 since SNI rules occupy 443!
        let Json(plain_conflict) = create_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Json(CreateRuleRequest {
                name: "plain-443".into(),
                listen_port: Some(443),
                protocol: Protocol::Tcp,
                sni: None,
                device_group_in: 20,
                device_group_out: None,
                forward_mode: "direct".into(),
                target_addr: "10.0.0.4".into(),
                target_port: 443,
                targets: None,
                upload_limit_mbps: None,
                download_limit_mbps: None,
                per_ip_upload_limit_mbps: None,
                per_ip_download_limit_mbps: None,
                load_balance_strategy: LoadBalanceStrategy::First,
                proxy_protocol_send: ProxyProtocolVersion::Off,
                proxy_protocol_accept: false,
                proxy_protocol_trusted: String::new(),
                max_connections: None,
                auto_restart_minutes: None,
            }),
        )
        .await;
        assert_eq!(plain_conflict.code, 409, "plain rule on SNI port must be 409");

        let Json(listed) = list_rules(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            Query(ListRulesQuery::default()),
            State(state),
        )
        .await;
        let rules = listed.data.unwrap();
        assert_eq!(rules.len(), 2);
        let de01 = rules.iter().find(|r| r.name == "sni-de01").unwrap();
        assert_eq!(de01.sni.as_deref(), Some("region-de01.example.com"));
        assert_eq!(de01.per_ip_upload_limit_mbps, 80);
        assert_eq!(de01.per_ip_download_limit_mbps, 80);
        assert_eq!(de01.max_connections, 250);
        assert_eq!(de01.auto_restart_minutes, 15);
    }

    #[tokio::test]
    async fn create_and_update_group_sni_settings() {
        let (state, _pool) = test_state().await;
        let Json(created) = create_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateGroupRequest {
                name: "Relay-HK".into(),
                group_type: GroupType::In,
                connect_host: "1.2.3.4".into(),
                port_range: "10000-20000".into(),
                sni_fallback_addr: Some("127.0.0.1:10443".into()),
                sni_loop_bypass_ips: Some("203.0.113.10, 198.51.100.20".into()),
            }),
        )
        .await;
        assert_eq!(created.code, 0, "{}", created.message);
        let g = created.data.unwrap();
        assert_eq!(g.sni_fallback_addr, "127.0.0.1:10443");
        assert_eq!(g.sni_loop_bypass_ips, "203.0.113.10,198.51.100.20");

        let Json(upd) = update_group(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(g.id),
            Json(UpdateGroupRequest {
                name: None,
                group_type: None,
                connect_host: None,
                port_range: None,
                sni_fallback_addr: Some("127.0.0.1:18443".into()),
                sni_loop_bypass_ips: Some("".into()),
            }),
        )
        .await;
        assert_eq!(upd.code, 0, "{}", upd.message);

        let Json(groups) = list_groups(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
        )
        .await;
        let updated = groups.data.unwrap().into_iter().find(|x| x.id == g.id).unwrap();
        assert_eq!(updated.sni_fallback_addr, "127.0.0.1:18443");
        assert_eq!(updated.sni_loop_bypass_ips, "");

        let Json(del) = delete_group(AdminOnly { user_id: 1 }, State(state), Path(g.id)).await;
        assert_eq!(del.code, 0);
    }

    #[tokio::test]
    async fn reset_and_delete_rule_work() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        sqlx::query("UPDATE forward_rules SET traffic_used = 500 WHERE id = 200")
            .execute(&pool)
            .await
            .unwrap();

        let Json(rst) = reset_rule_traffic(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
            Path(200),
        )
        .await;
        assert_eq!(rst.code, 0);

        let Json(del) = delete_rule(
            AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state),
            Path(200),
        )
        .await;
        assert_eq!(del.code, 0);
    }

    #[tokio::test]
    async fn batch_update_rate_limits_updates_selected_rules_preserves_untouched_fields_and_coalesces_pushes(
    ) {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        add_group(&pool, 21, 1, "gin2").await;
        sqlx::query("UPDATE forward_rules SET upload_limit_mbps = 500, download_limit_mbps = 600 WHERE id = 200")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules (id, name, uid, paused, listen_port, protocol, \
             device_group_in, target_addr, target_port, upload_limit_mbps, download_limit_mbps) \
             VALUES \
             (201, 'r2', 1, 0, 12001, 'tcp', 20, '127.0.0.1', 81, 1000, 1200), \
             (202, 'r3', 1, 0, 12002, 'tcp', 21, '127.0.0.1', 82, 300, 400)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (_id21, mut rx21) = state.node_connections.register(21, None).await;

        expect_group_pushes(&state, 20, 1, async {
            let Json(resp) = batch_update_rule_rate_limits(
                AuthUser {
                    user_id: 1,
                    admin: true,
                },
                State(state.clone()),
                Json(BatchUpdateRateLimitsRequest {
                    rule_ids: vec![200, 201, 201, 202, 99999],
                    upload_limit_mbps: None,
                    download_limit_mbps: None,
                    per_ip_upload_limit_mbps: Some(80),
                    per_ip_download_limit_mbps: Some(80),
                }),
            )
            .await;
            assert_eq!(resp.code, 0, "{}", resp.message);
            let data = resp.data.unwrap();
            assert_eq!(data.updated, 3);
            assert_eq!(data.not_found, vec![99999]);
        })
        .await;

        let mut g21_pushes = 0;
        while rx21.try_recv().is_ok() {
            g21_pushes += 1;
        }
        assert_eq!(g21_pushes, 1, "group 21 should receive 1 push");

        let rows: Vec<(i64, i32, i32, i32, i32)> = sqlx::query_as(
            "SELECT id, upload_limit_mbps, download_limit_mbps, per_ip_upload_limit_mbps, per_ip_download_limit_mbps \
             FROM forward_rules ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                (200, 500, 600, 80, 80),
                (201, 1000, 1200, 80, 80),
                (202, 300, 400, 80, 80),
            ]
        );
    }

    #[tokio::test]
    async fn batch_update_rate_limits_rejects_empty_and_negative_requests() {
        let (state, pool) = test_state().await;
        seed_rule_and_group(&pool).await;
        let admin = || AuthUser {
            user_id: 1,
            admin: true,
        };

        let Json(empty_ids) = batch_update_rule_rate_limits(
            admin(),
            State(state.clone()),
            Json(BatchUpdateRateLimitsRequest {
                rule_ids: vec![],
                upload_limit_mbps: Some(100),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(empty_ids.code, 400);

        let Json(no_fields) = batch_update_rule_rate_limits(
            admin(),
            State(state.clone()),
            Json(BatchUpdateRateLimitsRequest {
                rule_ids: vec![200],
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(no_fields.code, 400);

        let Json(neg_val) = batch_update_rule_rate_limits(
            admin(),
            State(state),
            Json(BatchUpdateRateLimitsRequest {
                rule_ids: vec![200],
                per_ip_download_limit_mbps: Some(-1),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(neg_val.code, 400);
    }
}
