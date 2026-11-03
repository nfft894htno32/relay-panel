use super::PgRepository;
use crate::db::error::DbError;
use crate::db::pg_schema::{apply_pg_schema, run_pg_migrations};
use crate::db::repo::*;
use relay_shared::protocol::{RuleTargetRequest, TrafficEntry};
use sqlx::postgres::PgPoolOptions;

fn pg_url() -> Option<String> {
    std::env::var("TEST_PG_URL").ok().filter(|s| !s.is_empty())
}

fn replace_db_in_url(url: &str, new_db: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let new_base = match base.rsplit_once('/') {
        Some((head, _)) => format!("{}/{}", head, new_db),
        None => format!("{}/{}", base, new_db),
    };
    match query {
        Some(q) => format!("{}?{}", new_base, q),
        None => new_base,
    }
}

async fn repo(suffix: &str) -> Option<PgRepository> {
    let url = pg_url()?;
    let db_name = format!("test_pr2_{}", suffix);
    let admin_url = replace_db_in_url(&url, "postgres");

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect admin db");

    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
        .execute(&admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {}", db_name))
        .execute(&admin)
        .await
        .expect("create test db");
    admin.close().await;

    let test_url = replace_db_in_url(&url, &db_name);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&test_url)
        .await
        .expect("connect test db");
    apply_pg_schema(&pool).await.expect("apply schema");
    run_pg_migrations(&pool).await.expect("run migrations");

    Some(PgRepository::new(pool))
}

async fn cleanup(db: &PgRepository) {
    let _ = db.pool.close().await;
}

#[tokio::test]
async fn pg_apply_schema_seeds_baseline_version() {
    let Some(db) = repo("schema_version").await else {
        return;
    };
    let v: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(v, crate::db::pg_schema::PG_SCHEMA_VERSION);
    run_pg_migrations(&db.pool)
        .await
        .expect("baseline migrations must be a no-op");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_rule_create_full_supports_sni_multiplexing() {
    let Some(db) = repo("rule_sni").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (1, 'gin', 'in', 'tok-1', 1)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let id1 = db
        .create_rule_full(
            "sni-1",
            1,
            443,
            "tcp",
            Some("region-de01.example.com"),
            1,
            None,
            "direct",
            "10.0.0.1",
            443,
            &[RuleTargetRequest {
                host: "10.0.0.1".into(),
                port: 443,
                enabled: true,
            }],
            "first",
            0,
            0,
            80,
            80,
            200,
            15,
            &RuleProxyProtocol::default(),
        )
        .await
        .unwrap();

    let id2 = db
        .create_rule_full(
            "sni-2",
            1,
            443,
            "tcp",
            Some("region-de02.example.com"),
            1,
            None,
            "direct",
            "10.0.0.2",
            443,
            &[],
            "first",
            0,
            0,
            0,
            0,
            0,
            0,
            &RuleProxyProtocol::default(),
        )
        .await
        .unwrap();
    assert_ne!(id1, id2);

    let dup = db
        .create_rule_full(
            "sni-dup",
            1,
            443,
            "tcp",
            Some("region-de01.example.com"),
            1,
            None,
            "direct",
            "10.0.0.3",
            443,
            &[],
            "first",
            0,
            0,
            0,
            0,
            0,
            0,
            &RuleProxyProtocol::default(),
        )
        .await;
    assert!(matches!(dup, Err(DbError::PortConflict)));

    let _ = TrafficEntry {
        rule_id: id1,
        upload: 1,
        download: 1,
    };
    cleanup(&db).await;
}
