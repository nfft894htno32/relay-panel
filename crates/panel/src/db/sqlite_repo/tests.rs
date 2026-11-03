use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use crate::db::schema::SCHEMA_SQL;
use relay_shared::protocol::{RuleTargetRequest, TrafficEntry};
use sqlx::sqlite::SqlitePoolOptions;

async fn repo() -> SqliteRepository {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
    SqliteRepository::new(pool)
}

async fn seed_group(db: &SqliteRepository, gid: i64) {
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (?, 'gin', 'in', ?, 1)",
    )
    .bind(gid)
    .bind(format!("tok-{gid}"))
    .execute(&db.pool)
    .await
    .unwrap();
}

async fn seed_group_with_range(db: &SqliteRepository, gid: i64, range: &str) {
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid, port_range) \
         VALUES (?, 'gin', 'in', ?, 1, ?)",
    )
    .bind(gid)
    .bind(format!("tok-{gid}"))
    .bind(range)
    .execute(&db.pool)
    .await
    .unwrap();
}

// ── UserRepository ──

#[tokio::test]
async fn user_lookup_and_password_round_trip() {
    let db = repo().await;
    assert!(db.exists_by_id(1).await.unwrap());
    assert!(db.is_admin(1).await.unwrap());
    assert!(!db.exists_by_id(999_999).await.unwrap());
    assert!(!db.is_admin(999_999).await.unwrap());

    assert_eq!(db.count_placeholder_admin_password().await.unwrap(), 1);
    db.replace_placeholder_admin_password("$2b$12$realhash")
        .await
        .unwrap();
    assert_eq!(db.count_placeholder_admin_password().await.unwrap(), 0);

    let u = db.find_by_username("admin").await.unwrap().unwrap();
    assert_eq!(u.id, 1);
    assert!(u.admin);
    assert!(u.must_change_password);

    let (ver, must_change, is_admin) = db.find_auth_state_by_id(1).await.unwrap().unwrap();
    assert_eq!(ver, 0);
    assert!(must_change);
    assert!(is_admin);

    db.change_own_password(1, "$2b$12$newhash").await.unwrap();
    let (ver2, must_change2, _) = db.find_auth_state_by_id(1).await.unwrap().unwrap();
    assert_eq!(ver2, 1);
    assert!(!must_change2);
    assert_eq!(
        db.find_password_by_id(1).await.unwrap().as_deref(),
        Some("$2b$12$newhash")
    );
}

// ── GroupRepository ──

#[tokio::test]
async fn group_crud_and_sni_settings_round_trip() {
    let db = repo().await;
    db.insert_group(
        "HK-Entry",
        "in",
        "tok-hk",
        1,
        "1.2.3.4",
        "10000-20000",
        "127.0.0.1:10443",
        "203.0.113.10,198.51.100.20",
    )
    .await
    .unwrap();

    let g = db.find_by_token("tok-hk").await.unwrap().unwrap();
    assert_eq!(g.name, "HK-Entry");
    assert_eq!(g.sni_fallback_addr, "127.0.0.1:10443");
    assert_eq!(g.sni_loop_bypass_ips, "203.0.113.10,198.51.100.20");

    db.update_group_fields(
        g.id,
        &ResourceScope::All,
        Some("HK-Renamed"),
        None,
        None,
        None,
        Some("127.0.0.1:18443"),
        Some(""),
    )
    .await
    .unwrap();

    let g2 = GroupRepository::find_by_id(&db, g.id, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(g2.name, "HK-Renamed");
    assert_eq!(g2.sni_fallback_addr, "127.0.0.1:18443");
    assert_eq!(g2.sni_loop_bypass_ips, "");
}

// ── RuleRepository (including SNI multiplexing & batch targets) ──

#[tokio::test]
async fn rule_create_full_supports_sni_multiplexing_and_conn_controls() {
    let db = repo().await;
    seed_group(&db, 1).await;

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
            100,
            100,
            80,
            80,
            200,
            15,
            &RuleProxyProtocol::default(),
        )
        .await
        .expect("sni-1 created");

    // Second SNI rule on same port 443 with different SNI succeeds
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
            &[RuleTargetRequest {
                host: "10.0.0.2".into(),
                port: 443,
                enabled: true,
            }],
            "round_robin",
            0,
            0,
            0,
            0,
            0,
            0,
            &RuleProxyProtocol::default(),
        )
        .await
        .expect("sni-2 created");
    assert_ne!(id1, id2);

    // Duplicate SNI on same port 443 fails with PortConflict
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

    // Plain TCP rule (no SNI) on port 443 fails with PortConflict because SNI rules occupy 443
    let plain = db
        .create_rule_full(
            "plain-443",
            1,
            443,
            "tcp",
            None,
            1,
            None,
            "direct",
            "10.0.0.4",
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
    assert!(matches!(plain, Err(DbError::PortConflict)));

    // Pure UDP rule on port 443 succeeds (does not overlap TCP)
    let id_udp = db
        .create_rule_full(
            "udp-443",
            1,
            443,
            "udp",
            None,
            1,
            None,
            "direct",
            "10.0.0.5",
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
        .expect("udp-443 created");
    assert!(id_udp > 0);

    // Verify list_rules batch loads targets and fields
    let rules = db.list_rules(&ResourceScope::All).await.unwrap();
    assert_eq!(rules.len(), 3);
    let r1 = rules.iter().find(|r| r.id == id1).unwrap();
    assert_eq!(r1.sni.as_deref(), Some("region-de01.example.com"));
    assert_eq!(r1.per_ip_upload_limit_mbps, 80);
    assert_eq!(r1.per_ip_download_limit_mbps, 80);
    assert_eq!(r1.max_connections, 200);
    assert_eq!(r1.auto_restart_minutes, 15);
    assert_eq!(r1.targets.len(), 1);
    assert_eq!(r1.targets[0].host, "10.0.0.1");
    assert_eq!(r1.targets[0].position, 1);
}

#[tokio::test]
async fn legacy_not_null_sni_column_compatible_with_none_sni() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let legacy_schema = SCHEMA_SQL.replace("sni TEXT,", "sni TEXT NOT NULL DEFAULT '',");
    sqlx::query(&legacy_schema).execute(&pool).await.unwrap();
    let db = SqliteRepository::new(pool);
    seed_group(&db, 1).await;

    let rid = db
        .create_rule_full(
            "raw-tcp",
            1,
            8443,
            "tcp",
            None,
            1,
            None,
            "direct",
            "10.0.0.9",
            443,
            &[
                RuleTargetRequest {
                    host: "10.0.0.9".into(),
                    port: 443,
                    enabled: true,
                },
                RuleTargetRequest {
                    host: "10.0.0.10".into(),
                    port: 443,
                    enabled: true,
                },
            ],
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
        .expect("create with None sni on legacy NOT NULL sni column succeeds");

    let fetched = db
        .find_rule_by_id(rid, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.sni, None);
    assert_eq!(fetched.targets.len(), 2);
    assert_eq!(fetched.targets[0].position, 1);
    assert_eq!(fetched.targets[1].position, 2);

    // Update to set SNI, then clear back to None
    let mut upd = RuleUpdate::default();
    upd.sni = Some(Some("sub.example.com"));
    db.update_rule_full(rid, &ResourceScope::All, &upd)
        .await
        .unwrap();
    let fetched2 = db
        .find_rule_by_id(rid, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched2.sni.as_deref(), Some("sub.example.com"));

    let mut clear_upd = RuleUpdate::default();
    clear_upd.sni = Some(None);
    db.update_rule_full(rid, &ResourceScope::All, &clear_upd)
        .await
        .unwrap();
    let fetched3 = db
        .find_rule_by_id(rid, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched3.sni, None);
}

#[tokio::test]
async fn auto_assign_port_respects_group_range() {
    use crate::service::rules::auto_assign_port;
    let db = repo().await;
    seed_group_with_range(&db, 1, "50000-50000").await;
    let p = auto_assign_port(&db, 1, "tcp").await.unwrap();
    assert_eq!(p, 50000);
}

// ── TrafficRepository ──

#[tokio::test]
async fn apply_traffic_batch_counts_real_bytes_and_updates_stats() {
    let db = repo().await;
    seed_group(&db, 1).await;
    let rid = db
        .create_rule_full(
            "r1",
            1,
            20000,
            "tcp",
            None,
            1,
            None,
            "direct",
            "127.0.0.1",
            80,
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

    let res = db
        .apply_traffic_batch(
            1,
            &[TrafficEntry {
                rule_id: rid,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert_eq!(res, vec![TrafficEntryResult::Ok]);

    let r = db
        .find_rule_by_id(rid, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.traffic_used, 3000);
    let u = UserRepository::find_by_id(&db, 1).await.unwrap().unwrap();
    assert_eq!(u.traffic_used, 3000);
}
