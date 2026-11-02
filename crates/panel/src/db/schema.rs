pub const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    traffic_used INTEGER NOT NULL DEFAULT 0,
    admin BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    group_type TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    uid INTEGER NOT NULL DEFAULT 1,
    connect_host TEXT NOT NULL DEFAULT '',
    port_range TEXT NOT NULL DEFAULT '1-65535',
    fallback_group INTEGER,
    config TEXT NOT NULL DEFAULT '{}',
    capabilities TEXT NOT NULL DEFAULT '[\"tcp\",\"udp\"]',
    region TEXT,
    line_type TEXT,
    remark TEXT,
    sni_fallback_addr TEXT NOT NULL DEFAULT '127.0.0.1:10443',
    sni_loop_bypass_ips TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uid INTEGER NOT NULL DEFAULT 1,
    paused BOOLEAN NOT NULL DEFAULT 0,
    listen_port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    device_group_in INTEGER NOT NULL,
    device_group_out INTEGER,
    forward_mode TEXT NOT NULL DEFAULT 'direct',
    sni TEXT,
    target_addr TEXT NOT NULL DEFAULT '',
    target_port INTEGER NOT NULL DEFAULT 0,
    load_balance_strategy TEXT NOT NULL DEFAULT 'first',
    upload_limit_mbps INTEGER NOT NULL DEFAULT 0,
    download_limit_mbps INTEGER NOT NULL DEFAULT 0,
    max_connections INTEGER NOT NULL DEFAULT 0,
    auto_restart_minutes INTEGER NOT NULL DEFAULT 0,
    proxy_protocol_send TEXT NOT NULL DEFAULT 'off',
    proxy_protocol_accept BOOLEAN NOT NULL DEFAULT 0,
    proxy_protocol_trusted TEXT NOT NULL DEFAULT '',
    config TEXT NOT NULL DEFAULT '{}',
    traffic_used INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS forward_rule_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES forward_rules(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 1),
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_forward_rule_targets_rule_pos
    ON forward_rule_targets (rule_id, position);

CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_type TEXT NOT NULL,
    stat_key TEXT NOT NULL,
    time TEXT NOT NULL,
    number INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_statistics_unique
    ON statistics (stat_type, stat_key, time);

CREATE TABLE IF NOT EXISTS traffic_history (
    rule_id INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    group_id INTEGER NOT NULL DEFAULT 0,
    hour_ts TEXT NOT NULL,
    real_upload INTEGER NOT NULL DEFAULT 0,
    real_download INTEGER NOT NULL DEFAULT 0,
    billed_total INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_traffic_history_uid ON traffic_history(uid, hour_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_history_hour ON traffic_history(hour_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_history_group ON traffic_history(group_id, hour_ts);

CREATE TABLE IF NOT EXISTS node_metrics_history (
    node_id TEXT NOT NULL,
    group_id INTEGER NOT NULL DEFAULT 0,
    hour_ts TEXT NOT NULL,
    samples INTEGER NOT NULL DEFAULT 0,
    cpu_sum REAL NOT NULL DEFAULT 0,
    cpu_max REAL NOT NULL DEFAULT 0,
    mem_sum REAL NOT NULL DEFAULT 0,
    mem_max REAL NOT NULL DEFAULT 0,
    conn_sum INTEGER NOT NULL DEFAULT 0,
    conn_max INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_node_metrics_hour ON node_metrics_history(hour_ts);
CREATE INDEX IF NOT EXISTS idx_node_metrics_group ON node_metrics_history(group_id, hour_ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor_id INTEGER,
    actor_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, ts);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'info',
    pinned INTEGER NOT NULL DEFAULT 0,
    published_at TEXT NOT NULL,
    expires_at TEXT,
    author_id INTEGER,
    author_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_announcements_published ON announcements(published_at);
CREATE INDEX IF NOT EXISTS idx_announcements_pinned ON announcements(pinned, published_at);

CREATE TABLE IF NOT EXISTS traffic_batches (
    group_id INTEGER NOT NULL,
    batch_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    confirmed_at TEXT,
    PRIMARY KEY (group_id, batch_id)
);
CREATE INDEX IF NOT EXISTS idx_traffic_batches_created ON traffic_batches(created_at);

CREATE TABLE IF NOT EXISTS kvs (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO users (id, username, password, admin)
VALUES (1, 'admin', '$2b$12$PLACEHOLDER_WILL_BE_HASHED_ON_INIT', 1);
";

/// Run idempotent SQLite migrations so an existing database upgrades cleanly to
/// the single-admin + multi-SNI schema.
pub async fn run_migrations(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    // Add SNI columns if missing on existing databases
    for alter in [
        "ALTER TABLE device_groups ADD COLUMN sni_fallback_addr TEXT NOT NULL DEFAULT '127.0.0.1:10443'",
        "ALTER TABLE device_groups ADD COLUMN sni_loop_bypass_ips TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE device_groups ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN sni TEXT",
        "ALTER TABLE forward_rules ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN auto_restart_minutes INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN proxy_protocol_send TEXT NOT NULL DEFAULT 'off'",
        "ALTER TABLE forward_rules ADD COLUMN proxy_protocol_accept BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN proxy_protocol_trusted TEXT NOT NULL DEFAULT ''",
    ] {
        let _ = sqlx::query(alter).execute(pool).await;
    }

    // Note: Do NOT drop legacy tables (plans, tunnel_profiles, orders, etc.) on
    // upgraded databases! Existing production SQLite tables (`users`,
    // `forward_rules`) retain `REFERENCES plans(id)` / `REFERENCES tunnel_profiles(id)`
    // in their table definitions, which would fail under `PRAGMA foreign_keys = ON`
    // if the referenced tables were dropped. Leaving legacy tables untouched also
    // guarantees non-destructive upgrades and effortless rollback.

    // Replace legacy single-TCP-per-port index with raw vs SNI partial unique indexes
    for idx in [
        "DROP INDEX IF EXISTS idx_fr_port_tcp",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_tcp_raw ON forward_rules (device_group_in, listen_port) WHERE protocol IN ('tcp', 'tcp_udp') AND (sni IS NULL OR sni = '')",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_tcp_sni ON forward_rules (device_group_in, listen_port, sni) WHERE protocol IN ('tcp', 'tcp_udp') AND sni IS NOT NULL AND sni != ''",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_udp ON forward_rules (device_group_in, listen_port) WHERE protocol IN ('udp', 'tcp_udp')",
    ] {
        sqlx::query(idx).execute(pool).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::db::init::init_db;
    use crate::db::repo::{
        GroupRepository, ResourceScope, RuleProxyProtocol, RuleRepository,
    };
    use crate::db::sqlite_repo::SqliteRepository;
    use relay_shared::protocol::RuleTargetRequest;

    #[tokio::test]
    async fn official_v1_2_20_production_db_upgrades_cleanly_with_foreign_keys_on() {
        let tmp = std::env::temp_dir().join(format!(
            "relay_upgrade_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let url = format!("sqlite:{}?mode=rwc", tmp.display());

        // 1. Seed a database shaped like official v1.2.20 (with plans, tunnel_profiles,
        //    FK references on users/forward_rules, and legacy idx_fr_port_tcp).
        {
            let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
            for stmt in [
                "CREATE TABLE plans (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)",
                "INSERT INTO plans (id, name) VALUES (1, 'Default Plan')",
                "CREATE TABLE tunnel_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)",
                "CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    balance TEXT NOT NULL DEFAULT '0',
                    plan_id INTEGER REFERENCES plans(id),
                    traffic_used INTEGER NOT NULL DEFAULT 0,
                    admin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    token_version INTEGER NOT NULL DEFAULT 0
                )",
                "INSERT INTO users (id, username, password, plan_id, admin) VALUES (1, 'admin', '$2b$12$existinghash', 1, 1)",
                "CREATE TABLE device_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    group_type TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    uid INTEGER NOT NULL REFERENCES users(id),
                    connect_host TEXT NOT NULL DEFAULT '',
                    port_range TEXT NOT NULL DEFAULT '1-65535',
                    fallback_group INTEGER REFERENCES device_groups(id),
                    config TEXT NOT NULL DEFAULT '{}',
                    capabilities TEXT NOT NULL DEFAULT '[\"tcp\",\"udp\"]',
                    region TEXT,
                    line_type TEXT,
                    remark TEXT,
                    rate REAL NOT NULL DEFAULT 1.0,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
                "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'Prod-Entry', 'in', 'prod-tok-1', 1)",
                "CREATE TABLE forward_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    uid INTEGER NOT NULL REFERENCES users(id),
                    paused BOOLEAN NOT NULL DEFAULT 0,
                    listen_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'tcp',
                    device_group_in INTEGER NOT NULL REFERENCES device_groups(id),
                    device_group_out INTEGER REFERENCES device_groups(id),
                    forward_mode TEXT NOT NULL DEFAULT 'direct',
                    tunnel_profile_id INTEGER REFERENCES tunnel_profiles(id),
                    target_addr TEXT NOT NULL DEFAULT '1.1.1.1',
                    target_port INTEGER NOT NULL DEFAULT 443,
                    load_balance_strategy TEXT NOT NULL DEFAULT 'first',
                    upload_limit_mbps INTEGER NOT NULL DEFAULT 0,
                    download_limit_mbps INTEGER NOT NULL DEFAULT 0,
                    max_connections INTEGER NOT NULL DEFAULT 0,
                    auto_restart_minutes INTEGER NOT NULL DEFAULT 0,
                    proxy_protocol_send TEXT NOT NULL DEFAULT 'off',
                    proxy_protocol_accept BOOLEAN NOT NULL DEFAULT 0,
                    proxy_protocol_trusted TEXT NOT NULL DEFAULT '',
                    config TEXT NOT NULL DEFAULT '{}',
                    traffic_used INTEGER NOT NULL DEFAULT 123456,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
                "CREATE UNIQUE INDEX idx_fr_port_tcp ON forward_rules (device_group_in, listen_port) WHERE protocol IN ('tcp', 'tcp_udp')",
                "INSERT INTO forward_rules (id, name, uid, listen_port, protocol, device_group_in, target_addr, target_port) VALUES (1, 'Existing-Rule', 1, 8443, 'tcp', 1, '1.1.1.1', 443)",
            ] {
                sqlx::query(stmt).execute(&pool).await.unwrap();
            }
            pool.close().await;
        }

        // 2. Run full init_db (SCHEMA_SQL + run_migrations + foreign_keys=ON)
        let pool = init_db(&url).await.expect("production DB must upgrade cleanly");
        let repo = SqliteRepository::new(pool.clone());

        // 3. Existing group and rule survive with defaults populated
        let groups = repo.list_groups(&ResourceScope::All).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].sni_fallback_addr, "127.0.0.1:10443");

        let rules = repo.list_rules(&ResourceScope::All).await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Existing-Rule");

        // 4. Creating new SNI rules on port 443 works with foreign_keys=ON
        let pp = RuleProxyProtocol::default();
        let r1 = repo
            .create_rule_full(
                "SNI-A",
                1,
                443,
                "tcp",
                Some("a.example.com"),
                1,
                None,
                "direct",
                "10.0.0.1",
                443,
                &[RuleTargetRequest {
                    host: "10.0.0.1".to_string(),
                    port: 443,
                    enabled: true,
                }],
                "first",
                0,
                0,
                0,
                0,
                &pp,
            )
            .await
            .expect("insert SNI rule A with FK enforcement on");
        let r2 = repo
            .create_rule_full(
                "SNI-B",
                1,
                443,
                "tcp",
                Some("b.example.com"),
                1,
                None,
                "direct",
                "10.0.0.2",
                443,
                &[RuleTargetRequest {
                    host: "10.0.0.2".to_string(),
                    port: 443,
                    enabled: true,
                }],
                "first",
                0,
                0,
                0,
                0,
                &pp,
            )
            .await
            .expect("insert SNI rule B on same port 443");
        assert_ne!(r1, r2);

        pool.close().await;
        let _ = std::fs::remove_file(&tmp);
    }
}
