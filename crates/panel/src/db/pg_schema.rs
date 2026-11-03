pub const PG_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    traffic_used BIGINT NOT NULL DEFAULT 0,
    admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    token_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_groups (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    group_type TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    uid BIGINT NOT NULL REFERENCES users(id),
    connect_host TEXT NOT NULL DEFAULT '',
    port_range TEXT NOT NULL DEFAULT '1-65535',
    fallback_group BIGINT REFERENCES device_groups(id),
    config TEXT NOT NULL DEFAULT '{}',
    capabilities TEXT NOT NULL DEFAULT '["tcp","udp"]',
    region TEXT,
    line_type TEXT,
    remark TEXT,
    sni_fallback_addr TEXT NOT NULL DEFAULT '127.0.0.1:10443',
    sni_loop_bypass_ips TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);

CREATE TABLE IF NOT EXISTS forward_rules (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    uid BIGINT NOT NULL REFERENCES users(id),
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    listen_port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    device_group_in BIGINT NOT NULL REFERENCES device_groups(id),
    device_group_out BIGINT REFERENCES device_groups(id),
    forward_mode TEXT NOT NULL DEFAULT 'direct',
    sni TEXT,
    target_addr TEXT NOT NULL DEFAULT '',
    target_port INTEGER NOT NULL DEFAULT 0,
    load_balance_strategy TEXT NOT NULL DEFAULT 'first',
    upload_limit_mbps INTEGER NOT NULL DEFAULT 0,
    download_limit_mbps INTEGER NOT NULL DEFAULT 0,
    per_ip_upload_limit_mbps INTEGER NOT NULL DEFAULT 0,
    per_ip_download_limit_mbps INTEGER NOT NULL DEFAULT 0,
    max_connections INTEGER NOT NULL DEFAULT 0,
    auto_restart_minutes INTEGER NOT NULL DEFAULT 0,
    proxy_protocol_send TEXT NOT NULL DEFAULT 'off',
    proxy_protocol_accept BOOLEAN NOT NULL DEFAULT FALSE,
    proxy_protocol_trusted TEXT NOT NULL DEFAULT '',
    config TEXT NOT NULL DEFAULT '{}',
    traffic_used BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);

CREATE TABLE IF NOT EXISTS forward_rule_targets (
    id BIGSERIAL PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES forward_rules(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    position INTEGER NOT NULL CHECK (position >= 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);

CREATE INDEX IF NOT EXISTS idx_forward_rule_targets_rule_position
    ON forward_rule_targets (rule_id, position);

CREATE TABLE IF NOT EXISTS statistics (
    id BIGSERIAL PRIMARY KEY,
    stat_type TEXT NOT NULL,
    stat_key TEXT NOT NULL,
    time TEXT NOT NULL,
    number BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_history (
    rule_id BIGINT NOT NULL,
    uid BIGINT NOT NULL,
    group_id BIGINT NOT NULL DEFAULT 0,
    hour_ts TEXT NOT NULL,
    real_upload BIGINT NOT NULL DEFAULT 0,
    real_download BIGINT NOT NULL DEFAULT 0,
    billed_total BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_traffic_history_uid ON traffic_history(uid, hour_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_history_hour ON traffic_history(hour_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_history_group ON traffic_history(group_id, hour_ts);

CREATE TABLE IF NOT EXISTS node_metrics_history (
    node_id TEXT NOT NULL,
    group_id BIGINT NOT NULL DEFAULT 0,
    hour_ts TEXT NOT NULL,
    samples BIGINT NOT NULL DEFAULT 0,
    cpu_sum DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_max DOUBLE PRECISION NOT NULL DEFAULT 0,
    mem_sum DOUBLE PRECISION NOT NULL DEFAULT 0,
    mem_max DOUBLE PRECISION NOT NULL DEFAULT 0,
    conn_sum BIGINT NOT NULL DEFAULT 0,
    conn_max BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, hour_ts)
);
CREATE INDEX IF NOT EXISTS idx_node_metrics_hour ON node_metrics_history(hour_ts);
CREATE INDEX IF NOT EXISTS idx_node_metrics_group ON node_metrics_history(group_id, hour_ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    actor_id BIGINT,
    actor_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, ts);

CREATE TABLE IF NOT EXISTS announcements (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'info',
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    published_at TEXT NOT NULL,
    expires_at TEXT,
    author_id BIGINT,
    author_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_announcements_published ON announcements(published_at);
CREATE INDEX IF NOT EXISTS idx_announcements_pinned ON announcements(pinned, published_at);

CREATE TABLE IF NOT EXISTS traffic_batches (
    group_id BIGINT NOT NULL,
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

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);

INSERT INTO users (id, username, password, admin)
VALUES (1, 'admin', '$2b$12$PLACEHOLDER_WILL_BE_HASHED_ON_INIT', TRUE)
ON CONFLICT (id) DO NOTHING;

SELECT setval(pg_get_serial_sequence('users', 'id'), (SELECT MAX(id) FROM users));

INSERT INTO schema_version (version) VALUES (1) ON CONFLICT (version) DO NOTHING;
"#;

pub const PG_SCHEMA_VERSION: i32 = 101;

pub fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut in_comment = false;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;

        if in_comment {
            if c == '\n' {
                in_comment = false;
                current.push(c);
            }
            i += 1;
            continue;
        }

        if in_string {
            current.push(c);
            if c == '\'' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '\'' {
                    current.push('\'');
                    i += 2;
                    continue;
                }
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '-' && i + 1 < bytes.len() && bytes[i + 1] as char == '-' {
            in_comment = true;
            i += 2;
            continue;
        }
        if c == '\'' {
            in_string = true;
            current.push(c);
            i += 1;
            continue;
        }
        if c == ';' {
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                statements.push(trimmed.to_string());
            }
            current.clear();
            i += 1;
            continue;
        }
        current.push(c);
        i += 1;
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        statements.push(trimmed.to_string());
    }
    statements
}

pub async fn apply_pg_schema(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for stmt in split_sql_statements(PG_SCHEMA_SQL) {
        sqlx::query(&stmt).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn run_pg_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let current: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(pool)
        .await?;

    if current >= PG_SCHEMA_VERSION {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    for stmt in [
        "ALTER TABLE device_groups ADD COLUMN IF NOT EXISTS sni_fallback_addr TEXT NOT NULL DEFAULT '127.0.0.1:10443'",
        "ALTER TABLE device_groups ADD COLUMN IF NOT EXISTS sni_loop_bypass_ips TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE device_groups ADD COLUMN IF NOT EXISTS sort_order INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS sni TEXT",
        "ALTER TABLE forward_rules ALTER COLUMN sni DROP NOT NULL",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS per_ip_upload_limit_mbps INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS per_ip_download_limit_mbps INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS max_connections INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS auto_restart_minutes INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS proxy_protocol_send TEXT NOT NULL DEFAULT 'off'",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS proxy_protocol_accept BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE forward_rules ADD COLUMN IF NOT EXISTS proxy_protocol_trusted TEXT NOT NULL DEFAULT ''",
        "DROP INDEX IF EXISTS idx_fr_port_tcp",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_tcp_raw ON forward_rules (device_group_in, listen_port) WHERE protocol IN ('tcp', 'tcp_udp') AND (sni IS NULL OR sni = '')",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_tcp_sni ON forward_rules (device_group_in, listen_port, sni) WHERE protocol IN ('tcp', 'tcp_udp') AND sni IS NOT NULL AND sni != ''",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_port_udp ON forward_rules (device_group_in, listen_port) WHERE protocol IN ('udp', 'tcp_udp')",
    ] {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT (version) DO NOTHING")
        .bind(PG_SCHEMA_VERSION)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(())
}
