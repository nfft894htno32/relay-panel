use crate::api::system::ReleaseCache;
use crate::config::Config;
use crate::db::repo::Repository;
use axum::Router;
use std::sync::Arc;

pub mod admin;
pub mod announcements;
pub mod audit;
pub mod auth;
pub mod auth_throttle;
pub mod diagnose;
pub mod geoip;
pub mod groups;
pub mod middleware;
pub mod node;
pub mod notify;
pub mod panel_update;
pub mod restart;
pub mod security_headers;
pub mod site;
pub mod stats;
pub mod system;
pub mod ws;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Repository>,
    pub config: Config,
    pub release_cache: ReleaseCache,
    pub node_connections: ws::NodeConnections,
    pub diagnose: diagnose::DiagnoseRegistry,
    pub geoip_in_flight: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        // Auth
        .route("/auth/login", axum::routing::post(auth::login))
        // Site announcements
        .route(
            "/user/announcements",
            axum::routing::get(announcements::list_for_user),
        )
        .route(
            "/user/announcements/active",
            axum::routing::get(announcements::active_for_user),
        )
        .route(
            "/user/announcements/latest-id",
            axum::routing::get(announcements::latest_id),
        )
        .route(
            "/admin/announcements",
            axum::routing::get(announcements::list_for_admin).post(announcements::create),
        )
        .route(
            "/admin/announcements/{id}",
            axum::routing::put(announcements::update).delete(announcements::delete),
        )
        // Site branding
        .route("/site", axum::routing::get(site::get_public_site))
        .route(
            "/user/site-notice",
            axum::routing::get(site::get_site_notice),
        )
        // Account & password
        .route("/user/password", axum::routing::put(admin::change_password))
        .route("/user/me", axum::routing::get(admin::get_me))
        // Rules
        .route(
            "/rules",
            axum::routing::get(admin::list_rules).post(admin::create_rule),
        )
        .route(
            "/rules/batch-rate-limits",
            axum::routing::post(admin::batch_update_rule_rate_limits),
        )
        .route(
            "/rules/{id}",
            axum::routing::put(admin::update_rule).delete(admin::delete_rule),
        )
        .route(
            "/rules/{id}/diagnose",
            axum::routing::post(diagnose::diagnose_rule),
        )
        .route(
            "/rules/{id}/restart",
            axum::routing::post(restart::restart_rule),
        )
        .route(
            "/rules/{id}/reset-traffic",
            axum::routing::post(admin::reset_rule_traffic),
        )
        // Device groups
        .route(
            "/groups",
            axum::routing::get(admin::list_groups).post(admin::create_group),
        )
        .route(
            "/groups/{id}",
            axum::routing::put(admin::update_group).delete(admin::delete_group),
        )
        .route("/groups/order", axum::routing::put(admin::reorder_groups))
        .route(
            "/groups/{id}/rotate-token",
            axum::routing::post(admin::rotate_group_token),
        )
        // Live NIC rates
        .route(
            "/nodes/live-rates",
            axum::routing::get(groups::list_live_rates),
        )
        // Site & notification settings
        .route(
            "/admin/settings/site",
            axum::routing::get(site::get_site_settings).put(site::update_site_settings),
        )
        .route(
            "/admin/settings/notify",
            axum::routing::get(notify::get_notify_settings).put(notify::update_notify_settings),
        )
        .route(
            "/admin/settings/notify/history",
            axum::routing::get(notify::get_notify_history),
        )
        .route(
            "/admin/settings/notify/test",
            axum::routing::post(notify::test_notify),
        )
        // Stats & monitoring
        .route("/stats", axum::routing::get(stats::get_stats))
        .route(
            "/stats/traffic",
            axum::routing::get(stats::get_traffic_history),
        )
        .route(
            "/stats/node-metrics",
            axum::routing::get(stats::get_node_metrics),
        )
        .route("/admin/audit-log", axum::routing::get(audit::get_audit_log))
        .route("/nodes", axum::routing::get(stats::get_node_status))
        .route(
            "/nodes/{group_id}",
            axum::routing::delete(stats::delete_node_status),
        )
        .route(
            "/nodes/{group_id}/label/{node_id}",
            axum::routing::put(stats::set_node_label),
        )
        .route(
            "/nodes/{group_id}/upgrade/{node_id}",
            axum::routing::post(stats::upgrade_node),
        )
        // System
        .route("/system/version", axum::routing::get(system::get_version))
        .route(
            "/system/panel-update",
            axum::routing::get(panel_update::get_panel_update)
                .post(panel_update::start_panel_update),
        )
        .route("/health", axum::routing::get(system::health))
        // WebSocket (node control channel)
        .route("/node/ws", axum::routing::get(ws::node_ws_handler))
        // Node (polled by relay-node binary)
        .route("/node/config", axum::routing::get(node::get_config))
        .route(
            "/node/report_traffic",
            axum::routing::post(node::report_traffic),
        )
        .route(
            "/node/report_status",
            axum::routing::post(node::report_status),
        )
        .route(
            "/node/diagnose_result",
            axum::routing::post(diagnose::receive_diagnose_result),
        )
        .route(
            "/node/upgrade_result",
            axum::routing::post(stats::receive_upgrade_result),
        )
}
