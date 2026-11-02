// Service-layer assembly of a node's runtime config (`NodeConfigResponse`).

use std::collections::HashMap;

use relay_shared::models::ForwardRuleTarget;
use relay_shared::protocol::{build_listeners_for_rule, ListenerConfig, NodeConfigResponse};

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};

fn format_target(host: &str, port: i32) -> String {
    let trimmed = host.trim();
    if trimmed.contains(':') && !trimmed.starts_with('[') {
        format!("[{trimmed}]:{port}")
    } else {
        format!("{trimmed}:{port}")
    }
}

pub async fn build_node_config(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigResponse, DbError> {
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    let (sni_fallback_addr, sni_loop_bypass_ips) = match group {
        Some(g) => {
            let bypass: Vec<String> = g
                .sni_loop_bypass_ips
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (g.sni_fallback_addr, bypass)
        }
        None => ("127.0.0.1:10443".to_string(), Vec::new()),
    };

    let rules = db.list_active_for_config(group_id).await?;
    let rule_ids: Vec<i64> = rules.iter().map(|r| r.id).collect();
    let enabled_targets = db.list_enabled_targets_for_rules(&rule_ids).await?;

    let mut targets_by_rule: HashMap<i64, Vec<ForwardRuleTarget>> = HashMap::new();
    for t in enabled_targets {
        targets_by_rule.entry(t.rule_id).or_default().push(t);
    }

    let mut listeners: Vec<ListenerConfig> = Vec::with_capacity(rules.len());
    for rule in &rules {
        let targets: Vec<String> = match targets_by_rule.get(&rule.id) {
            Some(list) if !list.is_empty() => {
                list.iter().map(|t| format_target(&t.host, t.port)).collect()
            }
            _ => vec![format_target(&rule.target_addr, rule.target_port)],
        };
        for mut l in build_listeners_for_rule(rule, targets) {
            l.sni_fallback_addr = sni_fallback_addr.clone();
            l.sni_loop_bypass_ips = sni_loop_bypass_ips.clone();
            listeners.push(l);
        }
    }

    Ok(NodeConfigResponse { listeners })
}
