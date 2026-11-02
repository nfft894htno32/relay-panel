// Shared types matching the backend (crates/shared/src/models.rs + protocol.rs).
// Keep these in sync when changing Rust structs.

export interface ApiEnvelope<T> {
  code: number;
  message: string;
  data: T | null;
}

export interface User {
  id: number;
  username: string;
  traffic_used: number;
  admin: boolean;
  created_at: string;
}

export interface ForwardRuleTarget {
  id: number;
  rule_id: number;
  host: string;
  port: number;
  position: number;
  enabled: boolean;
  created_at: string;
}

export interface RuleTargetInput {
  host: string;
  port: number;
  enabled: boolean;
}

export interface ForwardRule {
  id: number;
  name: string;
  uid: number;
  paused: boolean;
  listen_port: number;
  protocol: string;
  /** Optional TLS SNI hostname (or `*.example.com` wildcard) for single-port
   *  multi-SNI routing on TCP rules. Null/empty = raw port-level forwarding. */
  sni?: string | null;
  device_group_in: number;
  device_group_out: number | null;
  forward_mode: string;
  target_addr: string;
  target_port: number;
  targets?: ForwardRuleTarget[];
  /** Multi-target load-balancing strategy:
   *  "first" | "round_robin" | "failover". Defaults to "first". */
  load_balance_strategy?: string;
  /** Per-rule upload cap in Mbps (0 = unlimited). */
  upload_limit_mbps?: number;
  /** Per-rule download cap in Mbps (0 = unlimited). */
  download_limit_mbps?: number;
  /** Cap on concurrent TCP connections, counted PER NODE (0 = unlimited). */
  max_connections?: number;
  /** Restart the rule every N minutes to shed connections (0 = off).
   *  Non-zero values are floored at MIN_AUTO_RESTART_MINUTES by the API. */
  auto_restart_minutes?: number;
  /** PROXY protocol header sent to the target (TCP only). */
  proxy_protocol_send?: 'off' | 'v1' | 'v2';
  /** Expect a PROXY protocol header from the previous relay hop. */
  proxy_protocol_accept?: boolean;
  /** IPs/CIDRs allowed to send that header, comma separated; empty = any. */
  proxy_protocol_trusted?: string;
  config: string;
  traffic_used: number;
  status: string;
  created_at: string;
}

/** One traffic-history bucket. `bucket` is 'YYYY-MM-DD HH:00:00' UTC;
 *  the chart converts to the viewer's timezone. */
export interface TrafficHistoryBucket {
  bucket: string;
  group_id: number;
  group_name: string;
  real_upload: number;
  real_download: number;
  billed_total: number;
}

/** One node's metrics for one bucket. CPU/memory are 0..1 fractions;
 *  connections is a raw count. */
export interface NodeMetricBucket {
  bucket: string;
  node_id: string;
  group_id: number;
  group_name: string;
  cpu_avg: number;
  cpu_max: number;
  mem_avg: number;
  mem_max: number;
  conn_avg: number;
  conn_max: number;
}

export interface NodeMetricsResponse {
  granularity: string;
  since: string;
  buckets: NodeMetricBucket[];
  node_labels?: Record<string, string>;
}

export interface TrafficHistoryResponse {
  granularity: string;
  since: string;
  buckets: TrafficHistoryBucket[];
}

export interface NotifyConfigPublic {
  enabled: boolean;
  notify_offline: boolean;
  offline_alert_secs: number;
  notify_recovery: boolean;
  notify_version_outdated: boolean;
  repeat_alert_minutes: number;
  telegram_enabled: boolean;
  telegram_chat_id: string;
  telegram_bot_token_set: boolean;
  email_enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password_set: boolean;
  smtp_from: string;
  smtp_to: string;
  smtp_tls: boolean;
}

export interface NotifyHistoryEntry {
  id: string;
  created_at: string;
  event: 'offline' | 'offline_reminder' | 'recovery' | 'version_outdated' | 'test' | string;
  channel: 'telegram' | 'email' | string;
  status: 'sent' | 'failed' | string;
  node_key?: string | null;
  node_label?: string | null;
  detail: string;
}

export interface TestNotifyResult {
  ok: boolean;
  detail: string;
}

export const MIN_OFFLINE_ALERT_SECS = 60;

export interface Announcement {
  id: number;
  title: string;
  content: string;
  kind: string;
  pinned: boolean;
  published_at: string;
  expires_at: string | null;
  author_id: number | null;
  author_name: string;
}

export interface AnnouncementList {
  items: Announcement[];
  total: number;
}

export interface PublicSite {
  site_name: string;
  subtitle: string;
}

export interface SiteNotice {
  contact: string;
}

export interface SiteConfig extends PublicSite, SiteNotice {
  show_node_labels?: boolean;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor_id: number | null;
  actor_name: string;
  action: string;
  target_type: string;
  target_id: string;
  detail: string;
}

export interface AuditLogResponse {
  items: AuditEntry[];
  total: number;
}

export const MIN_AUTO_RESTART_MINUTES = 5;

export interface NodeRestartStatus {
  state: 'restarted' | 'unsupported' | 'control_channel_offline';
  node_id: string;
  group_name: string;
  public_ip?: string | null;
  node_version?: string | null;
}

export interface RestartResponse {
  rule_id: number;
  restarted: number;
  nodes: NodeRestartStatus[];
  node_labels?: Record<string, string>;
}

export interface DeviceGroup {
  id: number;
  name: string;
  group_type: string;
  token: string;
  uid: number;
  connect_host: string;
  port_range: string;
  fallback_group: number | null;
  config: string;
  /** Default fallback target when a shared SNI port receives non-TLS, missing
   *  SNI, unmatched SNI, or an anti-loop connection (default `127.0.0.1:10443`). */
  sni_fallback_addr?: string;
  /** Extra comma-separated IPs treated as anti-loop sources on shared SNI ports. */
  sni_loop_bypass_ips?: string;
  sort_order?: number;
  created_at: string;
}

export interface ListenerError {
  port: number;
  protocol: string;
  error: string;
}

export interface NodeDisk {
  mount: string;
  fs_type: string;
  total: number;
  used: number;
}

export interface NodeStatus {
  group_id: number;
  node_id?: string | null;
  label?: string | null;
  group_name?: string;
  group_sort_order?: number;
  node_version?: string | null;
  install_method?: string | null;
  config_protocol_version?: number | null;
  online?: boolean;
  ws_connected?: boolean | null;
  cpu: number;
  cpu_model?: string | null;
  cpu_cores?: number | null;
  mem: number;
  mem_total?: number | null;
  mem_used?: number | null;
  connections: number;
  uptime: number;
  process_uptime?: number | null;
  last_seen: string;
  public_ip?: string | null;
  public_ipv4?: string | null;
  public_ipv6?: string | null;
  ipv4_country_code?: string | null;
  ipv4_country_name?: string | null;
  ipv6_country_code?: string | null;
  ipv6_country_name?: string | null;
  disk_total?: number | null;
  disk_used?: number | null;
  disk_usage_percent?: number | null;
  disk_mount?: string | null;
  disks?: NodeDisk[] | null;
  upload_bps?: number | null;
  download_bps?: number | null;
  boot_upload_bytes?: number | null;
  boot_download_bytes?: number | null;
  network_interface?: string | null;
  listener_errors?: ListenerError[] | null;
}

export interface LoginResponse {
  token: string;
  admin: boolean;
}

export interface UserSelf {
  id: number;
  username: string;
  admin: boolean;
  current_rules: number;
  traffic_used: number;
  registered_at: string;
  must_change_password: boolean;
}

export type TargetProbeOutcome =
  | { reachable: { elapsed_ms: number } }
  | { failed: { error: string } }
  | 'timeout';

export interface DiagnoseTargetResult {
  address: string;
  outcome: TargetProbeOutcome;
}

export interface DiagnoseResult {
  type: string;
  request_id: string;
  rule_id: number;
  node_id: string;
  challenge?: string;
  listener_running: boolean;
  listen_port: number;
  protocol: string;
  transport: string;
  results: DiagnoseTargetResult[];
}

export type NodeDiagnoseStatus =
  | ({ status: 'result'; group_name: string; public_ip?: string | null } & DiagnoseResult)
  | { status: 'unsupported'; node_id: string; node_version: string; group_name: string; public_ip?: string | null }
  | { status: 'control_channel_offline'; node_id: string; group_name: string; public_ip?: string | null }
  | { status: 'timeout'; node_id: string; group_name: string; public_ip?: string | null };

export interface DiagnoseResponse {
  request_id: string;
  rule_id: number;
  nodes: NodeDiagnoseStatus[];
  node_labels?: Record<string, string>;
}

export interface NodeLiveRate {
  group_id: number;
  node_id: string;
  upload_bps: number;
  download_bps: number;
}

export interface NodeDisplayRow {
  group_id: number;
  group_name?: string | null;
  label?: string | null;
  group_sort_order?: number | null;
  node_id?: string | null;
  online?: boolean;
  ws_connected?: boolean | null;
  node_version?: string | null;
  install_method?: string | null;
  config_protocol_version?: number | null;
  connections?: number | null;
  cpu?: number | null;
  cpu_model?: string | null;
  cpu_cores?: number | null;
  mem?: number | null;
  mem_total?: number | null;
  mem_used?: number | null;
  uptime?: number | null;
  process_uptime?: number | null;
  last_seen?: string | null;
  public_ip?: string | null;
  public_ipv4?: string | null;
  public_ipv6?: string | null;
  ipv4_country_code?: string | null;
  ipv4_country_name?: string | null;
  ipv6_country_code?: string | null;
  ipv6_country_name?: string | null;
  disk_total?: number | null;
  disk_used?: number | null;
  disk_usage_percent?: number | null;
  disk_mount?: string | null;
  disks?: NodeDisk[] | null;
  upload_bps?: number | null;
  download_bps?: number | null;
  boot_upload_bytes?: number | null;
  boot_download_bytes?: number | null;
  network_interface?: string | null;
  listener_errors?: ListenerError[] | null;
  region?: string | null;
  line_type?: string | null;
}
