import { Table, Button, Modal, Form, Input, InputNumber, Select, Space, message, Popconfirm, Tag, Alert, Typography, Dropdown, Switch, Tabs, Spin, Tooltip } from 'antd';
import type { MenuProps } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, ApiOutlined, CopyOutlined, DownloadOutlined, UploadOutlined, PauseCircleOutlined, PlayCircleOutlined, DeleteOutlined, ArrowUpOutlined, ArrowDownOutlined, MedicineBoxOutlined, QuestionCircleOutlined, ThunderboltOutlined, SearchOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, ForwardRule, DeviceGroup, RuleTargetInput, DiagnoseResponse, NodeDiagnoseStatus, DiagnoseTargetResult, RestartResponse } from '../api/types';
import { MIN_AUTO_RESTART_MINUTES } from '../api/types';
import { useI18n } from '../i18n/context';
import { useTableScroll } from '../hooks/useIsMobile';
import { formatBytes } from '../utils/format';
import { useAuth } from '../auth/useAuth';
import HostSummary from '../components/HostSummary';
import { splitHosts } from '../utils/connectHosts';
import { moveRules } from '../utils/moveRules';
import type { MoveResult } from '../utils/moveRules';
import { asValidatedEntry, buildExportJSON, countUnexportable, exportFileLabel, mergeBulkTargets, parseDest, ruleTargets, validateImportEntry } from '../utils/rulesIO';
import type { TargetRow } from '../utils/rulesIO';

const { Text } = Typography;
const { TextArea } = Input;

function targetSummary(rule: ForwardRule): string {
  const targets = ruleTargets(rule).filter(t => t.enabled);
  const first = targets[0] ?? ruleTargets(rule)[0];
  if (!first) return '-';
  const suffix = targets.length > 1 ? ` (+${targets.length - 1})` : '';
  return `${first.host}:${first.port}${suffix}`;
}

function formTargets(values: { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }): RuleTargetInput[] {
  const targets = values.targets ?? [];
  return targets.map(t => ({ host: t.host?.trim() ?? '', port: Number(t.port), enabled: t.enabled !== false }));
}

function payloadWithTargets<T extends Record<string, unknown>>(values: T & { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }) {
  const targets = formTargets(values);
  if (targets.length < 1) {
    throw new Error('targets must have at least one entry');
  }
  const first = targets[0];
  return {
    ...values,
    target_addr: first.host,
    target_port: first.port,
    targets,
  };
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const RULE_PAGE_SIZES = [20, 50, 100, 200, 500];
const RULE_PAGE_SIZE_KEY = 'relaypanel_rules_page_size';

type RuleTab = 'basic' | 'forward';

const BASIC_TAB_FIELDS = new Set(['name', 'listen_port', 'protocol', 'sni', 'forward_mode', 'device_group_in']);

function tabOfFirstError(errorFields: { name: (string | number)[] }[]): RuleTab {
  const first = errorFields[0]?.name[0];
  return typeof first === 'string' && BASIC_TAB_FIELDS.has(first) ? 'basic' : 'forward';
}
function storedRulePageSize(): number {
  try {
    const v = Number(localStorage.getItem(RULE_PAGE_SIZE_KEY));
    return RULE_PAGE_SIZES.includes(v) ? v : 20;
  } catch {
    return 20;
  }
}

export default function Rules() {
  const { t } = useI18n();
  const tableScroll = useTableScroll();
  const [rulePageSize, setRulePageSize] = useState<number>(storedRulePageSize);
  const changeRulePageSize = (size: number) => {
    setRulePageSize(size);
    try { localStorage.setItem(RULE_PAGE_SIZE_KEY, String(size)); } catch { /* private mode */ }
  };
  const { isAdmin } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [rules, setRules] = useState<ForwardRule[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [listLoadFailed, setListLoadFailed] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [createTab, setCreateTab] = useState<RuleTab>('basic');
  const [editTab, setEditTab] = useState<RuleTab>('basic');
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importGroupId, setImportGroupId] = useState<number | undefined>(undefined);
  const [importResults, setImportResults] = useState<string[]>([]);
  const [editing, setEditing] = useState<ForwardRule | null>(null);
  const [loading, setLoading] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [diagnosing, setDiagnosing] = useState<ForwardRule | null>(null);
  const [diagnoseLoading, setDiagnoseLoading] = useState(false);
  const [diagnoseResult, setDiagnoseResult] = useState<DiagnoseResponse | null>(null);
  const selectedGroup: number | null = parseInt(searchParams.get('group') || '') || null;
  const ruleSearch = searchParams.get('q') || '';

  const setFilter = useCallback((key: 'group' | 'q', value: string | null) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const [selectedRowKeys, setSelectedRowKeys] = useState<number[]>([]);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveTarget, setMoveTarget] = useState<number | undefined>(undefined);
  const [moving, setMoving] = useState(false);
  const [moveResult, setMoveResult] = useState<MoveResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rulesRes, groupsRes] = await Promise.allSettled([
        api.get<unknown, ApiEnvelope<ForwardRule[]>>('/rules'),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
      ]);
      const rules = rulesRes.status === 'fulfilled' && rulesRes.value.code === 0
        ? rulesRes.value
        : null;
      const groups = groupsRes.status === 'fulfilled' && groupsRes.value.code === 0
        ? groupsRes.value
        : null;
      if (rules) setRules(rules.data || []);
      if (groups) setGroups(groups.data || []);
      setListLoadFailed(!rules || !groups);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const groupMap = useMemo(() => new Map(groups.map(g => [g.id, g])), [groups]);
  const groupInfo = useMemo(() => {
    const m = new Map<number, { name: string; connect_host: string }>();
    for (const g of groups) m.set(g.id, { name: g.name, connect_host: g.connect_host });
    return m;
  }, [groups]);

  const visibleRules = useMemo(() => {
    const q = ruleSearch.trim().toLowerCase();
    return rules.filter(r => {
      if (selectedGroup !== null && r.device_group_in !== selectedGroup) return false;
      if (!q) return true;
      if (r.name.toLowerCase().includes(q)) return true;
      if (r.sni && r.sni.toLowerCase().includes(q)) return true;
      if (String(r.listen_port).includes(q)) return true;
      return ruleTargets(r).some(
        tgt => tgt.host.toLowerCase().includes(q) || String(tgt.port).includes(q),
      );
    });
  }, [rules, selectedGroup, ruleSearch]);

  const handleCreate = async (values: {
    name: string; listen_port: number | null; protocol: string;
    sni?: string;
    device_group_in: number; device_group_out: number | null;
    forward_mode: string;
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    max_connections?: number;
    auto_restart_minutes?: number;
  }) => {
    if (formTargets(values).length < 1) {
      message.error(t('targetRequired'));
      return;
    }
    const payload = payloadWithTargets({
      ...values,
      listen_port: values.listen_port || null,
      sni: values.protocol === 'tcp' && values.sni?.trim() ? values.sni.trim() : null,
      forward_mode: 'direct',
      device_group_out: null,
      max_connections: values.max_connections ?? 0,
      auto_restart_minutes: values.auto_restart_minutes ?? 0,
    });
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>('/rules', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      load();
    } catch { message.error(t('failedCreateRule')); }
  };

  const handleEdit = (r: ForwardRule) => {
    setEditing(r);
    editForm.setFieldsValue({
      name: r.name, listen_port: r.listen_port, protocol: r.protocol,
      sni: r.sni ?? '',
      device_group_in: r.device_group_in,
      target_addr: r.target_addr, target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      max_connections: r.max_connections ?? 0,
      auto_restart_minutes: r.auto_restart_minutes ?? 0,
      proxy_protocol_send: r.proxy_protocol_send ?? 'off',
      proxy_protocol_accept: r.proxy_protocol_accept ?? false,
      proxy_protocol_trusted: r.proxy_protocol_trusted ?? '',
    });
    setEditTab('basic');
    setEditOpen(true);
  };

  const onSaveFailed = (setTab: (tab: RuleTab) => void) =>
    ({ errorFields }: { errorFields: { name: (string | number)[]; errors: string[] }[] }) => {
      if (errorFields.length === 0) return;
      setTab(tabOfFirstError(errorFields));
      message.error(errorFields[0].errors[0] || t('ruleFormInvalid'));
    };

  const handleCopy = (r: ForwardRule) => {
    createForm.setFieldsValue({
      name: `${r.name}-copy`,
      listen_port: null,
      protocol: r.protocol,
      sni: r.sni ?? '',
      device_group_in: r.device_group_in,
      target_addr: r.target_addr,
      target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      max_connections: r.max_connections ?? 0,
      auto_restart_minutes: r.auto_restart_minutes ?? 0,
      proxy_protocol_send: r.proxy_protocol_send ?? 'off',
      proxy_protocol_accept: r.proxy_protocol_accept ?? false,
      proxy_protocol_trusted: r.proxy_protocol_trusted ?? '',
    });
    setCreateTab('basic');
    setCreateOpen(true);
  };

  const notifyExported = (exported: ForwardRule[]) => {
    const skipped = countUnexportable(exported);
    if (skipped > 0) message.warning(t('exportedSkipped').replace('{count}', String(skipped)));
    else message.success(t('exported'));
  };

  const handleExportAll = () => {
    downloadText(`relaypanel-rules-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(rules));
    notifyExported(rules);
  };

  const handleExportFiltered = () => {
    if (visibleRules.length === 0) return;
    const label = selectedGroup === null
      ? 'filtered'
      : exportFileLabel(groupMap.get(selectedGroup)?.name ?? '') || `group-${selectedGroup}`;
    downloadText(
      `relaypanel-rules-${label}-${new Date().toISOString().slice(0, 10)}.json`,
      buildExportJSON(visibleRules),
    );
    notifyExported(visibleRules);
  };

  const handleExportSelected = () => {
    const selected = rules.filter(r => selectedRowKeys.includes(r.id));
    if (selected.length === 0) return;
    downloadText(`relaypanel-rules-selected-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(selected));
    notifyExported(selected);
  };

  const IMPORT_DEFAULTS = {
    protocol: 'tcp_udp' as const,
    forward_mode: 'direct' as const,
    load_balance_strategy: 'first' as const,
    upload_limit_mbps: 0,
    download_limit_mbps: 0,
  };
  const handleImport = async () => {
    if (!importGroupId) {
      message.error(t('selectInboundGroup'));
      return;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(importText); } catch {
      message.error(t('importInvalidJson')); return;
    }
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    if (entries.length === 0) {
      message.error(t('importInvalidFormat')); return;
    }
    const results: string[] = [];
    for (const e of entries) {
      const label = (typeof e === 'object' && e !== null && !Array.isArray(e))
        ? String((e as { name?: unknown })['name'] ?? '?')
        : '?';
      const err = validateImportEntry(e);
      if (err) { results.push(`❌ ${label}: ${err}`); continue; }
      const entry = asValidatedEntry(e);
      const targets = entry.dest.map(d => {
        const p = parseDest(d) ?? { host: '', port: 0 };
        return { host: p.host, port: p.port, enabled: true };
      });
      const first = targets[0];
      try {
        const res = await api.post<unknown, ApiEnvelope<null>>('/rules', {
          name: entry.name,
          listen_port: entry.listen_port,
          ...IMPORT_DEFAULTS,
          ...(entry.protocol ? { protocol: entry.protocol } : {}),
          ...(entry.sni ? { sni: entry.sni } : {}),
          device_group_in: importGroupId,
          target_addr: first.host,
          target_port: first.port,
          targets,
        });
        if (res.code === 0) results.push(`✅ ${entry.name}:${entry.listen_port}`);
        else results.push(`❌ ${entry.name}: ${res.message}`);
      } catch { results.push(`❌ ${entry.name}: network error`); }
    }
    if (results.length === 0) { message.error(t('importInvalidFormat')); return; }
    setImportResults(results);
    load();
  };
  const handleUpdate = async (values: {
    name?: string; listen_port?: number; protocol?: string;
    sni?: string;
    device_group_in?: number;
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    max_connections?: number;
    auto_restart_minutes?: number;
    proxy_protocol_send?: string;
    proxy_protocol_accept?: boolean;
    proxy_protocol_trusted?: string;
  }) => {
    if (!editing) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.listen_port !== undefined && values.listen_port !== editing.listen_port) payload.listen_port = values.listen_port;
    if (values.protocol !== undefined && values.protocol !== editing.protocol) payload.protocol = values.protocol;
    const effectiveProto = values.protocol ?? editing.protocol;
    if (values.sni !== undefined) {
      const nextSni = effectiveProto === 'tcp' ? (values.sni.trim() || '') : '';
      const prevSni = editing.sni ?? '';
      if (nextSni !== prevSni) {
        payload.sni = nextSni || null;
      }
    }
    if (values.device_group_in !== undefined && values.device_group_in !== editing.device_group_in) payload.device_group_in = values.device_group_in;
    const newTargets = formTargets(values);
    const oldTargets = ruleTargets(editing);
    if (JSON.stringify(newTargets) !== JSON.stringify(oldTargets)) {
      if (newTargets.length < 1) {
        message.error(t('targetRequired'));
        return;
      }
      const first = newTargets[0];
      payload.target_addr = first.host;
      payload.target_port = first.port;
      payload.targets = newTargets;
    }
    if (values.load_balance_strategy !== undefined && values.load_balance_strategy !== (editing.load_balance_strategy ?? 'first')) {
      payload.load_balance_strategy = values.load_balance_strategy;
    }
    const newUp = values.upload_limit_mbps ?? 0;
    const newDown = values.download_limit_mbps ?? 0;
    if (newUp !== (editing.upload_limit_mbps ?? 0) || newDown !== (editing.download_limit_mbps ?? 0)) {
      payload.upload_limit_mbps = newUp;
      payload.download_limit_mbps = newDown;
    }
    const newMaxConn = values.max_connections ?? 0;
    const newAutoRestart = values.auto_restart_minutes ?? 0;
    if (newMaxConn !== (editing.max_connections ?? 0) || newAutoRestart !== (editing.auto_restart_minutes ?? 0)) {
      payload.max_connections = newMaxConn;
      payload.auto_restart_minutes = newAutoRestart;
    }
    if (values.proxy_protocol_send !== undefined && values.proxy_protocol_send !== (editing.proxy_protocol_send ?? 'off')) {
      payload.proxy_protocol_send = values.proxy_protocol_send;
    }
    if (values.proxy_protocol_accept !== undefined && values.proxy_protocol_accept !== (editing.proxy_protocol_accept ?? false)) {
      payload.proxy_protocol_accept = values.proxy_protocol_accept;
    }
    if (values.proxy_protocol_trusted !== undefined && values.proxy_protocol_trusted.trim() !== (editing.proxy_protocol_trusted ?? '')) {
      payload.proxy_protocol_trusted = values.proxy_protocol_trusted.trim();
    }
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleUpdated'));
      setEditOpen(false);
      load();
    } catch { message.error(t('failedUpdateRule')); }
  };

  const handleDelete = async (id: number) => {
    // v1.2.12: the API reports errors as HTTP 200 + code != 0; this used to
    // say "deleted" regardless.
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/rules/${id}`);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleDeleted'));
    } catch { message.error(t('failedDeleteRule')); return; }
    load();
  };

  const handleBatchDelete = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    // v1.0.9: tally per-rule success/failure instead of assuming Promise.all
    // means everything worked — a delete can fail (e.g. 404/permission) and the
    // old code still reported the full count as deleted.
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.delete<unknown, ApiEnvelope<null>>(`/rules/${id}`);
        return res.code === 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success(t('batchDeleteSuccess').replace('{count}', String(ok)));
    } else {
      message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
    }
    setSelectedRowKeys([]);
    load();
  };

  /** v1.0.7: batch pause/resume. Each rule goes through PUT /rules/{id}
   *  {paused}. Resume can be rejected per-rule (403) when the rule points at a
   *  device group the user is no longer authorized for, so we tally ok/fail
   *  instead of assuming success. */
  const handleBatchSetPaused = async (paused: boolean) => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${id}`, { paused });
        return res.code === 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success((paused ? t('batchPauseSuccess') : t('batchResumeSuccess')).replace('{count}', String(ok)));
    } else {
      message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
    }
    setSelectedRowKeys([]);
    load();
  };

  /** Move the selected rules to another inbound group. A rule whose listen port
   *  is already taken there is skipped and reported (see utils/moveRules). */
  const handleBatchMove = async () => {
    if (moveTarget == null) return;
    const chosen = rules.filter(r => selectedRowKeys.includes(r.id));
    if (chosen.length === 0) return;
    setMoving(true);
    try {
      const result = await moveRules(chosen, moveTarget, (url, body) =>
        api.put<unknown, ApiEnvelope<null>>(url, body));
      setMoveResult(result);
      setMoveOpen(false);
      setSelectedRowKeys([]);
      load();
    } finally {
      setMoving(false);
    }
  };

  /** v1.2.0: restart one rule — drop its live connections and rebuild its
   *  listeners on every node of its inbound group. The rule's paused state is
   *  untouched; this is not a pause/resume round-trip.
   *
   *  `restarted` (nodes actually reached) drives the message rather than the
   *  HTTP code: the request can succeed while restarting nothing, e.g. every
   *  node is too old to understand the command. Reporting that as success would
   *  hide exactly the case the user needs to act on. */
  const handleRestart = async (r: ForwardRule) => {
    try {
      const res = await api.post<unknown, ApiEnvelope<RestartResponse>>(`/rules/${r.id}/restart`, {});
      if (res.code !== 0) {
        message.error(res.message || t('restartFailed'));
        return;
      }
      const data = res.data;
      const outdated = (data?.nodes ?? []).filter(n => n.state === 'unsupported').length;
      const offline = (data?.nodes ?? []).filter(n => n.state === 'control_channel_offline').length;
      if ((data?.restarted ?? 0) > 0) {
        let msg = t('restartSuccess').replace('{count}', String(data?.restarted ?? 0));
        if (outdated > 0) msg += ` ${t('restartOutdatedSuffix').replace('{count}', String(outdated))}`;
        if (offline > 0) msg += ` ${t('restartOfflineSuffix').replace('{count}', String(offline))}`;
        if (outdated > 0 || offline > 0) message.warning(msg);
        else message.success(msg);
      } else if (outdated > 0) {
        message.warning(t('restartAllOutdated').replace('{count}', String(outdated)));
      } else if (offline > 0) {
        message.warning(t('restartAllOffline').replace('{count}', String(offline)));
      } else {
        message.warning(t('restartNoNodes'));
      }
    } catch {
      message.error(t('restartFailed'));
    }
  };

  /** v1.2.0: batch restart. Per-rule POST like batch pause/resume — there is no
   *  bulk endpoint. A rule can fail individually (paused → 400, or not owned →
   *  404), so tally ok/fail rather than assuming Promise.all means success. */
  const handleBatchRestart = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.post<unknown, ApiEnvelope<RestartResponse>>(`/rules/${id}/restart`, {});
        // Reaching zero nodes is not a success worth reporting as one.
        return res.code === 0 && (res.data?.restarted ?? 0) > 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success(t('batchRestartSuccess').replace('{count}', String(ok)));
    } else {
      // NOT batchPartial: that message blames "unauthorized lines can't be
      // resumed", which is the batch-resume failure mode and has nothing to do
      // with a restart. A restart fails when the rule is paused or every node is
      // old/offline — say that instead of pointing at the wrong cause.
      message.warning(
        t('batchRestartPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail))
      );
    }
    setSelectedRowKeys([]);
  };

  /** v1.2.15: batch reset of the selected rules' own traffic counters, one
   *  POST per rule like batch restart. Only the rules' statistic: the owners'
   *  quota is counted separately and does not move. */
  const handleBatchResetTraffic = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.post<unknown, ApiEnvelope<null>>(`/rules/${id}/reset-traffic`, {});
        return res.code === 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success(t('batchResetTrafficSuccess').replace('{count}', String(ok)));
    } else {
      message.warning(t('batchResetTrafficPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
    }
    setSelectedRowKeys([]);
    load();
  };

  /** v0.4.8: run a diagnosis for a rule. The panel fans the probe out to the
   *  rule's inbound-group nodes over WS and waits up to 8s for results. */
  const handleDiagnose = async (r: ForwardRule) => {
    setDiagnosing(r);
    setDiagnoseResult(null);
    setDiagnoseLoading(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<DiagnoseResponse>>(`/rules/${r.id}/diagnose`);
      if (res.code === 0 && res.data) {
        setDiagnoseResult(res.data);
      } else {
        message.error(res.message || t('diagnoseFailed'));
      }
    } catch {
      message.error(t('diagnoseFailed'));
    } finally {
      setDiagnoseLoading(false);
    }
  };

  /** Toggle a rule's paused state via the dedicated paused field on the update
   *  API. Paused rules stay in the DB but the node stops forwarding (get_config
   *  filters WHERE paused = 0). This is the only way to pause a rule — before
   *  v0.3.0 the paused column existed but had no API to flip it. */
  const handleTogglePause = async (r: ForwardRule) => {
    const nextPaused = !r.paused;
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${r.id}`, { paused: nextPaused });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(nextPaused ? t('rulePaused') : t('ruleResumed'));
      load();
    } catch { message.error(t('failedUpdateRule')); }
  };

  const protoTags = (p: string) => {
    if (p === 'tcp_udp') return <><Tag color="blue">TCP</Tag><Tag color="purple">UDP</Tag></>;
    if (p === 'udp') return <Tag color="purple">UDP</Tag>;
    return <Tag color="blue">TCP</Tag>;
  };

  const allColumns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    // v0.4.9: inbound group name. Hidden on small screens (responsive md+) so
    // the mobile view keeps the core columns. Lookup misses → "未知分组 (#ID)".
    {
      title: t('groupName'), key: 'group_name', width: 140, responsive: ['md' as const],
      render: (_: unknown, r: ForwardRule) => {
        const g = groupInfo.get(r.device_group_in);
        return g
          ? <Tag>{g.name}</Tag>
          : <Text type="secondary">{t('unknownGroup')} (#{r.device_group_in})</Text>;
      },
    },
    { title: t('name'), dataIndex: 'name', key: 'name' },
    {
      title: t('listenIp'), key: 'listen_ip', width: 160,
      render: (_: unknown, r: ForwardRule) => {
        // Several addresses read like several targets: first, "(+N)", all on hover.
        return (
          <HostSummary
            value={groupInfo.get(r.device_group_in)?.connect_host}
            empty={<Text type="secondary">{t('notConfigured')}</Text>}
          />
        );
      },
    },
    { title: t('listenPort'), dataIndex: 'listen_port', key: 'listen_port', render: (v: number) => <span className="rp-mono">{v}</span> },
    {
      title: t('protocol'), dataIndex: 'protocol', key: 'protocol',
      render: (p: string, r: ForwardRule) => (
        <Space size={4} wrap>
          {protoTags(p)}
          {r.sni && <Tag color="magenta">SNI: {r.sni}</Tag>}
          {r.proxy_protocol_send && r.proxy_protocol_send !== 'off' && (
            <Tooltip title={t('ppSendHint')}>
              <Tag color="geekblue">{t('ppTagSend').replace('{v}', r.proxy_protocol_send)}</Tag>
            </Tooltip>
          )}
          {r.proxy_protocol_accept && (
            <Tooltip title={t('ppAcceptHint')}>
              <Tag color="geekblue">{t('ppTagAccept')}</Tag>
            </Tooltip>
          )}
          {r.paused && <Tag color="red">{t('paused')}</Tag>}
        </Space>
      ),
    },
    {
      title: t('target'), key: 'target',
      render: (_: unknown, r: ForwardRule) => {
        // v1.0.9: a multi-target rule shows "first (+N)"; hovering lists every
        // enabled target IP so the admin can see the failover/round-robin pool.
        const all = ruleTargets(r).filter(t => t.enabled).map(t => `${t.host}:${t.port}`);
        const summary = <span className="rp-mono">{targetSummary(r)}</span>;
        return (
          <Space size={4} wrap>
            {all.length > 1 ? (
              <Tooltip title={<div>{all.map((s, i) => <div key={i} className="rp-mono">{s}</div>)}</div>}>
                {summary}
              </Tooltip>
            ) : summary}
            {r.load_balance_strategy && r.load_balance_strategy !== 'first' && (
              <Tag color="cyan">{r.load_balance_strategy === 'round_robin' ? t('lbRoundRobin') : t('lbFailover')}</Tag>
            )}
          </Space>
        );
      },
    },
    // v1.2.15: sortable, across every page, so the heaviest rules can be found.
    {
      title: t('traffic'), dataIndex: 'traffic_used', key: 'traffic_used',
      sorter: (a: ForwardRule, b: ForwardRule) => (a.traffic_used ?? 0) - (b.traffic_used ?? 0),
      render: (v: number) => <span style={{ whiteSpace: 'nowrap' }}>{formatBytes(v)}</span>,
    },
    {
      title: t('action'), key: 'action',
      render: (_: unknown, r: ForwardRule) => (
        <Space size="small" wrap style={{ minWidth: 250 }}>
          <Button
            size="small" type="text"
            icon={r.paused ? <PlayCircleOutlined /> : <PauseCircleOutlined />}
            aria-label={`${r.paused ? t('resume') : t('pause')} ${r.name}`}
            onClick={() => handleTogglePause(r)}
          >
            {r.paused ? t('resume') : t('pause')}
          </Button>
          <Button size="small" type="text" icon={<EditOutlined />} aria-label={`${t('edit')} ${r.name}`} onClick={() => handleEdit(r)}>{t('edit')}</Button>
          <Button size="small" type="text" icon={<CopyOutlined />} aria-label={`${t('copy')} ${r.name}`} onClick={() => handleCopy(r)}>{t('copy')}</Button>
          {/* v0.4.9: diagnosis is TCP-only — disable for pure-UDP rules. */}
          <Button size="small" type="text" icon={<MedicineBoxOutlined />} disabled={r.protocol === 'udp'} aria-label={`${t('diagnose')} ${r.name}`} onClick={() => handleDiagnose(r)} title={r.protocol === 'udp' ? t('diagnoseUdpUnsupported') : t('diagnose')}>{t('diagnose')}</Button>
          {/* v1.2.0: restart drops every live connection on this rule, so it is
              behind a confirm (diagnose is read-only and isn't). Disabled while
              paused — there are no listeners to restart. */}
          <Popconfirm
            title={t('restartConfirmTitle')}
            description={t('restartConfirmDesc')}
            onConfirm={() => handleRestart(r)}
            okButtonProps={{ danger: true }}
            disabled={r.paused}
          >
            <Button
              size="small"
              type="text"
              icon={<ThunderboltOutlined />}
              disabled={r.paused}
              aria-label={`${t('restart')} ${r.name}`}
              title={r.paused ? t('restartPausedHint') : t('restart')}
            >
              {t('restart')}
            </Button>
          </Popconfirm>
          <Popconfirm title={t('deleteRuleConfirm')} onConfirm={() => handleDelete(r.id)}>
            <Button danger size="small" type="text" aria-label={`${t('delete')} ${r.name}`}>{t('delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];
  const columns = allColumns;

  const inGroups = groups.filter(g => g.group_type === 'in');
  const allInGroups = inGroups;
  const protocolOptions = [
    { value: 'tcp_udp', label: t('tcpUdp') },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
  ];
  const strategyOptions = [
    { value: 'first', label: t('lbFirst') },
    { value: 'round_robin', label: t('lbRoundRobin') },
    { value: 'failover', label: t('lbFailover') },
  ];
  const isUdp = (p?: string) => p === 'udp' || p === 'tcp_udp';

  const createGroupId = Form.useWatch('device_group_in', createForm);
  const editGroupId = Form.useWatch('device_group_in', editForm);
  const createProto = Form.useWatch('protocol', createForm);
  const editProto = Form.useWatch('protocol', editForm);

  const hostForForm = (gid?: number) => {
    if (!gid) return '';
    return splitHosts(groupInfo.get(gid)?.connect_host).join(', ');
  };
  const renderHostHint = (gid?: number) => {
    const host = hostForForm(gid);
    return (
      <Alert
        type="info" showIcon style={{ marginBottom: 12, padding: '4px 12px' }}
        title={t('currentInboundHost').replace('{host}', host || t('notConfigured'))}
      />
    );
  };

  /** v1.2.0: connection cap + scheduled restart. Shared by the create and edit
   *  forms so the two can't drift. */
  const renderConnectionControls = (proto?: string) => {
    const udpOnly = proto === 'udp';
    return (
    <>
      <Form.Item
        name="max_connections"
        label={t('maxConnections')}
        extra={udpOnly ? t('maxConnectionsUdpUnsupported') : t('maxConnectionsHint')}
        initialValue={0}
      >
        <InputNumber min={0} style={{ width: '100%', maxWidth: 252 }} placeholder="0" disabled={udpOnly} />
      </Form.Item>
      <Form.Item
        name="auto_restart_minutes"
        label={t('autoRestart')}
        extra={t('autoRestartHint').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))}
        initialValue={0}
        rules={[{
          validator: (_, value) => {
            const v = Number(value ?? 0);
            if (v === 0 || v >= MIN_AUTO_RESTART_MINUTES) return Promise.resolve();
            return Promise.reject(new Error(
              t('autoRestartTooSmall').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))
            ));
          },
        }]}
      >
        <InputNumber min={0} style={{ width: '100%' }} addonAfter={t('minutes')} placeholder="0" />
      </Form.Item>
    </>
    );
  };

  const renderStrategyField = () => (
    <Form.Item
      name="load_balance_strategy"
      initialValue="first"
      label={
        <span>
          {t('loadBalanceStrategy')}{' '}
          <Tooltip
            overlayStyle={{ maxWidth: 360 }}
            title={
              <div style={{ fontSize: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{t('lbStrategyBlockTitle')}</div>
                <div>• {t('lbFirstDesc')}</div>
                <div>• {t('lbRoundRobinDesc')}</div>
                <div>• {t('lbFailoverDesc')}</div>
                <div style={{ marginTop: 8, opacity: 0.75 }}>{t('lbStrategyBlockFooter')}</div>
              </div>
            }
          >
            <QuestionCircleOutlined style={{ color: '#999' }} />
          </Tooltip>
        </span>
      }
    >
      <Select options={strategyOptions} style={{ maxWidth: 252 }} />
    </Form.Item>
  );

  const renderTargetsEditor = () => (
    <Form.List name="targets" initialValue={[{ host: '', port: undefined as unknown as number, enabled: true }]}>
      {(fields, { add, remove, move }) => (
        <Space orientation="vertical" style={{ width: '100%' }}>
          <Text strong>{t('targets')}</Text>
          {fields.map((field, index) => (
            <Space key={field.key} align="baseline" wrap>
              <Form.Item
                {...field}
                name={[field.name, 'host']}
                label={t('address')}
                rules={[{ required: true }]}
                style={{ marginBottom: 8 }}
              >
                <TargetHostInput fieldName={field.name} placeholder={t('targetAddressOrDest')} />
              </Form.Item>
              <Form.Item
                {...field}
                name={[field.name, 'port']}
                label={t('port')}
                rules={[
                  { required: true, message: t('targetPortInvalid') },
                  {
                    validator: (_, v) => {
                      if (v == null || v === '' || !Number.isFinite(Number(v)) || Number(v) < 1 || Number(v) > 65535) {
                        return Promise.reject(new Error(t('targetPortInvalid')));
                      }
                      return Promise.resolve();
                    },
                  },
                ]}
                style={{ marginBottom: 8 }}
              >
                <InputNumber min={1} max={65535} placeholder={t('targetPort')} style={{ width: 110 }} />
              </Form.Item>
              <Form.Item
                {...field}
                name={[field.name, 'enabled']}
                valuePropName="checked"
                initialValue={true}
                style={{ marginBottom: 8 }}
              >
                <Switch size="small" />
              </Form.Item>
              <Button size="small" icon={<ArrowUpOutlined />} aria-label={t('moveTargetUp')} disabled={index === 0} onClick={() => move(index, index - 1)} />
              <Button size="small" icon={<ArrowDownOutlined />} aria-label={t('moveTargetDown')} disabled={index === fields.length - 1} onClick={() => move(index, index + 1)} />
              <Button size="small" danger icon={<DeleteOutlined />} aria-label={t('deleteTarget')} disabled={fields.length <= 1} onClick={() => remove(field.name)} />
            </Space>
          ))}
          <Space wrap>
            <Button size="small" icon={<PlusOutlined />} onClick={() => add({ host: '', port: undefined as unknown as number, enabled: true })}>{t('addTarget')}</Button>
            <BulkTargetsButton t={t} />
          </Space>
        </Space>
      )}
    </Form.List>
  );

  // v1.2.12: offered once a group filter or a search narrows the list.
  const filterActive = selectedGroup !== null || ruleSearch.trim() !== '';
  const exportMenuItems: MenuProps['items'] = [
    ...(filterActive
      ? [{
        key: 'export-filtered',
        label: t('exportFiltered').replace('{count}', String(visibleRules.length)),
        icon: <DownloadOutlined />,
        disabled: visibleRules.length === 0,
        onClick: handleExportFiltered,
      }]
      : []),
    { key: 'export-all', label: t('exportAll'), icon: <DownloadOutlined />, onClick: handleExportAll },
    { key: 'import', label: t('import'), icon: <UploadOutlined />, onClick: () => setImportOpen(true) },
  ];

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><ApiOutlined /> {t('forwardRules')}</h2>
        <Space wrap>
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder={t('searchRulePlaceholder')}
            aria-label={t('searchRulePlaceholder')}
            value={ruleSearch}
            onChange={(e) => { setFilter('q', e.target.value); setSelectedRowKeys([]); }}
            style={{ width: 220 }}
          />
          <Select
            style={{ minWidth: 180 }}
            allowClear
            placeholder={t('filterByGroup')}
            aria-label={t('filterByGroup')}
            value={selectedGroup ?? undefined}
            onChange={(v: number | undefined) => { setFilter('group', v == null ? null : String(v)); setSelectedRowKeys([]); }}
            options={Array.from(new Set(rules.map(r => r.device_group_in)))
              .map(gid => {
                const g = groupMap.get(gid);
                return { value: gid, label: g ? g.name : `${t('unknownGroup')} (#${gid})` };
              })}
          />
          {selectedRowKeys.length > 0 && (
            <Button icon={<DownloadOutlined />} onClick={handleExportSelected}>
              {t('batchExport')} ({selectedRowKeys.length})
            </Button>
          )}
          {selectedRowKeys.length > 0 && (
            <Button icon={<PlayCircleOutlined />} onClick={() => handleBatchSetPaused(false)}>
              {t('batchResume')} ({selectedRowKeys.length})
            </Button>
          )}
          {selectedRowKeys.length > 0 && (
            <Button icon={<PauseCircleOutlined />} onClick={() => handleBatchSetPaused(true)}>
              {t('batchPause')} ({selectedRowKeys.length})
            </Button>
          )}
          {selectedRowKeys.length > 0 && (
            <Button onClick={() => { setMoveTarget(undefined); setMoveOpen(true); }}>
              {t('batchMove')} ({selectedRowKeys.length})
            </Button>
          )}
          {selectedRowKeys.length > 0 && (
            <Popconfirm
              title={t('batchRestartConfirm').replace('{count}', String(selectedRowKeys.length))}
              description={t('restartConfirmDesc')}
              onConfirm={handleBatchRestart}
              okButtonProps={{ danger: true }}
            >
              <Button icon={<ThunderboltOutlined />}>
                {t('batchRestart')} ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          {selectedRowKeys.length > 0 && (
            <Popconfirm
              title={t('batchResetTrafficConfirm').replace('{count}', String(selectedRowKeys.length))}
              description={t('batchResetTrafficDesc')}
              onConfirm={handleBatchResetTraffic}
            >
              <Button>
                {t('batchResetTraffic')} ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          {selectedRowKeys.length > 0 && (
            <Popconfirm
              title={t('batchDeleteConfirm').replace('{count}', String(selectedRowKeys.length))}
              onConfirm={handleBatchDelete}
              okButtonProps={{ danger: true }}
            >
              <Button danger icon={<DeleteOutlined />}>
                {t('batchDelete')} ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Dropdown menu={{ items: exportMenuItems }}>
            <Button icon={<DownloadOutlined />}>{t('exportImport')}</Button>
          </Dropdown>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { createForm.resetFields(); setCreateTab('basic'); setCreateOpen(true); }}>{t('addRule')}</Button>
        </Space>
      </div>
      {listLoadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('loadFailed')}
          description={t('loadFailedRetry')}
        />
      )}
      <Table
        rowSelection={{ selectedRowKeys, onChange: (keys) => setSelectedRowKeys(keys as number[]) }}
        dataSource={visibleRules} columns={columns} rowKey="id" loading={loading}
        pagination={{
          pageSize: rulePageSize,
          pageSizeOptions: RULE_PAGE_SIZES,
          showSizeChanger: true,
          onChange: (_page, size) => { if (size !== rulePageSize) changeRulePageSize(size); },
        }}
        scroll={tableScroll}
      />

      <Modal title={t('addRule')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} okText={t('create')} cancelText={t('cancel')} width={620}>
        <Form form={createForm} onFinish={handleCreate} onFinishFailed={onSaveFailed(setCreateTab)} layout="vertical" className="rp-rule-form">
          <Tabs activeKey={createTab} onChange={(k) => setCreateTab(k as RuleTab)} items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input placeholder="my-rule" /></Form.Item>
                {renderHostHint(createGroupId)}
                <Form.Item name="listen_port" label={t('listenPort')} extra={t('listenPortHint')}><InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="auto" /></Form.Item>
                <Form.Item name="protocol" label={t('protocol')} rules={[{ required: true }]} initialValue="tcp_udp"
                  extra={isUdp(createProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                  <Select
                    options={protocolOptions}
                  />
                </Form.Item>
                <Form.Item
                  name="sni"
                  label="SNI 域名分流 (单端口多域名复用)"
                  extra={createProto === 'tcp' ? '留空为普通独占端口；填写域名（如 region-de01.example.com 或 *.example.com）后可与其他 TCP+SNI 规则共用同一端口（如 443）' : '仅纯 TCP 协议支持 SNI 分流'}
                >
                  <Input placeholder="region-de01.example.com 或 *.example.com（留空为独占端口）" disabled={createProto !== 'tcp'} />
                </Form.Item>
                {/* v0.4.20: forward_mode always direct. */}
                <Form.Item name="forward_mode" hidden initialValue="direct"><Input /></Form.Item>
                <Form.Item name="device_group_in" label={t('inboundGroup')} rules={[{ required: true }]}>
                  <Select options={allInGroups.map(g => ({ value: g.id, label: g.name }))} placeholder={allInGroups.length ? t('select') : t('createGroupFirst')} />
                </Form.Item>
              </>),
            },
            {
              key: 'forward',
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor()}
                {renderStrategyField()}
                <Form.Item
                  label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                  extra={t('rateLimitsHint')}
                >
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                    <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                  </Space>
                </Form.Item>
                <ProxyProtocolFields proto={createProto} t={t} />
                {renderConnectionControls(createProto)}
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal title={t('editRule')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={() => editForm.submit()} okText={t('save')} cancelText={t('cancel')} width={620}>
        <Form form={editForm} onFinish={handleUpdate} onFinishFailed={onSaveFailed(setEditTab)} layout="vertical" className="rp-rule-form">
          <Tabs activeKey={editTab} onChange={(k) => setEditTab(k as RuleTab)} items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')}><Input /></Form.Item>
                {renderHostHint(editGroupId)}
                <Form.Item name="listen_port" label={t('listenPort')}><InputNumber min={1} max={65535} style={{ width: '100%' }} /></Form.Item>
                <Form.Item name="protocol" label={t('protocol')}
                  extra={isUdp(editProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                  <Select
                    options={protocolOptions}
                  />
                </Form.Item>
                <Form.Item
                  name="sni"
                  label="SNI 域名分流 (单端口多域名复用)"
                  extra={editProto === 'tcp' ? '留空为普通独占端口；填写域名（如 region-de01.example.com 或 *.example.com）后可与其他 TCP+SNI 规则共用同一端口（如 443）' : '仅纯 TCP 协议支持 SNI 分流'}
                >
                  <Input placeholder="region-de01.example.com 或 *.example.com（留空为独占端口）" disabled={editProto !== 'tcp'} />
                </Form.Item>
                {/* v0.4.20: forward_mode always direct. */}
                <Form.Item name="forward_mode" hidden initialValue="direct"><Input /></Form.Item>
                <Form.Item name="device_group_in" label={t('inboundGroup')}><Select options={allInGroups.map(g => ({ value: g.id, label: g.name }))} /></Form.Item>
              </>),
            },
            {
              key: 'forward',
              forceRender: true,
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor()}
                {renderStrategyField()}
                <Form.Item
                  label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                  extra={t('rateLimitsHint')}
                >
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                    <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                  </Space>
                </Form.Item>
                <ProxyProtocolFields proto={editProto} t={t} />
                {renderConnectionControls(editProto)}
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal title={t('import')} open={importOpen} onCancel={() => { setImportOpen(false); setImportText(''); setImportResults([]); }}
        onOk={importResults.length > 0 ? undefined : handleImport}
        okText={importResults.length > 0 ? t('close') : t('import')}
        cancelText={t('cancel')} width={600}
        footer={importResults.length > 0 ? <Button onClick={() => { setImportOpen(false); setImportText(''); setImportResults([]); }}>{t('close')}</Button> : undefined}
      >
        {importResults.length === 0 ? (
          <>
            <Form.Item label={t('selectInboundGroup')}>
              <Select aria-label={t('selectInboundGroup')} value={importGroupId} onChange={setImportGroupId}
                options={allInGroups.map(g => ({ value: g.id, label: `${g.name} (#${g.id})` }))}
                placeholder={t('selectDeviceGroups')} style={{ width: '100%' }} />
            </Form.Item>
            <Alert type="info" showIcon style={{ marginBottom: 12 }}
              title={t('importHint')} />
            <TextArea value={importText} onChange={e => setImportText(e.target.value)}
              rows={10} placeholder='[{"dest":["1.2.3.4:8080"],"listen_port":38446,"name":"SK5"}]' />
          </>
        ) : (
          <div style={{ maxHeight: 300, overflowY: 'auto' }} aria-live="polite" aria-label={t('import')}>
            {importResults.map((r, i) => <div key={i} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 13, lineHeight: 1.8 }}>{r}</div>)}
          </div>
        )}
      </Modal>

      <Modal
        open={moveOpen} title={t('batchMoveTitle').replace('{count}', String(selectedRowKeys.length))}
        onCancel={() => setMoveOpen(false)} onOk={handleBatchMove}
        okText={t('batchMoveRun')} cancelText={t('cancel')}
        okButtonProps={{ disabled: moveTarget == null, loading: moving }}
      >
        <Form.Item label={t('batchMoveTarget')}>
          <Select
            aria-label={t('batchMoveTarget')} value={moveTarget} onChange={setMoveTarget}
            options={allInGroups.map(g => ({ value: g.id, label: `${g.name} (#${g.id})` }))}
            placeholder={t('selectDeviceGroups')} style={{ width: '100%' }}
          />
        </Form.Item>
        <Alert type="info" showIcon title={t('batchMoveHint')} />
      </Modal>

      <Modal
        open={moveResult != null} title={t('batchMoveResultTitle')}
        onCancel={() => setMoveResult(null)} footer={<Button onClick={() => setMoveResult(null)}>{t('close')}</Button>}
      >
        {moveResult && (
          <div aria-live="polite">
            <Alert
              type={moveResult.moved.length > 0 ? 'success' : 'warning'} showIcon style={{ marginBottom: 12 }}
              title={moveResult.moved.length > 0
                ? t('batchMoveDone').replace('{count}', String(moveResult.moved.length))
                : t('batchMoveNothing')}
            />
            {moveResult.occupied.length > 0 && (
              <>
                <Text strong>{t('batchMoveOccupied').replace('{count}', String(moveResult.occupied.length))}</Text>
                <div style={{ maxHeight: 200, overflowY: 'auto', margin: '6px 0 12px' }}>
                  {moveResult.occupied.map(r => (
                    <div key={r.id} className="rp-mono">#{r.id} {r.name} — :{r.listen_port}</div>
                  ))}
                </div>
              </>
            )}
            {moveResult.failed.length > 0 && (
              <>
                <Text strong>{t('batchMoveFailed').replace('{count}', String(moveResult.failed.length))}</Text>
                <div style={{ maxHeight: 200, overflowY: 'auto', margin: '6px 0 12px' }}>
                  {moveResult.failed.map(f => (
                    <div key={f.rule.id} className="rp-mono">#{f.rule.id} {f.rule.name} — {f.message}</div>
                  ))}
                </div>
              </>
            )}
            {moveResult.alreadyThere.length > 0 && (
              <Text type="secondary">{t('batchMoveAlready').replace('{count}', String(moveResult.alreadyThere.length))}</Text>
            )}
          </div>
        )}
      </Modal>

      {/* v0.4.8: rule diagnosis modal — three sections: ingress node, target
          egress, and panel dispatch summary. */}
      <Modal
        title={diagnosing ? `${t('diagnoseTitle')} · ${diagnosing.name} (#${diagnosing.id})` : t('diagnoseTitle')}
        open={!!diagnosing}
        onCancel={() => { setDiagnosing(null); setDiagnoseResult(null); }}
        footer={<Button onClick={() => { setDiagnosing(null); setDiagnoseResult(null); }}>{t('close')}</Button>}
        width={720}
      >
        {diagnoseLoading ? (
          <div style={{ textAlign: 'center', padding: 32 }} aria-live="polite" aria-busy="true"><Spin tip={t('diagnoseRunning')} /></div>
        ) : diagnoseResult ? (
          <>
            <Alert type="info" showIcon style={{ marginBottom: 16 }}
              title={t('diagnoseScopeHint')} />
            {/* v0.4.14: only the relay-node's OWN TCP diagnosis is shown — the
                node's listener status + its node→target TCP connectivity/latency.
                The latency is the node→target TCP handshake time, NOT a client
                end-to-end latency. */}
            <Typography.Title level={5}>{t('diagnoseIngress')}</Typography.Title>
            {diagnoseResult.nodes.length === 0 ? (
              <Text type="secondary">{t('diagnoseNoNodes')}</Text>
            ) : (
              <Space orientation="vertical" style={{ width: '100%' }}>
                {diagnoseResult.nodes.map((n, i) => (
                  <DiagnoseNodeRow key={i} node={n} t={t} isAdmin={isAdmin} label={diagnoseResult.node_labels?.[n.node_id]} />
                ))}
              </Space>
            )}
          </>
        ) : (
          <Text type="secondary">{t('diagnoseIdle')}</Text>
        )}
      </Modal>
    </>
  );
}

/** Render one node's diagnosis row. v0.4.15: the visible label is
 *  "分组名 · 公网IP" (or "分组名 · IP 未上报"), NEVER the raw node_id. node_id is
 *  admin-only (tooltip for troubleshooting); a regular user sees just the
 *  label. Same shape across all four statuses; the status tag + details differ. */
function DiagnoseNodeRow({ node, t, isAdmin, label: nodeLabel }: { node: NodeDiagnoseStatus; t: (k: string) => string; isAdmin: boolean; label?: string }) {
  const tableScroll = useTableScroll();
  // The admin's name for the machine, when there is one the viewer may see, goes
  // first: "HK-1 · 分组名 · 公网IP".
  const label = `${nodeLabel ? `${nodeLabel} · ` : ''}${node.group_name || '-'} · ${node.public_ip || t('diagnoseIpMissing')}`;
  const labelText = <Text strong>{label}</Text>;
  // node_id is internal — only an admin gets the troubleshooting tooltip.
  const labelWithId = isAdmin
    ? <Tooltip title={t('diagnoseNodeIdLabel') + node.node_id}>{labelText}</Tooltip>
    : labelText;
  return (
    <div>
      <Space wrap align="center">
        {labelWithId}
        {node.status === 'result' && (
          <>
            <Tag color={node.listener_running ? 'green' : 'red'}>
              {node.listener_running ? t('diagnoseListenerRunning') : t('diagnoseListenerStopped')}
            </Tag>
            {node.listen_port ? <Text type="secondary">:{node.listen_port}</Text> : null}
            {node.protocol ? <Tag>{node.protocol}</Tag> : null}
            {node.transport ? <Tag>{node.transport}</Tag> : null}
          </>
        )}
        {node.status === 'unsupported' && (
          <Text type="warning">{t('diagnoseUnsupportedPrefix')}{node.node_version}{t('diagnoseUnsupportedSuffix')}</Text>
        )}
        {node.status === 'control_channel_offline' && (
          <Text type="secondary">{t('diagnoseOffline')}</Text>
        )}
        {node.status === 'timeout' && (
          <Tag color="orange">{t('diagnoseTimeout')}</Tag>
        )}
      </Space>
      {node.status === 'result' && node.results.length > 0 && (
        <Table<DiagnoseTargetResult> size="small" pagination={false} style={{ marginTop: 8 }} scroll={tableScroll}
          dataSource={node.results} rowKey="address"
          columns={[
            { title: t('diagnoseTarget'), dataIndex: 'address', key: 'address', render: (v: string) => <span className="rp-mono">{v}</span> },
            { title: t('diagnoseOutcome'), key: 'outcome', render: (_: unknown, r: DiagnoseTargetResult) => <ProbeOutcomeTag o={r.outcome} t={t} /> },
          ]}
        />
      )}
    </div>
  );
}

function ProbeOutcomeTag({ o, t }: { o: DiagnoseTargetResult['outcome']; t: (k: string) => string }) {
  // v0.4.9: 'route_only' variant removed — diagnosis is TCP-only.
  if (o === 'timeout') return <Tag color="orange">{t('diagnoseOutcomeTimeout')}</Tag>;
  if ('reachable' in o) return <Tag color="green">{t('diagnoseOutcomeReachable')} {o.reachable.elapsed_ms}ms</Tag>;
  if ('failed' in o) return <Tag color="red">{t('diagnoseOutcomeFailed')}: {o.failed.error}</Tag>;
  return <Tag>?</Tag>;
}

/** v1.2.15: the target host box also takes `host:port`. "1.2.3.4:443",
 *  "example.com:8443" or "[2001:db8::1]:443" splits on blur into the host and
 *  port boxes of the same row. A bare IPv6 address is left alone — the dest
 *  grammar needs brackets around one before a port. */
function TargetHostInput({ fieldName, value, onChange, placeholder }: {
  fieldName: number;
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
}) {
  const form = Form.useFormInstance();
  const split = () => {
    const parsed = parseDest((value ?? '').trim());
    if (!parsed) return;
    form.setFieldValue(['targets', fieldName, 'host'], parsed.host);
    form.setFieldValue(['targets', fieldName, 'port'], parsed.port);
    form.validateFields([['targets', fieldName, 'port']]).catch(() => {});
  };
  return (
    <Input value={value} onChange={onChange} onBlur={split} placeholder={placeholder}
      style={{ width: 'min(320px, 100vw - 100px)' }} />
  );
}

/** v1.2.15: paste many targets at once instead of one "add target" per row. */
function BulkTargetsButton({ t }: { t: (k: string) => string }) {
  const form = Form.useFormInstance();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const apply = () => {
    const current = (form.getFieldValue('targets') ?? []) as TargetRow[];
    const r = mergeBulkTargets(current, text);
    if (r.invalid.length > 0) {
      message.error(t('bulkTargetsInvalid').replace('{entries}', r.invalid.slice(0, 5).join(', ')));
      return;
    }
    form.setFieldValue('targets', r.targets);
    message.success(t('bulkTargetsAdded').replace('{added}', String(r.added)).replace('{skipped}', String(r.skipped)));
    setOpen(false);
    setText('');
  };
  return (
    <>
      <Button size="small" icon={<PlusOutlined />} onClick={() => setOpen(true)}>{t('bulkAddTargets')}</Button>
      <Modal title={t('bulkAddTargets')} open={open} onOk={apply} onCancel={() => setOpen(false)}
        okText={t('add')} cancelText={t('cancel')} destroyOnHidden>
        <Input.TextArea rows={8} value={text} onChange={(e) => setText(e.target.value)}
          placeholder={'1.2.3.4:443\nexample.com:8443\n[2001:db8::1]:443'} aria-label={t('bulkAddTargets')} />
        <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>{t('bulkAddTargetsHint')}</Text>
      </Modal>
    </>
  );
}

/** v1.2.15: a rule's PROXY protocol settings, in the create and edit forms.
 *  TCP only: on a UDP rule the controls are disabled and say why. The trusted
 *  sources only matter when accepting, so that box appears with the switch. */
function ProxyProtocolFields({ proto, t }: { proto?: string; t: (k: string) => string }) {
  const form = Form.useFormInstance();
  const accept = Form.useWatch('proxy_protocol_accept', form);
  const udpOnly = proto === 'udp';
  return (
    <>
      <Form.Item
        name="proxy_protocol_send"
        label={t('ppSend')}
        extra={udpOnly ? t('ppUdpUnsupported') : t('ppSendHint')}
        initialValue="off"
      >
        <Select
          disabled={udpOnly}
          style={{ maxWidth: 252 }}
          options={[
            { value: 'off', label: t('ppOff') },
            { value: 'v1', label: t('ppV1') },
            { value: 'v2', label: t('ppV2') },
          ]}
        />
      </Form.Item>
      <Form.Item
        name="proxy_protocol_accept"
        label={t('ppAccept')}
        extra={t('ppAcceptHint')}
        valuePropName="checked"
        initialValue={false}
      >
        <Switch disabled={udpOnly} />
      </Form.Item>
      {accept && !udpOnly && (
        <Form.Item name="proxy_protocol_trusted" label={t('ppTrusted')} extra={t('ppTrustedHint')} initialValue="">
          <Input placeholder="203.0.113.7, 10.0.0.0/8" />
        </Form.Item>
      )}
    </>
  );
}
