import { useEffect, useMemo, useRef, useState } from 'react';
import { Spin, Result, Empty, message, Typography, Space } from 'antd';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core';
import {
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { LineChartOutlined, ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';
import api from '../api/client';
import type { ApiEnvelope, NodeStatus, NodeDisplayRow, NodeLiveRate } from '../api/types';
import { useI18n } from '../i18n/context';
import { useAuth } from '../auth/useAuth';
import { useIsMobile } from '../hooks/useIsMobile';
import { NodeGroupSection } from '../components/nodes/NodeGroupSection';
import { SortableNodeGroupSection } from '../components/nodes/SortableNodeGroupSection';
import { NodeDetailDrawer } from '../components/nodes/NodeDetailDrawer';
import {
  hasGroupOrder,
  mergeVisibleOrder,
  moveGroup,
  stableGroupedRows,
  withGroupOrder,
} from '../components/nodes/sort';
import { rateSummary } from '../components/nodes/shared';
import { upgradableNodes } from '../components/nodes/upgrade';
import { UpgradeAllButton } from '../components/nodes/UpgradeAllButton';
import { UpgradeSlot } from '../components/nodes/UpgradeSlot';
import { formatBps, formatBytes } from '../utils/format';

type AnyNodeRow = NodeDisplayRow;

const LIVE_RATE_POLL_MS = 2000;

const liveKey = (groupId: number, nodeId: string) => `${groupId}:${nodeId}`;

interface VersionInfo {
  current_version: string;
  config_protocol_version?: number;
  latest_node_version?: string;
  node_version_check_failed?: boolean;
}

export default function NodeStatus() {
  const { t } = useI18n();
  const { isAdmin } = useAuth();
  const isMobile = useIsMobile();

  const [adminRows, setAdminRows] = useState<NodeStatus[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [latestNodeVersion, setLatestNodeVersion] = useState('');
  const [nodeVersionCheckFailed, setNodeVersionCheckFailed] = useState(false);
  const [panelProtocol, setPanelProtocol] = useState(0);
  const [detailRow, setDetailRow] = useState<AnyNodeRow | null>(null);
  const inFlightRef = useRef(false);
  const [liveRates, setLiveRates] = useState<Map<string, NodeLiveRate>>(() => new Map());
  const liveInFlightRef = useRef(false);
  const orderGenRef = useRef(0);

  const loadAdmin = async () => {
    const gen = orderGenRef.current;
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes');
      if (gen !== orderGenRef.current) return;
      if (res.code !== 0) {
        setLoadFailed(true);
        return;
      }
      setLoadFailed(false);
      setAdminRows(res.data || []);
    } catch {
      setLoadFailed(true);
    }
  };

  const loadLiveRates = async () => {
    if (document.hidden || liveInFlightRef.current) return;
    liveInFlightRef.current = true;
    try {
      const res = await api.get<unknown, ApiEnvelope<NodeLiveRate[]>>('/nodes/live-rates');
      const next = new Map<string, NodeLiveRate>();
      if (res.code === 0) {
        for (const r of res.data || []) next.set(liveKey(r.group_id, r.node_id), r);
      }
      setLiveRates(next);
    } catch {
      setLiveRates(new Map());
    } finally {
      liveInFlightRef.current = false;
    }
  };

  const loadVersion = async () => {
    try {
      const res = await api.get<unknown, VersionInfo>('/system/version');
      setPanelProtocol(res.config_protocol_version || 0);
      setLatestNodeVersion(res.latest_node_version || '');
      setNodeVersionCheckFailed(!!res.node_version_check_failed);
    } catch { /* ignore */ }
  };

  const refresh = async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      await loadAdmin();
    } finally {
      inFlightRef.current = false;
    }
  };

  useEffect(() => {
    if (isAdmin) loadVersion();
    refresh();
    const ti = setInterval(refresh, 5000);
    return () => clearInterval(ti);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  useEffect(() => {
    loadLiveRates();
    const ti = setInterval(loadLiveRates, LIVE_RATE_POLL_MS);
    return () => clearInterval(ti);
  }, []);

  const baseRows: AnyNodeRow[] | null = adminRows;
  // Overlay the pushed rate on online nodes that have one. The group header
  // sums row rates, so it picks the live figures up with no change of its own.
  const rows = useMemo(() => {
    if (!baseRows || liveRates.size === 0) return baseRows;
    return baseRows.map((r) => {
      const live = r.online && r.node_id ? liveRates.get(liveKey(r.group_id, r.node_id)) : undefined;
      return live ? { ...r, upload_bps: live.upload_bps, download_bps: live.download_bps } : r;
    });
  }, [baseRows, liveRates]);
  const groups = useMemo(() => (rows ? stableGroupedRows(rows) : null), [rows]);
  // v1.2.16: "upgrade all" — every node the per-node button would accept, across
  // all groups (same eligibility ladder). Admin only.
  // Where the icon is lined up: it sits in the page header row, over the first
  // visible group table's 节点更新 column.
  const pageHeaderRef = useRef<HTMLDivElement>(null);
  const groupsRef = useRef<HTMLDivElement>(null);
  const upgradableAll = useMemo(
    () => (isAdmin && rows ? upgradableNodes(rows, latestNodeVersion, panelProtocol, nodeVersionCheckFailed) : []),
    [isAdmin, rows, latestNodeVersion, panelProtocol, nodeVersionCheckFailed],
  );
  // v1.2.14: every group's header sums its own online nodes; this is the same
  // sum over all of them, for the page header.
  const all = useMemo(() => (rows ? rateSummary(rows) : null), [rows]);
  // The drawer follows the node, not the snapshot taken when it was opened, so
  // its figures (the live rate included) keep updating while it stays open.
  const detailCurrent = detailRow
    ? rows?.find((r) => r.group_id === detailRow.group_id && r.node_id === detailRow.node_id) ?? detailRow
    : null;

  // Drag to reorder the groups: pointer, plus keyboard (Space to pick up,
  // arrows to move, Space to drop, Escape to cancel). Enter is left out on
  // purpose: on the group header it folds the group. Hooks, so above the early
  // returns.
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
      keyboardCodes: { start: ['Space'], cancel: ['Escape'], end: ['Space'] },
    }),
  );
  // Only an admin on a wide screen drags; everyone else just sees the order.
  const canReorder = isAdmin && !isMobile;

  const title = t('nodeStatus');

  // Load failure (DB error / request failure) — not a normal empty state.
  // v0.4.15 PR3: applies to admins too (loadAdmin now surfaces failures).
  if (loadFailed) {
    return (
      <>
        <h2 className="rp-page-title"><LineChartOutlined /> {title}</h2>
        <Result status="warning" title={t('loadFailed')} subTitle={t('loadFailedRetry')} />
      </>
    );
  }

  if (rows === null || groups === null) {
    return <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>;
  }

  // No groups at all.
  if (groups.length === 0) {
    return (
      <>
        <h2 className="rp-page-title"><LineChartOutlined /> {title}</h2>
        <Result
          status="info"
          icon={<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
          title={isAdmin ? t('noNodesHint') : t('adminNoLines')}
        />
      </>
    );
  }

  // The admin dropped a group on another's place. Show the new order at once,
  // then save it; if saving fails, put the old order back.
  const handleGroupDragEnd = async ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id || !adminRows) return;
    const shown = groups.filter(([, r]) => hasGroupOrder(r)).map(([gid]) => gid);
    const next = moveGroup(shown, Number(active.id), Number(over.id));
    if (next === shown) return;

    const before = adminRows;
    orderGenRef.current += 1;
    setAdminRows(withGroupOrder(before, next));
    try {
      // The page lists only groups that have a node record; the server orders
      // all of them. Send the whole list so the others keep their places.
      const list = await api.get<unknown, ApiEnvelope<{ id: number }[]>>('/groups');
      if (list.code !== 0) throw new Error(list.message);
      const full = mergeVisibleOrder((list.data || []).map((g) => g.id), next);
      const res = await api.put<unknown, ApiEnvelope<null>>('/groups/order', { ids: full });
      if (res.code !== 0) throw new Error(res.message);
    } catch {
      setAdminRows(before);
      message.error(t('reorderGroupsFailed'));
    } finally {
      orderGenRef.current += 1;
    }
  };

  const renderSection = (gid: number, groupRows: AnyNodeRow[]) => {
    const props = {
      rows: groupRows,
      panelProtocol,
      latestNodeVersion,
      nodeVersionCheckFailed,
      isMobile,
      t,
      openDetail: setDetailRow,
      onDelete: isAdmin ? handleDelete : undefined,
      onBatchUpgraded: isAdmin ? refresh : undefined,
    };
    return canReorder && hasGroupOrder(groupRows)
      ? <SortableNodeGroupSection key={gid} id={gid} {...props} />
      : <NodeGroupSection key={gid} {...props} />;
  };

  // v1.2.5: drop one node's status record. Admin-only, and the button is only
  // rendered on offline rows — see NodeDesktopTable for why.
  const handleDelete = async (row: NodeDisplayRow) => {
    try {
      const qs = row.node_id ? `?node_id=${encodeURIComponent(row.node_id)}` : '';
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/nodes/${row.group_id}${qs}`);
      if (res.code !== 0) { message.error(res.message || t('nodeRemoveFailed')); return; }
      message.success(t('nodeRemoved'));
      refresh();
    } catch {
      message.error(t('nodeRemoveFailed'));
    }
  };

  return (
    <>
      <div ref={pageHeaderRef} className="rp-page-header rp-page-header-sticky">
        <h2 className="rp-page-title" data-upgrade-obstacle=""><LineChartOutlined /> {title}</h2>
        <Space wrap size={[12, 8]}>
          {all && all.total > 0 && (
            <Typography.Text type="secondary" style={{ fontSize: 13 }} data-testid="all-nodes-rate" data-upgrade-obstacle="">
              {t('onlineNodesOfTotal').replace('{online}', String(all.online)).replace('{total}', String(all.total))}
              {' · '}
              <ArrowUpOutlined /> {formatBps(all.up)} <ArrowDownOutlined /> {formatBps(all.down)}
              {all.hasTotals && (
                <span data-testid="all-nodes-traffic" title={t('allNodesTrafficTip')}>
                  {' · '}{t('allNodesTraffic')} <ArrowUpOutlined /> {formatBytes(all.totalUp)} <ArrowDownOutlined /> {formatBytes(all.totalDown)}
                </span>
              )}
            </Typography.Text>
          )}
          {upgradableAll.length > 0 && (
            <UpgradeSlot rowRef={pageHeaderRef} tablesRef={groupsRef}>
              <UpgradeAllButton
                nodes={upgradableAll}
                latestNodeVersion={latestNodeVersion}
                labelKey="upgradeAll"
                t={t}
                onDone={refresh}
                testId="upgrade-all"
              />
            </UpgradeSlot>
          )}
        </Space>
      </div>
      <div ref={groupsRef}>
        {canReorder ? (
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleGroupDragEnd}>
            <SortableContext
              items={groups.filter(([, r]) => hasGroupOrder(r)).map(([gid]) => gid)}
              strategy={verticalListSortingStrategy}
            >
              {groups.map(([gid, groupRows]) => renderSection(gid, groupRows))}
            </SortableContext>
          </DndContext>
        ) : (
          groups.map(([gid, groupRows]) => renderSection(gid, groupRows))
        )}
      </div>
      <NodeDetailDrawer
        row={detailCurrent}
        open={detailRow !== null}
        onClose={() => setDetailRow(null)}
        isAdmin={isAdmin}
        panelProtocol={panelProtocol}
        onDeleted={refresh}
      />
    </>
  );
}
