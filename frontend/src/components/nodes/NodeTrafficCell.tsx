/* eslint-disable react-refresh/only-export-components */

import { Button, Progress, Tag, Tooltip, Typography } from 'antd';
import { SettingOutlined } from '@ant-design/icons';
import type { NodeDisplayRow, NodeTrafficQuota, TrafficDirection } from '../../api/types';
import type { Tfn } from './types';
import { formatBytes, formatDateTime, formatPercent } from '../../utils/format';

const { Text } = Typography;

export function trafficDirectionLabel(direction: TrafficDirection | undefined, t: Tfn): string {
  switch (direction) {
    case 'upload':
      return t('nodeTrafficDirectionUpload');
    case 'download':
      return t('nodeTrafficDirectionDownload');
    case 'max':
      return t('nodeTrafficDirectionMax');
    case 'both':
    default:
      return t('nodeTrafficDirectionBoth');
  }
}

export function trafficQuotaColor(quota: NodeTrafficQuota): string {
  if (quota.status === 'exhausted') return '#ff4d4f';
  if (quota.status === 'warning') return '#faad14';
  return '#52c41a';
}

export function trafficResetText(quota: NodeTrafficQuota, t: Tfn): string {
  if (quota.reset_day && quota.reset_day >= 1 && quota.reset_day <= 31) {
    const base = t('nodeTrafficResetMonthly').replace('{day}', String(quota.reset_day));
    return quota.next_reset_date ? `${base} (${quota.next_reset_date})` : base;
  }
  return t('nodeTrafficResetManual');
}

export function NodeTrafficTooltip({ quota, t }: { quota: NodeTrafficQuota; t: Tfn }) {
  const remaining = quota.total_bytes > 0 ? Math.max(0, quota.total_bytes - quota.used_bytes) : null;
  const thresholds = quota.warn_thresholds.length > 0
    ? `${quota.warn_thresholds.map((v) => `${v}%`).join(', ')}, 100%`
    : '100%';
  return (
    <div style={{ fontSize: 12, lineHeight: 1.6 }}>
      <div>{t('nodeTrafficDirection')}: {trafficDirectionLabel(quota.direction, t)}</div>
      {quota.total_bytes > 0 ? (
        <>
          <div>
            {formatBytes(quota.used_bytes)} / {formatBytes(quota.total_bytes)}
            {quota.usage_percent != null ? ` (${formatPercent(quota.usage_percent)})` : ''}
          </div>
          <div>{t('nodeTrafficRemaining')}: {formatBytes(remaining)}</div>
          <div>{t('nodeTrafficThresholds')}: {thresholds}</div>
        </>
      ) : (
        <div>{t('nodeTrafficQuota')}: {t('nodeTrafficUnlimited')}</div>
      )}
      <div>
        {t('nodeTrafficCycleTracked')}: ↑ {formatBytes(quota.period_upload_bytes)} / ↓ {formatBytes(quota.period_download_bytes)}
      </div>
      {quota.base_bytes > 0 && (
        <div>{t('nodeTrafficCalibratedBase')}: {formatBytes(quota.base_bytes)}</div>
      )}
      <div>{t('nodeTrafficNextReset')}: {trafficResetText(quota, t)}</div>
      {quota.last_reset_at && (
        <div>{t('nodeTrafficLastReset')}: {formatDateTime(quota.last_reset_at)}</div>
      )}
    </div>
  );
}

interface Props {
  row: NodeDisplayRow;
  t: Tfn;
  onEdit?: (row: NodeDisplayRow) => void;
  compact?: boolean;
}

/** Quota progress cell for desktop node table and mobile node cards. */
export function NodeTrafficCell({ row, t, onEdit, compact }: Props) {
  const quota = row.traffic_quota;
  const canEdit = Boolean(onEdit && row.node_id);

  if (!quota || quota.total_bytes === 0) {
    const trackedText = quota && quota.used_bytes > 0 ? formatBytes(quota.used_bytes) : null;
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {quota ? (
          <Tooltip title={<NodeTrafficTooltip quota={quota} t={t} />}>
            <Text type="secondary" className="rp-mono" style={{ fontSize: 12 }}>
              {trackedText ?? t('nodeTrafficUnlimited')}
            </Text>
          </Tooltip>
        ) : (
          <Text type="secondary" style={{ fontSize: 12 }}>-</Text>
        )}
        {canEdit && (
          <Button
            size="small"
            type="link"
            style={{ padding: 0, height: 'auto', fontSize: 12 }}
            onClick={() => onEdit?.(row)}
          >
            {t('nodeTrafficSetQuota')}
          </Button>
        )}
      </div>
    );
  }

  const pct = quota.usage_percent ?? 0;
  const clampedPct = Math.min(100, Math.max(0, Math.round(pct)));
  const color = trafficQuotaColor(quota);

  return (
    <Tooltip title={<NodeTrafficTooltip quota={quota} t={t} />}>
      <div
        style={{
          minWidth: compact ? undefined : 164,
          cursor: canEdit ? 'pointer' : undefined,
        }}
        onClick={canEdit ? () => onEdit?.(row) : undefined}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, fontSize: 12 }}>
          <span className="rp-mono" style={{ whiteSpace: 'nowrap' }}>
            {formatBytes(quota.used_bytes)} / {formatBytes(quota.total_bytes)}
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            {quota.status === 'exhausted' && (
              <Tag color="red" style={{ marginInlineEnd: 0, fontSize: 11, lineHeight: '16px', padding: '0 4px' }}>
                {t('nodeTrafficExhausted')}
              </Tag>
            )}
            {quota.status === 'warning' && (
              <Tag color="orange" style={{ marginInlineEnd: 0, fontSize: 11, lineHeight: '16px', padding: '0 4px' }}>
                {formatPercent(pct)}
              </Tag>
            )}
            {canEdit && (
              <Button
                size="small"
                type="text"
                icon={<SettingOutlined style={{ fontSize: 12 }} />}
                aria-label={t('nodeTrafficEditQuota')}
                style={{ width: 20, height: 20, padding: 0 }}
                onClick={(e) => {
                  e.stopPropagation();
                  onEdit?.(row);
                }}
              />
            )}
          </span>
        </div>
        <Progress
          percent={clampedPct}
          size="small"
          showInfo={quota.status === 'normal'}
          format={() => formatPercent(pct)}
          strokeColor={color}
          status={quota.status === 'exhausted' ? 'exception' : 'normal'}
          style={{ marginBottom: 0, marginTop: 2 }}
        />
      </div>
    </Tooltip>
  );
}
