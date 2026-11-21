import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Form,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Tag,
  Typography,
  message,
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  NodeDisplayRow,
  NodeTrafficQuota,
  TrafficDirection,
} from '../../api/types';
import { useI18n } from '../../i18n/context';
import { formatBytes, formatDateTime } from '../../utils/format';
import { trafficResetText } from './NodeTrafficCell';

const { Text } = Typography;

type ByteUnit = 'MB' | 'GB' | 'TB';

const UNIT_MULTIPLIER: Record<ByteUnit, number> = {
  MB: 1024 ** 2,
  GB: 1024 ** 3,
  TB: 1024 ** 4,
};

const UNIT_OPTIONS: { value: ByteUnit; label: ByteUnit }[] = [
  { value: 'MB', label: 'MB' },
  { value: 'GB', label: 'GB' },
  { value: 'TB', label: 'TB' },
];

const THRESHOLD_PRESETS = ['50', '70', '80', '85', '90', '95'].map((v) => ({
  value: v,
  label: `${v}%`,
}));

function splitBytes(bytes: number): { value: number; unit: ByteUnit } {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return { value: 0, unit: 'GB' };
  }
  if (bytes >= UNIT_MULTIPLIER.TB && bytes % UNIT_MULTIPLIER.TB === 0) {
    return { value: bytes / UNIT_MULTIPLIER.TB, unit: 'TB' };
  }
  if (bytes >= UNIT_MULTIPLIER.GB) {
    return { value: Number((bytes / UNIT_MULTIPLIER.GB).toFixed(2)), unit: 'GB' };
  }
  return { value: Number((bytes / UNIT_MULTIPLIER.MB).toFixed(2)), unit: 'MB' };
}

function toBytes(value: number | null | undefined, unit: ByteUnit): number {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.round(n * UNIT_MULTIPLIER[unit]);
}

function parseThresholds(raw: (string | number)[] | undefined): number[] | null {
  if (!raw || raw.length === 0) return [];
  const parsed: number[] = [];
  for (const item of raw) {
    const cleaned = String(item).trim().replace(/%$/, '');
    if (!/^\d+$/.test(cleaned)) return null;
    const n = Number(cleaned);
    if (!Number.isInteger(n) || n < 1 || n > 99) return null;
    parsed.push(n);
  }
  const unique = Array.from(new Set(parsed)).sort((a, b) => a - b);
  if (unique.length > 5) return null;
  return unique;
}

interface Props {
  row: NodeDisplayRow | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}

export function NodeTrafficModal({ row, open, onClose, onSaved }: Props) {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [totalUnit, setTotalUnit] = useState<ByteUnit>('GB');
  const [usedUnit, setUsedUnit] = useState<ByteUnit>('GB');
  const [usedDirty, setUsedDirty] = useState(false);

  const quota: NodeTrafficQuota | null = row?.traffic_quota ?? null;

  useEffect(() => {
    if (!open || !row) return;
    const totalSplit = splitBytes(quota?.total_bytes ?? 0);
    const usedSplit = splitBytes(quota?.used_bytes ?? 0);
    setTotalUnit(totalSplit.unit);
    setUsedUnit(usedSplit.unit);
    setUsedDirty(false);
    form.setFieldsValue({
      total_value: totalSplit.value,
      used_value: usedSplit.value,
      direction: quota?.direction ?? 'both',
      warn_thresholds: (quota?.warn_thresholds ?? [80]).map(String),
      reset_day: quota?.reset_day ?? null,
    });
    // Only re-initialize when opening the modal or switching nodes so 5s status polls
    // do not overwrite edits in progress.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, row?.group_id, row?.node_id]);

  const directionOptions = useMemo(
    () => [
      { value: 'both' as TrafficDirection, label: t('nodeTrafficDirectionBoth') },
      { value: 'upload' as TrafficDirection, label: t('nodeTrafficDirectionUpload') },
      { value: 'download' as TrafficDirection, label: t('nodeTrafficDirectionDownload') },
      { value: 'max' as TrafficDirection, label: t('nodeTrafficDirectionMax') },
    ],
    [t],
  );

  const nodeTitle = row
    ? [row.label || row.group_name || `Group ${row.group_id}`, row.public_ipv4 || row.public_ip]
        .filter(Boolean)
        .join(' · ')
    : '';

  const handleSave = async () => {
    if (!row?.node_id) {
      message.warning(t('nodeTrafficLegacyUnsupported'));
      return;
    }
    let values: {
      total_value?: number | null;
      used_value?: number | null;
      direction?: TrafficDirection;
      warn_thresholds?: string[];
      reset_day?: number | null;
    };
    try {
      values = await form.validateFields();
    } catch {
      return;
    }

    const thresholds = parseThresholds(values.warn_thresholds);
    if (thresholds === null) {
      message.error(t('nodeTrafficThresholdsInvalid'));
      return;
    }

    const payload: Record<string, unknown> = {
      total_bytes: toBytes(values.total_value, totalUnit),
      direction: values.direction ?? 'both',
      warn_thresholds: thresholds,
      reset_day: values.reset_day ? Number(values.reset_day) : null,
    };
    if (usedDirty) {
      payload.used_bytes = toBytes(values.used_value, usedUnit);
    }

    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<NodeTrafficQuota>>(
        `/nodes/${row.group_id}/traffic/${encodeURIComponent(row.node_id)}`,
        payload,
      );
      if (res.code !== 0) {
        message.error(res.message || t('nodeTrafficSaveFailed'));
        return;
      }
      message.success(t('nodeTrafficSaved'));
      onSaved();
      onClose();
    } catch {
      message.error(t('nodeTrafficSaveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!row?.node_id) return;
    setResetting(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<NodeTrafficQuota>>(
        `/nodes/${row.group_id}/traffic/${encodeURIComponent(row.node_id)}/reset`,
      );
      if (res.code !== 0) {
        message.error(res.message || t('nodeTrafficResetFailed'));
        return;
      }
      message.success(t('nodeTrafficResetSuccess'));
      onSaved();
      onClose();
    } catch {
      message.error(t('nodeTrafficResetFailed'));
    } finally {
      setResetting(false);
    }
  };

  return (
    <Modal
      title={t('nodeTrafficConfigTitle')}
      open={open}
      onCancel={onClose}
      width={540}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
          {row?.node_id ? (
            <Popconfirm
              title={t('nodeTrafficResetConfirm')}
              description={t('nodeTrafficResetDesc')}
              okText={t('nodeTrafficResetBtn')}
              cancelText={t('cancel')}
              okButtonProps={{ danger: true }}
              onConfirm={handleReset}
            >
              <Button danger icon={<ReloadOutlined />} loading={resetting}>
                {t('nodeTrafficResetBtn')}
              </Button>
            </Popconfirm>
          ) : (
            <span />
          )}
          <Space>
            <Button onClick={onClose}>{t('cancel')}</Button>
            <Button type="primary" loading={saving} disabled={!row?.node_id} onClick={() => void handleSave()}>
              {t('save')}
            </Button>
          </Space>
        </div>
      }
    >
      {row && !row.node_id && (
        <Alert type="warning" showIcon title={t('nodeTrafficLegacyUnsupported')} style={{ marginBottom: 16 }} />
      )}
      {row && (
        <div
          style={{
            marginBottom: 16,
            padding: '10px 12px',
            borderRadius: 8,
            background: 'var(--rp-bg, #f8fafc)',
            border: '1px solid var(--rp-border, #f0f0f0)',
            fontSize: 12,
            lineHeight: 1.7,
          }}
        >
          <div>
            <Text strong>{nodeTitle}</Text>
            {row.network_interface && (
              <Text type="secondary" className="rp-mono" style={{ marginLeft: 8 }}>
                NIC: {row.network_interface}
              </Text>
            )}
          </div>
          {quota && (
            <>
              <div className="rp-mono">
                {t('nodeTrafficCycleTracked')}: ↑ {formatBytes(quota.period_upload_bytes)} / ↓ {formatBytes(quota.period_download_bytes)}
                {quota.base_bytes > 0 ? ` · ${t('nodeTrafficCalibratedBase')}: ${formatBytes(quota.base_bytes)}` : ''}
              </div>
              <div>
                {t('nodeTrafficNextReset')}: {trafficResetText(quota, t)}
                {quota.last_reset_at ? ` · ${t('nodeTrafficLastReset')}: ${formatDateTime(quota.last_reset_at)}` : ''}
              </div>
              {(quota.notified_thresholds.length > 0 || quota.notified_exhausted) && (
                <div style={{ marginTop: 4 }}>
                  <Text type="secondary" style={{ marginRight: 6 }}>{t('nodeTrafficNotifiedThresholds')}:</Text>
                  {quota.notified_thresholds.map((pct) => (
                    <Tag key={pct} color="orange">{pct}%</Tag>
                  ))}
                  {quota.notified_exhausted && <Tag color="red">100%</Tag>}
                </div>
              )}
            </>
          )}
        </div>
      )}

      <Form form={form} layout="vertical">
        <Form.Item label={t('nodeTrafficTotal')} extra={t('nodeTrafficTotalHint')}>
          <Space.Compact style={{ width: '100%' }}>
            <Form.Item name="total_value" noStyle rules={[{ required: true }]}>
              <InputNumber
                min={0}
                precision={2}
                style={{ width: '100%' }}
                aria-label={t('nodeTrafficTotal')}
              />
            </Form.Item>
            <Select
              value={totalUnit}
              onChange={setTotalUnit}
              options={UNIT_OPTIONS}
              style={{ width: 90 }}
              aria-label="total-unit"
            />
          </Space.Compact>
        </Form.Item>

        <Form.Item label={t('nodeTrafficUsed')} extra={t('nodeTrafficUsedHint')}>
          <Space.Compact style={{ width: '100%' }}>
            <Form.Item name="used_value" noStyle>
              <InputNumber
                min={0}
                precision={2}
                style={{ width: '100%' }}
                aria-label={t('nodeTrafficUsed')}
                onChange={() => setUsedDirty(true)}
              />
            </Form.Item>
            <Select
              value={usedUnit}
              onChange={(u) => {
                setUsedUnit(u);
                setUsedDirty(true);
              }}
              options={UNIT_OPTIONS}
              style={{ width: 90 }}
              aria-label="used-unit"
            />
          </Space.Compact>
        </Form.Item>

        <Form.Item name="direction" label={t('nodeTrafficDirection')}>
          <Select options={directionOptions} />
        </Form.Item>

        <Form.Item
          name="warn_thresholds"
          label={t('nodeTrafficThresholds')}
          extra={t('nodeTrafficThresholdsHint')}
          rules={[
            {
              validator: (_, v) =>
                parseThresholds(v) !== null
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('nodeTrafficThresholdsInvalid'))),
            },
          ]}
        >
          <Select
            mode="tags"
            tokenSeparators={[',', ' ', '，']}
            options={THRESHOLD_PRESETS}
            placeholder={t('nodeTrafficThresholdsPlaceholder')}
          />
        </Form.Item>

        <Form.Item
          name="reset_day"
          label={t('nodeTrafficResetDay')}
          extra={t('nodeTrafficResetDayHint')}
        >
          <InputNumber
            min={1}
            max={31}
            precision={0}
            style={{ width: 220 }}
            placeholder={t('nodeTrafficResetDayPlaceholder')}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
