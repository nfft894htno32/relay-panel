import { Table, Button, Modal, Form, Input, Select, Space, message, Popconfirm, Typography, Tag, Tooltip, Alert } from 'antd';
import { PlusOutlined, ReloadOutlined, CopyOutlined, EditOutlined, CloudServerOutlined, CodeOutlined, ApiOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup, NodeStatus } from '../api/types';
import { useI18n } from '../i18n/context';
import { useTableScroll } from '../hooks/useIsMobile';
import { copyText } from '../utils/clipboard';
import { formatDateTime } from '../utils/format';
import { buildInstallCommand } from '../utils/installCommand';
import ConnectHostsEditor from '../components/ConnectHostsEditor';
import { NodeLabelCell } from '../components/nodes/NodeLabelCell';
import HostSummary from '../components/HostSummary';
import { joinHosts, splitHosts } from '../utils/connectHosts';

const { Text } = Typography;

function isMonitorOnly(g: { group_type: string }): boolean {
  return g.group_type === 'monitor';
}

const dash = <span style={{ color: 'var(--rp-text-tertiary)' }}>-</span>;

function isLocalhost(): boolean {
  const h = window.location.hostname;
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

export default function Groups() {
  const tableScroll = useTableScroll();
  const { t } = useI18n();
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [nodes, setNodes] = useState<NodeStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [cmdModalOpen, setCmdModalOpen] = useState(false);
  const [cmdModalContent, setCmdModalContent] = useState<{ title: ReactNode; body: ReactNode }>({ title: null, body: null });
  const [editing, setEditing] = useState<DeviceGroup | null>(null);
  const [rotating, setRotating] = useState<DeviceGroup | null>(null);
  const [confirmName, setConfirmName] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();

  const createType = Form.useWatch('group_type', createForm) ?? 'in';
  const editType = Form.useWatch('group_type', editForm) ?? editing?.group_type;
  const createIsMonitor = createType === 'monitor';
  const editIsMonitor = editType === 'monitor';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const g = await api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups');
      if (g.code !== 0) {
        setLoadFailed(true);
      } else {
        setLoadFailed(false);
        setGroups(g.data || []);
      }
      try {
        const n = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes');
        setNodes(n.data || []);
      } catch { setNodes([]); }
    } catch {
      setLoadFailed(true);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const nodesByGroup = useCallback((groupId: number): NodeStatus[] => {
    return nodes.filter(n => n.group_id === groupId);
  }, [nodes]);

  const nodeCount = useCallback((groupId: number) => nodesByGroup(groupId).length, [nodesByGroup]);
  const onlineCount = useCallback((groupId: number) => nodesByGroup(groupId).filter(n => n.online).length, [nodesByGroup]);

  const handleCreate = async (values: {
    name: string;
    group_type: string;
    connect_hosts?: string[];
    port_range: string;
    sni_fallback_addr?: string;
    sni_loop_bypass_ips?: string;
  }) => {
    try {
      const { connect_hosts, ...rest } = values;
      const payload = {
        ...rest,
        connect_host: joinHosts(connect_hosts ?? []),
        sni_fallback_addr: values.sni_fallback_addr?.trim() || '127.0.0.1:10443',
        sni_loop_bypass_ips: values.sni_loop_bypass_ips?.trim() || '',
      };
      if (values.group_type === 'monitor') {
        payload.connect_host = '';
        payload.port_range = '';
      }
      const res = await api.post<unknown, ApiEnvelope<DeviceGroup>>('/groups', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      load();
    } catch { message.error(t('failedCreateGroup')); }
  };

  const handleEdit = (g: DeviceGroup) => {
    setEditing(g);
    editForm.setFieldsValue({
      name: g.name,
      group_type: g.group_type,
      connect_hosts: splitHosts(g.connect_host).length ? splitHosts(g.connect_host) : [''],
      port_range: g.port_range,
      sni_fallback_addr: g.sni_fallback_addr || '127.0.0.1:10443',
      sni_loop_bypass_ips: g.sni_loop_bypass_ips || '',
    });
    setEditOpen(true);
  };

  const handleUpdate = async (values: {
    name?: string;
    group_type?: string;
    connect_hosts?: string[];
    port_range?: string;
    sni_fallback_addr?: string;
    sni_loop_bypass_ips?: string;
  }) => {
    if (!editing) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.group_type !== undefined && values.group_type !== editing.group_type) payload.group_type = values.group_type;
    if (values.connect_hosts !== undefined) {
      const joined = joinHosts(values.connect_hosts);
      if (joined !== joinHosts(splitHosts(editing.connect_host))) payload.connect_host = joined;
    }
    if (values.port_range !== undefined && values.port_range !== editing.port_range) payload.port_range = values.port_range;
    if (
      values.sni_fallback_addr !== undefined &&
      values.sni_fallback_addr.trim() !== (editing.sni_fallback_addr || '127.0.0.1:10443')
    ) {
      payload.sni_fallback_addr = values.sni_fallback_addr.trim();
    }
    if (
      values.sni_loop_bypass_ips !== undefined &&
      values.sni_loop_bypass_ips.trim() !== (editing.sni_loop_bypass_ips || '')
    ) {
      payload.sni_loop_bypass_ips = values.sni_loop_bypass_ips.trim();
    }
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/groups/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupUpdated'));
      setEditOpen(false);
      load();
    } catch { message.error(t('failedUpdateGroup')); }
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/groups/${id}`);
      if (res.code !== 0) {
        message.error(res.message || (res.code === 409 ? t('groupInUse') : t('failedDeleteGroup')));
        return;
      }
      message.success(t('groupDeleted'));
      load();
    } catch { message.error(t('failedDeleteGroup')); }
  };

  const doCopy = async (text: string, successMsg: string) => {
    if (!text || text.length < 20) { message.error(t('copyFailed')); return; }
    const ok = await copyText(text);
    if (ok) {
      message.success(successMsg);
    } else {
      message.error(t('copyFailed'));
    }
  };

  const panelUrlRef = async (): Promise<string> => {
    try {
      const resp = await api.get<unknown, { public_panel_url?: string }>("/system/version");
      if (resp.public_panel_url) return resp.public_panel_url;
    } catch { /* ignore */ }
    return window.location.origin;
  };

  const showInstallCommand = async (g: DeviceGroup) => {
    const panelUrl = await panelUrlRef();
    const cmd = buildInstallCommand(g.token, panelUrl);
    setCmdModalContent({
      title: <span>{t('installCommandTitle')}</span>,
      body: (
        <>
          {(isLocalhost() || panelUrl.includes("127.0.0.1") || panelUrl.includes("localhost") || panelUrl.includes("0.0.0.0")) && (
            <Alert type="warning" showIcon style={{ marginBottom: 12 }} title={t('localhostWarning')} />
          )}
          <Input.TextArea value={cmd} readOnly autoSize={{ minRows: 3, maxRows: 5 }} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12 }} />
          <div style={{ textAlign: 'right', marginTop: 8 }}>
            <Button type="primary" icon={<CopyOutlined />} onClick={() => doCopy(cmd, t('installCommandCopied'))}>
              {t('copyInstallCommand')}
            </Button>
          </div>
        </>
      ),
    });
    setCmdModalOpen(true);
  };

  const handleRotateToken = async () => {
    if (!rotating) return;
    setRotateBusy(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<{ token: string }>>(
        `/groups/${rotating.id}/rotate-token`,
      );
      if (res.code !== 0 || !res.data) { message.error(res.message || t('tokenRotateFailed')); return; }
      const newToken = res.data.token;
      const panelUrl = await panelUrlRef();
      const cmd = buildInstallCommand(newToken, panelUrl);
      setRotating(null);
      setConfirmName('');
      load();
      setCmdModalContent({
        title: <span>{t('tokenRotated')}</span>,
        body: (
          <>
            <Alert type="warning" showIcon style={{ marginBottom: 12 }} title={t('tokenRotatedHint')} />
            <div style={{ marginBottom: 6 }}><Text strong>{t('nodeToken')}</Text></div>
            <Input value={newToken} readOnly style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12, marginBottom: 12 }} />
            <div style={{ marginBottom: 6 }}><Text strong>{t('installCommandTitle')}</Text></div>
            <Input.TextArea value={cmd} readOnly autoSize={{ minRows: 3, maxRows: 5 }} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12 }} />
            <div style={{ textAlign: 'right', marginTop: 8 }}>
              <Button type="primary" icon={<CopyOutlined />} onClick={() => doCopy(cmd, t('installCommandCopied'))}>
                {t('copyInstallCommand')}
              </Button>
            </div>
          </>
        ),
      });
      setCmdModalOpen(true);
    } catch {
      message.error(t('tokenRotateFailed'));
    } finally {
      setRotateBusy(false);
    }
  };

  const typeColor = (gt: string) => {
    switch (gt) {
      case 'in': return 'green';
      case 'out': return 'cyan';
      case 'monitor': return 'default';
      default: return 'default';
    }
  };

  const typeLabel = (gt: string) => {
    switch (gt) {
      case 'in': return t('inboundListener');
      case 'out': return t('outboundEgress');
      case 'monitor': return t('typeMonitor');
      default: return gt;
    }
  };

  const groupTypeOptions = [
    { value: 'in', label: t('inboundListener') },
    { value: 'monitor', label: t('typeMonitor') },
  ];

  const columns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    { title: t('name'), dataIndex: 'name', key: 'name', width: 160, ellipsis: { showTitle: true } },
    {
      title: t('type'), dataIndex: 'group_type', key: 'group_type',
      render: (gt: string) => <Tag color={typeColor(gt)}>{typeLabel(gt)}</Tag>,
    },
    {
      title: t('nodes'), key: 'nodes', width: 100,
      render: (_: unknown, g: DeviceGroup) => {
        const total = nodeCount(g.id);
        const online = onlineCount(g.id);
        return <span>{total > 0 ? `${online}/${total}` : '-'}</span>;
      },
    },
    {
      title: t('nodeToken'), dataIndex: 'token', key: 'token',
      render: (tk: string, g: DeviceGroup) => (
        <Space>
          <Text code style={{ maxWidth: 150 }} ellipsis>{tk}</Text>
          <Tooltip title={t('copyInstallCommand')}>
            <Button size="small" type="text" icon={<CodeOutlined />} aria-label={t('copyInstallCommand')} onClick={() => showInstallCommand(g)} />
          </Tooltip>
        </Space>
      ),
    },
    { title: t('connectHost'), dataIndex: 'connect_host', key: 'connect_host', render: (v: string, g: DeviceGroup) => isMonitorOnly(g) ? dash : <HostSummary value={v} empty={dash} /> },
    { title: t('portRange'), dataIndex: 'port_range', key: 'port_range', render: (v: string, g: DeviceGroup) => isMonitorOnly(g) ? dash : <span className="rp-mono">{v}</span> },
    {
      title: 'SNI 回落地址',
      dataIndex: 'sni_fallback_addr',
      key: 'sni_fallback_addr',
      render: (v: string | undefined, g: DeviceGroup) =>
        isMonitorOnly(g) ? dash : <span className="rp-mono">{v || '127.0.0.1:10443'}</span>,
    },
    {
      title: t('action'), key: 'action',
      render: (_: unknown, g: DeviceGroup) => (
        <Space size={0} wrap style={{ minWidth: 150 }}>
          <Button size="small" type="text" icon={<EditOutlined />} onClick={() => handleEdit(g)}>{t('edit')}</Button>
          <Tooltip title={t('rotateTokenHint')}>
            <Button
              size="small"
              type="text"
              icon={<SafetyCertificateOutlined />}
              onClick={() => { setConfirmName(''); setRotating(g); }}
            >
              {t('rotateToken')}
            </Button>
          </Tooltip>
          <Popconfirm title={t('deleteGroupConfirm')} onConfirm={() => handleDelete(g.id)}>
            <Button danger size="small" type="text">{t('delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const handleSetNodeLabel = async (row: { group_id: number; node_id?: string | null }, label: string): Promise<boolean> => {
    if (!row.node_id) return false;
    try {
      const res = await api.put<unknown, ApiEnvelope<string | null>>(
        `/nodes/${row.group_id}/label/${encodeURIComponent(row.node_id)}`,
        { label },
      );
      if (res.code !== 0) { message.error(res.message || t('nodeLabelSaveFailed')); return false; }
      message.success(t('nodeLabelSaved'));
      load();
      return true;
    } catch {
      message.error(t('nodeLabelSaveFailed'));
      return false;
    }
  };

  const expandedRowRender = (g: DeviceGroup) => {
    const groupNodes = nodesByGroup(g.id);
    if (groupNodes.length === 0) {
      return (
        <div style={{ padding: '8px 0', color: 'var(--rp-text-tertiary)', fontSize: 13 }}>
          {t('noNodesInGroup')}
          <Button size="small" type="link" icon={<ApiOutlined />} style={{ marginLeft: 12 }} onClick={() => showInstallCommand(g)}>
            {t('addNode')}
          </Button>
        </div>
      );
    }
    return (
      <div style={{ padding: 4 }}>
        <div style={{ marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>{t('nodesInGroup')} ({groupNodes.length})</Text>
          <Button size="small" icon={<ApiOutlined />} onClick={() => showInstallCommand(g)}>{t('addNode')}</Button>
        </div>
        <Table
          dataSource={groupNodes}
          rowKey={(n: NodeStatus) => n.node_id ?? `${n.public_ipv4 ?? n.public_ip}-${n.last_seen}`}
          pagination={false}
          scroll={tableScroll}
          size="small"
          columns={[
            { title: t('nodeLabel'), dataIndex: 'label', key: 'label', width: 200, render: (_: unknown, n: NodeStatus) => (
              <div>
                <NodeLabelCell row={n} t={t} onSave={handleSetNodeLabel} />
                <NodeAddresses node={n} />
              </div>
            ) },
            { title: 'ID', dataIndex: 'node_id', key: 'node_id', width: 120, render: (v: string | undefined) => v ? <Text code style={{ fontSize: 11 }}>{v.slice(0, 8)}...{v.slice(-4)}</Text> : '-' },
            { title: t('status'), dataIndex: 'online', key: 'online', width: 80, render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? t('online') : t('offline')}</Tag> },
            { title: t('nodeVersion'), dataIndex: 'node_version', key: 'version', width: 90, render: (v: string | undefined) => v ? <span className="rp-mono" style={{ fontSize: 12 }}>{v}</span> : '-' },
            { title: t('lastSeen'), dataIndex: 'last_seen', key: 'last_seen', width: 120, render: (v: string | undefined) => <span className="rp-mono" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{formatDateTime(v)}</span> },
          ]}
        />
      </div>
    );
  };

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><CloudServerOutlined /> {t('deviceGroups')}</h2>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>{t('addGroup')}</Button>
        </Space>
      </div>
      {loadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('loadFailed')}
          description={t('loadFailedRetry')}
        />
      )}
      <Table
        dataSource={groups}
        columns={columns}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
        scroll={tableScroll}
        expandable={{
          expandedRowRender,
          rowExpandable: () => true,
        }}
      />

      <Modal title={t('addGroup')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} okText={t('create')} cancelText={t('cancel')}>
        <Form form={createForm} onFinish={handleCreate} layout="vertical">
          <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input placeholder="tokyo-node-1" /></Form.Item>
          <Form.Item name="group_type" label={t('type')} rules={[{ required: true }]} initialValue="in">
            <Select options={groupTypeOptions} />
          </Form.Item>
          {createIsMonitor ? (
            <Alert
              type="info"
              showIcon
              title={t('monitorOnlyNoForwardTitle')}
              description={t('monitorOnlyNoForwardDesc')}
            />
          ) : (
            <>
              <ConnectHostsEditor t={t} />
              <Form.Item name="port_range" label={t('portRange')} rules={[{ required: true }]} initialValue="10000-65535"><Input placeholder="10000-65535" /></Form.Item>
              <Form.Item
                name="sni_fallback_addr"
                label="SNI 回落地址 (Fallback)"
                initialValue="127.0.0.1:10443"
                extra="单端口多 SNI 分流未匹配或触发防回环时的回落目标（默认 127.0.0.1:10443）"
              >
                <Input placeholder="127.0.0.1:10443" />
              </Form.Item>
              <Form.Item
                name="sni_loop_bypass_ips"
                label="防回环额外白名单 IP/CIDR"
                initialValue=""
                extra="可选，逗号分隔（支持 IP 或 CIDR）。除本机公网 IP 和当前端口转发目标 IP 外，额外直接回落到 Fallback 的来源 IP"
              >
                <Input placeholder="203.0.113.10,198.51.100.0/24" />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>

      <Modal title={t('editGroup')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={() => editForm.submit()} okText={t('save')} cancelText={t('cancel')}>
        <Form form={editForm} onFinish={handleUpdate} layout="vertical">
          <Form.Item name="name" label={t('name')}><Input /></Form.Item>
          <Form.Item name="group_type" label={t('type')}><Select options={groupTypeOptions} /></Form.Item>
          {editIsMonitor ? (
            <Alert
              type="info"
              showIcon
              title={t('monitorOnlyNoForwardTitle')}
              description={`${t('monitorOnlyNoForwardDesc')} ${t('monitorOnlyEditKeepsFields')}`}
            />
          ) : (
            <>
              <ConnectHostsEditor t={t} legacy={splitHosts(editing?.connect_host)} canAdd={editType !== 'out'} />
              <Form.Item name="port_range" label={t('portRange')}><Input /></Form.Item>
              <Form.Item
                name="sni_fallback_addr"
                label="SNI 回落地址 (Fallback)"
                extra="单端口多 SNI 分流未匹配或触发防回环时的回落目标（默认 127.0.0.1:10443）"
              >
                <Input placeholder="127.0.0.1:10443" />
              </Form.Item>
              <Form.Item
                name="sni_loop_bypass_ips"
                label="防回环额外白名单 IP/CIDR"
                extra="可选，逗号分隔（支持 IP 或 CIDR）。除本机公网 IP 和当前端口转发目标 IP 外，额外直接回落到 Fallback 的来源 IP"
              >
                <Input placeholder="203.0.113.10,198.51.100.0/24" />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>

      <Modal title={cmdModalContent.title} open={cmdModalOpen} onCancel={() => setCmdModalOpen(false)} footer={null} width={580}>
        {cmdModalContent.body}
      </Modal>

      <Modal
        title={t('rotateTokenConfirmTitle')}
        open={!!rotating}
        onCancel={() => { setRotating(null); setConfirmName(''); }}
        onOk={handleRotateToken}
        okText={t('rotateTokenConfirmOk')}
        cancelText={t('cancel')}
        confirmLoading={rotateBusy}
        okButtonProps={{ danger: true, disabled: confirmName.trim() !== (rotating?.name ?? '') }}
      >
        {rotating && (
          <>
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              title={t('rotateTokenWarnTitle').replace('{count}', String(nodeCount(rotating.id)))}
              description={t('rotateTokenWarnDesc')}
            />
            <div style={{ marginBottom: 6 }}>
              {t('rotateTokenTypeName').replace('{name}', rotating.name)}
            </div>
            <Input
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              placeholder={rotating.name}
              autoComplete="off"
            />
          </>
        )}
      </Modal>
    </>
  );
}

function NodeAddresses({ node }: { node: { public_ipv4?: string | null; public_ip?: string | null; public_ipv6?: string | null } }) {
  const addrs = [node.public_ipv4 ?? node.public_ip, node.public_ipv6].filter((a): a is string => !!a);
  if (addrs.length === 0) return null;
  return (
    <div className="rp-mono" style={{ fontSize: 11, lineHeight: '16px', color: 'var(--rp-text-tertiary)' }}>
      {addrs.map((a) => <div key={a}>{a}</div>)}
    </div>
  );
}
