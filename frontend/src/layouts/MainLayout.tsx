import { Layout, Menu, Button, Space, Typography, Segmented, Modal, Form, Input, message, Spin, Tooltip, Drawer, Dropdown } from 'antd';
import type { MenuProps } from 'antd';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useState, Suspense } from 'react';
import {
  MenuOutlined,
  EllipsisOutlined,
  TranslationOutlined,
  DashboardOutlined,
  ApiOutlined,
  CloudServerOutlined,
  UserOutlined,
  LogoutOutlined,
  LockOutlined,
  GithubOutlined,
} from '@ant-design/icons';
import { useI18n } from '../i18n/context';
import api from '../api/client';
import type { ApiEnvelope } from '../api/types';
import { useAuth } from '../auth/useAuth';
import { useIsMobile } from '../hooks/useIsMobile';
import { makePasswordValidator } from '../utils/password';

const { Sider, Content, Header } = Layout;
const { Text } = Typography;

export default function MainLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { t, lang, setLang } = useI18n();
  const { isAdmin, user, logout: authLogout } = useAuth();
  const [changePwOpen, setChangePwOpen] = useState(false);
  const [pwForm] = Form.useForm();
  const [pwSubmitting, setPwSubmitting] = useState(false);
  const isMobile = useIsMobile();
  const [menuOpen, setMenuOpen] = useState(false);
  const [siderCollapsed, setSiderCollapsed] = useState(false);

  const menuItems = [
    { key: '/', icon: <DashboardOutlined />, label: t('dashboard') },
    { key: '/groups', icon: <CloudServerOutlined />, label: t('deviceGroups') },
    { key: '/rules', icon: <ApiOutlined />, label: t('forwardRules') },
    { key: '/nodes', icon: <CloudServerOutlined />, label: t('nodeStatus') },
    { key: '/account', icon: <UserOutlined />, label: t('personalCenter') },
  ];

  const logout = () => {
    authLogout();
    navigate('/login');
  };

  const handleChangePassword = async (values: { current_password: string; new_password: string }) => {
    setPwSubmitting(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>('/user/password', values);
      if (res.code !== 0) {
        message.error(res.message);
        return;
      }
      message.success(t('passwordChanged'));
      setChangePwOpen(false);
      pwForm.resetFields();
    } catch {
      message.error(t('passwordChangeFailed'));
    } finally {
      setPwSubmitting(false);
    }
  };

  const brand = t('brand');
  const brandBlock = (collapsed = false) => (
    <div title={brand} style={{
      height: 'var(--rp-header-height)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: collapsed ? '0 4px' : '0 16px',
      color: '#fff', fontSize: collapsed ? 13 : 17, fontWeight: 600, letterSpacing: collapsed ? 0 : 0.5,
    }}>
      <span style={{
        display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: 2,
        overflow: 'hidden', overflowWrap: 'anywhere', textAlign: 'center', lineHeight: 1.3,
      }}>
        {brand}
      </span>
    </div>
  );

  const menu = (
    <Menu
      theme="dark"
      mode="inline"
      selectedKeys={[location.pathname]}
      items={menuItems}
      onClick={({ key }) => {
        navigate(key);
        setMenuOpen(false);
      }}
      style={{ borderRight: 0 }}
    />
  );

  const moreItems: MenuProps['items'] = [
    { key: 'who', label: `${user?.username ?? ''} · ${isAdmin ? t('admin') : t('user')}`, disabled: true },
    { type: 'divider' },
    { key: 'lang', icon: <TranslationOutlined />, label: lang === 'zh-CN' ? t('langEnUS') : t('langZhCN') },
    { key: 'password', icon: <LockOutlined />, label: t('changePassword') },
    { key: 'github', icon: <GithubOutlined />, label: 'GitHub' },
    { type: 'divider' },
    { key: 'logout', icon: <LogoutOutlined />, label: t('logout'), danger: true },
  ];
  const onMore: MenuProps['onClick'] = ({ key }) => {
    if (key === 'lang') setLang(lang === 'zh-CN' ? 'en-US' : 'zh-CN');
    else if (key === 'password') setChangePwOpen(true);
    else if (key === 'github') window.open('https://github.com/nfft894htno32/relay-panel', '_blank', 'noopener,noreferrer');
    else if (key === 'logout') logout();
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {isMobile ? (
        <Drawer
          placement="left"
          open={menuOpen}
          onClose={() => setMenuOpen(false)}
          size={240}
          closable={false}
          styles={{ body: { padding: 0, background: 'var(--rp-sidebar-bg)' } }}
        >
          {brandBlock()}
          {menu}
        </Drawer>
      ) : (
        <Sider
          collapsible
          breakpoint="lg"
          width={220}
          onCollapse={(collapsed) => setSiderCollapsed(collapsed)}
          style={{
            background: 'var(--rp-sidebar-bg)',
            position: 'sticky', top: 0, height: '100vh', overflow: 'auto',
          }}
        >
          {brandBlock(siderCollapsed)}
          {menu}
        </Sider>
      )}
      <Layout>
        <Header style={{
          position: 'sticky', top: 0, zIndex: 100,
          background: '#fff', height: 'var(--rp-header-height)',
          padding: isMobile ? '0 8px 0 4px' : '0 24px', lineHeight: 'var(--rp-header-height)',
          display: 'flex', justifyContent: isMobile ? 'space-between' : 'flex-end', alignItems: 'center',
          borderBottom: '1px solid var(--rp-border)',
        }}>
          {isMobile ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, flex: '1 1 auto', minWidth: 0 }}>
                <Button type="text" icon={<MenuOutlined />} aria-label={t('openMenu')} onClick={() => setMenuOpen(true)} style={{ flexShrink: 0 }} />
                <Text strong ellipsis={{ tooltip: brand }} style={{ fontSize: 16, minWidth: 0 }}>{brand}</Text>
              </div>
              <Space size={4} style={{ flexShrink: 0 }}>
                <Dropdown menu={{ items: moreItems, onClick: onMore }} trigger={['click']} placement="bottomRight">
                  <Button type="text" icon={<EllipsisOutlined />} aria-label={t('moreActions')} />
                </Dropdown>
              </Space>
            </>
          ) : (
          <Space size="middle">
            <Segmented
              size="small"
              value={lang}
              onChange={(v) => setLang(v as 'zh-CN' | 'en-US')}
              options={[
                { value: 'zh-CN', label: t('langZhCN') },
                { value: 'en-US', label: t('langEnUS') },
              ]}
            />
            <Text type="secondary" style={{ fontSize: 13 }}>
              {isAdmin ? t('admin') : t('user')}
            </Text>
            <Button type="text" size="small" icon={<LockOutlined />} onClick={() => setChangePwOpen(true)}>
              {t('changePassword')}
            </Button>
            <Tooltip title="GitHub">
              <Button
                type="text"
                size="small"
                icon={<GithubOutlined />}
                href="https://github.com/nfft894htno32/relay-panel"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="GitHub"
              />
            </Tooltip>
            <Button type="text" size="small" icon={<LogoutOutlined />} onClick={logout}>
              {t('logout')}
            </Button>
          </Space>
          )}
        </Header>
        <Content style={{ margin: 'var(--rp-content-padding)', background: 'var(--rp-bg)' }}>
          <Suspense fallback={<div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>}>
            <Outlet />
          </Suspense>
        </Content>
      </Layout>

      <Modal
        title={t('changePassword')}
        open={changePwOpen}
        onCancel={() => { setChangePwOpen(false); pwForm.resetFields(); }}
        onOk={() => pwForm.submit()}
        okText={t('save')}
        cancelText={t('cancel')}
        confirmLoading={pwSubmitting}
      >
        <Form form={pwForm} onFinish={handleChangePassword} layout="vertical">
          <Form.Item
            name="current_password"
            label={t('currentPassword')}
            rules={[{ required: true }]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            name="new_password"
            label={t('newPassword')}
            rules={[
              { required: true, message: t('passwordRequired') },
              { validator: makePasswordValidator(t('newPasswordTooShort'), t('passwordTooLong')) },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error(t('passwordsDoNotMatch')));
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
}
