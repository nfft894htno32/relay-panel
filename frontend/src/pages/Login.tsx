import { Form, Input, Button, Card, message, Typography, Segmented } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, LoginResponse } from '../api/types';
import { useI18n } from '../i18n/context';
import { useAuth } from '../auth/useAuth';
import { useSite } from '../hooks/useSite';

const { Title, Text } = Typography;

export default function Login() {
  const navigate = useNavigate();
  const { t, lang, setLang } = useI18n();
  const { login } = useAuth();
  const site = useSite();

  const onFinish = async (values: { username: string; password: string }) => {
    try {
      const res = await api.post<unknown, ApiEnvelope<LoginResponse>>('/auth/login', values);
      if (res.code !== 0 || !res.data) {
        message.error(res.message || t('loginFailedMsg'));
        return;
      }
      await login(res.data.token);
      message.success(t('loginSuccess'));
      navigate('/');
    } catch {
      message.error(t('loginFailed'));
    }
  };

  return (
    <div style={{
      display: 'flex', justifyContent: 'center', alignItems: 'center',
      minHeight: '100vh', background: 'var(--rp-bg)',
      padding: '56px 16px',
      boxSizing: 'border-box',
    }}>
      <div style={{ position: 'absolute', top: 20, right: 24 }}>
        <Segmented
          size="small"
          value={lang}
          onChange={(v) => setLang(v as 'zh-CN' | 'en-US')}
          options={[
            { value: 'zh-CN', label: t('langZhCN') },
            { value: 'en-US', label: t('langEnUS') },
          ]}
        />
      </div>
      <Card style={{ width: '100%', maxWidth: 380, boxShadow: 'var(--rp-shadow)' }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <Title level={3} style={{ margin: 0, fontWeight: 600 }}>{site.site_name || t('brand')}</Title>
          <Text type="secondary" style={{ fontSize: 13 }}>{site.subtitle || t('subtitle')}</Text>
        </div>

        <Form onFinish={onFinish} size="large">
          <Form.Item name="username" rules={[{ required: true, message: t('usernameRequired') }]}>
            <Input prefix={<UserOutlined style={{ color: 'var(--rp-text-tertiary)' }} />} placeholder={t('username')} aria-label={t('username')} />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: t('passwordRequired') }]}>
            <Input.Password prefix={<LockOutlined style={{ color: 'var(--rp-text-tertiary)' }} />} placeholder={t('password')} aria-label={t('password')} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 12 }}>
            <Button type="primary" htmlType="submit" block>{t('login')}</Button>
          </Form.Item>
        </Form>
        <div style={{ marginTop: 16, textAlign: 'center' }}>
          <a
            href="https://github.com/nfft894htno32/relay-panel"
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontSize: 12, color: 'var(--rp-text-tertiary)' }}
          >
            {t('sourceCode')}
          </a>
        </div>
      </Card>
    </div>
  );
}
