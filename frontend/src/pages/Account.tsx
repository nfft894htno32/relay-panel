import { useEffect, useState } from 'react';
import { Card, Descriptions, Spin, Button, Space, Modal, Form, Input, message, Typography, Result } from 'antd';
import { LockOutlined, LogoutOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, UserSelf } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';
import { makePasswordValidator } from '../utils/password';
import { useAuth } from '../auth/useAuth';

const { Text } = Typography;

export default function Account() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const { logout: authLogout } = useAuth();
  const [me, setMe] = useState<UserSelf | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);

  const [changePwOpen, setChangePwOpen] = useState(false);
  const [pwForm] = Form.useForm();
  const [pwSubmitting, setPwSubmitting] = useState(false);

  const load = async () => {
    setLoading(true);
    setLoadFailed(false);
    try {
      const res = await api.get<unknown, ApiEnvelope<UserSelf>>('/user/me');
      if (res.code !== 0 || !res.data) {
        setLoadFailed(true);
        return;
      }
      setMe(res.data);
    } catch {
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

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

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>;
  }

  if (loadFailed || !me) {
    return (
      <Result
        status="warning"
        title={t('accountLoadFailed')}
        extra={<Button type="primary" onClick={load}>{t('refresh')}</Button>}
      />
    );
  }

  return (
    <>
      <Card
        title={t('myAccount')}
        extra={
          <Space>
            <Button icon={<LockOutlined />} onClick={() => setChangePwOpen(true)}>{t('changePassword')}</Button>
            <Button danger icon={<LogoutOutlined />} onClick={logout}>{t('logout')}</Button>
          </Space>
        }
      >
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label={t('accountUsername')}>
            <Text strong>{me.username}</Text>
            {me.admin && <Text type="secondary"> ({t('admin')})</Text>}
          </Descriptions.Item>
          <Descriptions.Item label={t('forwardRules')}>
            {me.current_rules}
          </Descriptions.Item>
          <Descriptions.Item label={t('accountTrafficUsed')}>
            <span>{formatBytes(me.traffic_used)}</span>
          </Descriptions.Item>
          <Descriptions.Item label={t('accountMemberSince')}>
            <span className="rp-mono">{me.registered_at || '-'}</span>
          </Descriptions.Item>
        </Descriptions>
      </Card>

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
    </>
  );
}
