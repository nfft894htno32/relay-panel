import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { NotifyConfigPublic, NotifyHistoryEntry } from '../api/types';

const { mockGet, mockPut, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
  mockPost: vi.fn(),
}));
vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut, post: mockPost },
}));

import NotifySettings from './NotifySettings';

const sampleConfig: NotifyConfigPublic = {
  enabled: true,
  notify_traffic: true,
  notify_offline: true,
  offline_alert_secs: 180,
  notify_recovery: false,
  notify_version_outdated: false,
  repeat_alert_minutes: 0,
  telegram_enabled: true,
  telegram_chat_id: '-100999',
  telegram_bot_token_set: true,
  email_enabled: false,
  smtp_host: '',
  smtp_port: 0,
  smtp_username: '',
  smtp_password_set: false,
  smtp_from: '',
  smtp_to: '',
  smtp_tls: false,
};

const sampleHistory: NotifyHistoryEntry[] = [
  {
    id: 'h1',
    created_at: '2026-11-21T06:00:00Z',
    event: 'traffic_threshold',
    channel: 'telegram',
    status: 'sent',
    node_key: '1:n1',
    node_label: '香港 HK-1',
    detail: '',
  },
  {
    id: 'h2',
    created_at: '2026-11-21T07:00:00Z',
    event: 'traffic_exhausted',
    channel: 'telegram',
    status: 'sent',
    node_key: '1:n1',
    node_label: '香港 HK-1',
    detail: '',
  },
];

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockPost.mockReset();
  mockGet.mockImplementation((url: string) => {
    if (url === '/admin/settings/notify') return Promise.resolve({ code: 0, message: 'ok', data: sampleConfig });
    if (url === '/admin/settings/notify/history') return Promise.resolve({ code: 0, message: 'ok', data: sampleHistory });
    return Promise.reject(new Error(`unexpected ${url}`));
  });
});

describe('NotifySettings page', () => {
  it('loads notification settings and renders traffic alert history events', async () => {
    render(<NotifySettings />);

    expect(await screen.findByText('notifyEventTrafficThreshold')).toBeInTheDocument();
    expect(screen.getByText('notifyEventTrafficExhausted')).toBeInTheDocument();
    expect(screen.getAllByText('香港 HK-1')).toHaveLength(2);
    expect(screen.getByRole('switch', { name: 'notifyTraffic' })).toBeChecked();
  });

  it('saves updated notify_traffic switch and sends telegram test notification', async () => {
    mockPut.mockResolvedValue({ code: 0, message: 'ok', data: { ...sampleConfig, notify_traffic: false } });
    mockPost.mockResolvedValue({ code: 0, message: 'ok', data: { ok: true, detail: '' } });

    render(<NotifySettings />);
    const trafficSwitch = await screen.findByRole('switch', { name: 'notifyTraffic' });
    fireEvent.click(trafficSwitch);

    const testBtns = screen.getAllByRole('button', { name: /saveAndTest/ });
    fireEvent.click(testBtns[0]);

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    expect(mockPut.mock.calls[0][0]).toBe('/admin/settings/notify');
    expect(mockPut.mock.calls[0][1].notify_traffic).toBe(false);
    await waitFor(() =>
      expect(mockPost).toHaveBeenCalledWith('/admin/settings/notify/test', { channel: 'telegram' }),
    );
  });
});
