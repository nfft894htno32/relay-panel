import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { NodeDisplayRow } from '../../api/types';

const { mockPut, mockPost } = vi.hoisted(() => ({ mockPut: vi.fn(), mockPost: vi.fn() }));
vi.mock('../../api/client', () => ({
  default: { put: mockPut, post: mockPost },
}));

import { NodeTrafficModal } from './NodeTrafficModal';

const GB = 1024 ** 3;

const baseRow: NodeDisplayRow = {
  group_id: 3,
  group_name: 'HK-Relay',
  node_id: 'node-hk-1',
  label: '香港主力',
  public_ipv4: '203.0.113.10',
  network_interface: 'eth0',
  online: true,
  traffic_quota: {
    total_bytes: 1000 * GB,
    used_bytes: 250 * GB,
    base_bytes: 200 * GB,
    period_upload_bytes: 20 * GB,
    period_download_bytes: 30 * GB,
    direction: 'both',
    warn_thresholds: [80, 90],
    reset_day: 1,
    last_reset_at: '2026-11-01T00:00:00Z',
    next_reset_date: '2026-12-01',
    usage_percent: 25.0,
    notified_thresholds: [],
    notified_exhausted: false,
    status: 'normal',
  },
};

beforeEach(() => {
  mockPut.mockReset();
  mockPost.mockReset();
});

describe('NodeTrafficModal', () => {
  it('omits used_bytes when the admin edits total quota without modifying used traffic', async () => {
    mockPut.mockResolvedValue({ code: 0, message: 'ok', data: baseRow.traffic_quota });
    const onSaved = vi.fn();
    const onClose = vi.fn();

    render(<NodeTrafficModal row={baseRow} open onClose={onClose} onSaved={onSaved} />);

    const totalInput = screen.getByLabelText('nodeTrafficTotal');
    fireEvent.change(totalInput, { target: { value: '500' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    const [url, body] = mockPut.mock.calls[0];
    expect(url).toBe('/nodes/3/traffic/node-hk-1');
    expect(body.total_bytes).toBe(500 * GB);
    expect(body).not.toHaveProperty('used_bytes');
    expect(body.warn_thresholds).toEqual([80, 90]);
    expect(body.reset_day).toBe(1);
    expect(onSaved).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('sends calibrated used_bytes when the admin modifies used traffic', async () => {
    mockPut.mockResolvedValue({ code: 0, message: 'ok', data: baseRow.traffic_quota });
    render(<NodeTrafficModal row={baseRow} open onClose={vi.fn()} onSaved={vi.fn()} />);

    const usedInput = screen.getByLabelText('nodeTrafficUsed');
    fireEvent.change(usedInput, { target: { value: '420' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    const [, body] = mockPut.mock.calls[0];
    expect(body.used_bytes).toBe(420 * GB);
  });

  it('resets used traffic via POST after confirmation', async () => {
    mockPost.mockResolvedValue({ code: 0, message: 'ok', data: baseRow.traffic_quota });
    const onSaved = vi.fn();
    render(<NodeTrafficModal row={baseRow} open onClose={vi.fn()} onSaved={onSaved} />);

    fireEvent.click(screen.getByRole('button', { name: /nodeTrafficResetBtn/ }));
    const confirmBtns = await screen.findAllByRole('button', { name: /nodeTrafficResetBtn/ });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/nodes/3/traffic/node-hk-1/reset'));
    expect(onSaved).toHaveBeenCalled();
  });
});
