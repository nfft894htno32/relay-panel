import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../api/client', () => ({ default: { get: vi.fn(), put: vi.fn() } }));
const { mockLogout } = vi.hoisted(() => ({ mockLogout: vi.fn() }));
vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ isAdmin: true, user: { id: 1, username: 'admin' }, logout: mockLogout }),
}));
const { mockIsMobile } = vi.hoisted(() => ({ mockIsMobile: vi.fn(() => false) }));
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: mockIsMobile }));

import MainLayout from './MainLayout';

const renderAt = (path = '/') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<div>home page</div>} />
          <Route path="rules" element={<div>rules page</div>} />
          <Route path="login" element={<div>login page</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  mockIsMobile.mockReset();
  mockLogout.mockReset();
});

describe('MainLayout on a desktop', () => {
  it('keeps the sider and the header bar in place while the page scrolls', () => {
    mockIsMobile.mockReturnValue(false);
    const { container } = renderAt();
    const sider = container.querySelector('.ant-layout-sider') as HTMLElement;
    expect(sider.style.position).toBe('sticky');
    expect(sider.style.height).toBe('100vh');
    const header = container.querySelector('.ant-layout-header') as HTMLElement;
    expect(header.style.position).toBe('sticky');
    expect(Number(header.style.zIndex)).toBeGreaterThan(15);
  });

  it('keeps the sider and the labelled header controls', () => {
    mockIsMobile.mockReturnValue(false);
    const { container } = renderAt();
    expect(container.querySelector('.ant-layout-sider')).not.toBeNull();
    expect(screen.queryByRole('button', { name: 'openMenu' })).toBeNull();
    expect(screen.getByText('changePassword')).toBeInTheDocument();
  });
});

describe('MainLayout on a phone', () => {
  it('has no sider; the menu opens from a header button and closes on navigation', async () => {
    mockIsMobile.mockReturnValue(true);
    const user = userEvent.setup();
    const { container } = renderAt();
    expect(container.querySelector('.ant-layout-sider')).toBeNull();
    expect(screen.queryByText('forwardRules')).toBeNull();

    await user.click(screen.getByRole('button', { name: 'openMenu' }));
    await user.click(await screen.findByText('forwardRules'));

    expect(await screen.findByText('rules page')).toBeInTheDocument();
    await waitFor(() => expect(container.ownerDocument.querySelector('.ant-drawer-open')).toBeNull());
  });

  it('folds the header controls into one menu that says who is signed in', async () => {
    mockIsMobile.mockReturnValue(true);
    const user = userEvent.setup();
    renderAt();

    await user.click(screen.getByRole('button', { name: 'moreActions' }));
    expect(await screen.findByText('admin · admin')).toBeInTheDocument();
    expect(screen.getByText('changePassword')).toBeInTheDocument();

    await user.click(screen.getByText('logout'));
    expect(mockLogout).toHaveBeenCalled();
  });
});
