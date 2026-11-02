/* eslint-disable react-refresh/only-export-components */
import { lazy, Suspense } from 'react';
import { createBrowserRouter } from 'react-router-dom';
import { Spin } from 'antd';
import MainLayout from './layouts/MainLayout';
import { RequireAuth } from './RequireAuth';
import { RequireAdmin } from './RequireAdmin';

const Login = lazy(() => import('./pages/Login'));
const ForcePasswordChange = lazy(() => import('./pages/ForcePasswordChange'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Rules = lazy(() => import('./pages/Rules'));
const Groups = lazy(() => import('./pages/Groups'));
const NodeStatus = lazy(() => import('./pages/NodeStatus'));
const Account = lazy(() => import('./pages/Account'));
const Forbidden = lazy(() => import('./pages/Forbidden'));

function PageSpin() {
  return (
    <div style={{ textAlign: 'center', padding: 48 }}>
      <Spin />
    </div>
  );
}

function withSuspense(el: React.ReactElement) {
  return <Suspense fallback={<PageSpin />}>{el}</Suspense>;
}

export const router = createBrowserRouter([
  { path: '/login', element: withSuspense(<Login />) },
  { path: '/force-password-change', element: withSuspense(<ForcePasswordChange />) },
  {
    path: '/',
    element: <RequireAuth><MainLayout /></RequireAuth>,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'rules', element: <Rules /> },
      { path: 'groups', element: <RequireAdmin><Groups /></RequireAdmin> },
      { path: 'nodes', element: <NodeStatus /> },
      { path: 'node-status', element: <NodeStatus /> },
      { path: 'account', element: <Account /> },
      { path: '403', element: <Forbidden /> },
    ],
  },
]);
