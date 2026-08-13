import { lazy, Suspense, type ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './lib/auth'
import { PageLoading } from './components/Feedback'
import { AppShell } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'

const DashboardPage = lazy(() => import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })))
const RealmsPage = lazy(() => import('./pages/RealmsPage').then((module) => ({ default: module.RealmsPage })))
const UsersPage = lazy(() => import('./pages/UsersPage').then((module) => ({ default: module.UsersPage })))
const ClientsPage = lazy(() => import('./pages/ClientsPage').then((module) => ({ default: module.ClientsPage })))
const RolesPage = lazy(() => import('./pages/RolesPage').then((module) => ({ default: module.RolesPage })))
const SessionsPage = lazy(() => import('./pages/SessionsPage').then((module) => ({ default: module.SessionsPage })))
const KeysPage = lazy(() => import('./pages/KeysPage').then((module) => ({ default: module.KeysPage })))
const ApprovalsPage = lazy(() => import('./pages/ApprovalsPage').then((module) => ({ default: module.ApprovalsPage })))
const AuditPage = lazy(() => import('./pages/OperationsPages').then((module) => ({ default: module.AuditPage })))
const LogsPage = lazy(() => import('./pages/OperationsPages').then((module) => ({ default: module.LogsPage })))
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage').then((module) => ({ default: module.IntegrationsPage })))
const ProfilePage = lazy(() => import('./pages/PersonalPages').then((module) => ({ default: module.ProfilePage })))
const PersonalSecurityPage = lazy(() => import('./pages/PersonalPages').then((module) => ({ default: module.PersonalSecurityPage })))
const PersonalSessionsPage = lazy(() => import('./pages/PersonalPages').then((module) => ({ default: module.PersonalSessionsPage })))
const APIKeysPage = lazy(() => import('./pages/PersonalPages').then((module) => ({ default: module.APIKeysPage })))
const PersonalRequestsPage = lazy(() => import('./pages/PersonalPages').then((module) => ({ default: module.PersonalRequestsPage })))

function ProtectedLayout() {
  const { loading, authenticated } = useAuth()
  if (loading) return <PageLoading label="세션을 확인하는 중" />
  if (!authenticated) return <Navigate to="/login" replace />
  return <AppShell />
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  return me?.permissions.platform_admin ? children : <Navigate to="/personal" replace />
}

export default function App() {
  return (
    <Suspense fallback={<PageLoading label="화면을 준비하는 중" />}><Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedLayout />}>
        <Route index element={<Navigate to="/personal" replace />} />
        <Route path="/personal" element={<ProfilePage />} />
        <Route path="/personal/security" element={<PersonalSecurityPage />} />
        <Route path="/personal/api-keys" element={<APIKeysPage />} />
        <Route path="/personal/sessions" element={<PersonalSessionsPage />} />
        <Route path="/personal/requests" element={<PersonalRequestsPage />} />
        <Route path="/admin" element={<AdminOnly><DashboardPage /></AdminOnly>} />
        <Route path="/admin/realms" element={<AdminOnly><RealmsPage /></AdminOnly>} />
        <Route path="/admin/realms/:realmId" element={<AdminOnly><RealmsPage /></AdminOnly>} />
        <Route path="/admin/users" element={<AdminOnly><UsersPage /></AdminOnly>} />
        <Route path="/admin/clients" element={<AdminOnly><ClientsPage /></AdminOnly>} />
        <Route path="/admin/roles" element={<AdminOnly><RolesPage /></AdminOnly>} />
        <Route path="/admin/sessions" element={<AdminOnly><SessionsPage /></AdminOnly>} />
        <Route path="/admin/keys" element={<AdminOnly><KeysPage /></AdminOnly>} />
        <Route path="/admin/approvals" element={<AdminOnly><ApprovalsPage /></AdminOnly>} />
        <Route path="/admin/audit" element={<AdminOnly><AuditPage /></AdminOnly>} />
        <Route path="/admin/logs" element={<AdminOnly><LogsPage /></AdminOnly>} />
        <Route path="/admin/integrations" element={<AdminOnly><IntegrationsPage /></AdminOnly>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes></Suspense>
  )
}
