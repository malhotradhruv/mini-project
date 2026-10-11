import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { Login } from './pages/Login';
import { WarRoom } from './pages/WarRoom';
import { Topology } from './pages/Topology';
import { Incidents } from './pages/Incidents';
import { Integrations } from './pages/Integrations';
import { BenchmarksPage } from './pages/BenchmarksPage';

// Protected Route Guard Layout
const ProtectedDashboardLayout: React.FC = () => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      <Sidebar />
      <main className="flex-1 h-screen overflow-y-auto bg-slate-950">
        <Outlet />
      </main>
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Authentication Route */}
          <Route path="/login" element={<Login />} />

          {/* Protected Enterprise SOC Routes */}
          <Route element={<ProtectedDashboardLayout />}>
            <Route path="/" element={<Navigate to="/war-room" replace />} />
            <Route path="/war-room" element={<WarRoom />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/benchmarks" element={<BenchmarksPage />} />
          </Route>

          {/* Fallback Catch-All */}
          <Route path="*" element={<Navigate to="/war-room" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
