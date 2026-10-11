import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Radio,
  Network,
  Database,
  Plug,
  Award,
  LogOut,
  ShieldAlert,
  Cpu,
  UserCheck,
  Lock,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Sidebar: React.FC = () => {
  const { username, role, deviceId, logout } = useAuth();

  const navItems = [
    { to: '/war-room',    label: 'Live War Room',        icon: Radio,    badge: 'LIVE'  },
    { to: '/topology',   label: 'Attack Topology',       icon: Network,  badge: null    },
    { to: '/incidents',  label: 'Incident Archive',      icon: Database, badge: null    },
    { to: '/integrations', label: 'Data Feeds',          icon: Plug,     badge: null    },
    { to: '/benchmarks', label: 'IEEE Benchmarks',       icon: Award,    badge: null    },
  ];

  const shortDeviceId = deviceId ? deviceId.slice(0, 8).toUpperCase() : 'UNKNOWN';

  return (
    <aside
      className="w-64 h-screen flex flex-col justify-between shrink-0 select-none z-30"
      style={{
        background: 'rgba(5, 6, 9, 0.97)',
        borderRight: '1px solid var(--edge)',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
      }}
    >

      {/* ── Brand Header ── */}
      <div>
        <div
          className="px-4 py-4"
          style={{ borderBottom: '1px solid var(--edge)' }}
        >
          {/* Logo row */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2.5">
              <div
                className="p-1.5 rounded-md"
                style={{
                  background: 'var(--cyan-subtle)',
                  border: '1px solid var(--cyan-dim)',
                  color: 'var(--cyan)',
                  boxShadow: '0 0 12px var(--cyan-subtle)',
                }}
              >
                <ShieldAlert className="w-4 h-4" />
              </div>
              <span
                className="font-mono text-xs font-bold tracking-[0.12em]"
                style={{ color: 'var(--text-primary)' }}
              >
                SENTINEL <span style={{ color: 'var(--cyan)' }}>//</span> SOC
              </span>
            </div>

            {/* Online badge */}
            <div
              className="flex items-center gap-1.5 px-2 py-0.5 rounded-full"
              style={{
                background: 'var(--emerald-subtle)',
                border: '1px solid var(--emerald-dim)',
              }}
            >
              <span
                className="live-dot"
                style={{ color: 'var(--emerald)', width: '6px', height: '6px' }}
              />
              <span
                className="font-mono text-[9px] font-bold tracking-widest"
                style={{ color: 'var(--emerald)' }}
              >
                ONLINE
              </span>
            </div>
          </div>

          {/* Subtitle */}
          <p className="font-mono text-[10px] tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
            AUTONOMOUS CYBER WAR ROOM
          </p>
        </div>

        {/* ── Navigation ── */}
        <nav className="p-2 mt-1">
          {/* Section label */}
          <div
            className="px-3 py-1.5 font-mono text-[9px] font-bold tracking-[0.18em] uppercase mb-1"
            style={{ color: 'var(--text-tertiary)' }}
          >
            Navigation Console
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className="block"
              >
                {({ isActive }) => (
                  <div
                    className={`
                      nav-active-indicator flex items-center justify-between px-3 py-2.5 rounded-md mb-0.5
                      font-mono text-[11px] font-medium transition-all duration-150
                      ${isActive ? '' : 'glass-interactive'}
                    `}
                    style={
                      isActive
                        ? {
                            background: 'rgba(0, 240, 255, 0.06)',
                            border: '1px solid var(--cyan-dim)',
                            color: 'var(--cyan)',
                            boxShadow: 'inset 0 0 12px rgba(0,240,255,0.06)',
                          }
                        : {
                            color: 'var(--text-tertiary)',
                          }
                    }
                  >
                    <div className="flex items-center gap-3">
                      <Icon className="w-3.5 h-3.5 shrink-0" />
                      <span>{item.label}</span>
                    </div>

                    {item.badge && (
                      <span
                        className="badge badge-crimson text-[8px] animate-pulse"
                      >
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* ── Bottom Panel — Analyst Identity ── */}
      <div
        className="p-3"
        style={{ borderTop: '1px solid var(--edge)' }}
      >
        {/* Identity Card */}
        <div
          className="p-2.5 rounded-md mb-2.5"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--edge)',
          }}
        >
          {/* Username + Role */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 min-w-0">
              <UserCheck className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cyan)' }} />
              <div className="min-w-0">
                <p className="font-mono text-[11px] font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                  {username || 'SecOps_Analyst'}
                </p>
                <p className="font-mono text-[9px] tracking-widest uppercase" style={{ color: 'var(--cyan)' }}>
                  {role || 'ANALYST'}
                </p>
              </div>
            </div>
          </div>

          {/* Device Lock */}
          <div
            className="flex items-center justify-between pt-2"
            style={{ borderTop: '1px solid var(--edge-subtle)' }}
          >
            <div className="flex items-center gap-1.5" title={`Device Token: ${deviceId}`}>
              <Lock className="w-2.5 h-2.5" style={{ color: 'var(--text-tertiary)' }} />
              <span className="font-mono text-[9px]" style={{ color: 'var(--text-tertiary)' }}>LOCK:</span>
              <span
                className="data-chip"
                style={{ fontSize: '9px', color: 'var(--text-secondary)' }}
              >
                {shortDeviceId}
              </span>
            </div>
            <span className="font-mono text-[9px] font-bold tracking-wider" style={{ color: 'var(--emerald)' }}>
              SECURED
            </span>
          </div>
        </div>

        {/* Terminate Session */}
        <button
          onClick={logout}
          className="btn btn-danger w-full text-[10px] py-2"
        >
          <LogOut className="w-3 h-3" />
          TERMINATE SESSION
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
