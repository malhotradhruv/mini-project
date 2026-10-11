import React, { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Lock,
  User,
  Cpu,
  AlertCircle,
  CheckCircle2,
  Terminal,
  Zap,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const { isAuthenticated, login, register, deviceId } = useAuth();
  const navigate = useNavigate();

  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('lead_analyst');
  const [password, setPassword] = useState('SentinelSecOps!2025');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // If already authenticated, redirect to War Room
  if (isAuthenticated) {
    return <Navigate to="/war-room" replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      if (isRegister) {
        await register(username, password);
        setSuccess('Analyst profile registered successfully. Toggle to Login and sign in.');
      } else {
        await login(username, password);
        navigate('/war-room');
      }
    } catch (err: any) {
      const msg =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        'Authentication failed. Please verify credentials.';
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  };

  const shortDeviceId = deviceId ? deviceId.slice(0, 8).toUpperCase() : 'UNKNOWN';

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 flex items-center justify-center p-4 relative overflow-hidden font-mono selection:bg-cyan-500 selection:text-slate-950">
      {/* Subtle Cyber Grid Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293715_1px,transparent_1px),linear-gradient(to_bottom,#1f293715_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Dark Radar Blurs */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-[128px] pointer-events-none animate-pulse" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/10 rounded-full blur-[128px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-emerald-500/5 rounded-full blur-[140px] pointer-events-none" />

      {/* Glassmorphic Portal Card */}
      <div className="w-full max-w-md bg-slate-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-[0_0_50px_-12px_rgba(6,182,212,0.15)] p-8 relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex p-3 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 mb-3 shadow-[0_0_24px_rgba(6,182,212,0.25)]">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-slate-100">
            SENTINEL <span className="text-cyan-400">//</span> SOC COMMAND
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center justify-center space-x-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>AUTONOMOUS MULTI-AGENT SWARM PLATFORM</span>
          </p>
        </div>

        {/* Device Lock Notice Banner */}
        <div className="p-3.5 mb-5 rounded-xl bg-amber-950/30 border border-amber-500/30 text-amber-300 text-xs flex items-start space-x-2.5 shadow-[inset_0_0_12px_rgba(245,158,11,0.05)]">
          <span className="text-base leading-none">🔒</span>
          <p className="leading-relaxed text-[11px]">
            <strong className="font-semibold text-amber-200">Single-Device Session Lock Enabled.</strong> Authenticating will terminate active sessions on other browsers.
          </p>
        </div>

        {/* Hardware Fingerprint Badge */}
        <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[10px] text-slate-400 mb-6">
          <div className="flex items-center space-x-2" title={`Full Hardware Token: ${deviceId}`}>
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>HARDWARE ID:</span>
            <span className="text-cyan-300 font-bold bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
              DEV-{shortDeviceId}
            </span>
          </div>
          <span className="text-emerald-400 font-bold uppercase tracking-wider text-[9px] bg-emerald-950/50 px-1.5 py-0.5 rounded border border-emerald-500/30">
            LOCKED
          </span>
        </div>

        {/* Toggle between Analyst Login and Register Access */}
        <div className="flex border-b border-slate-800 mb-6 text-xs">
          <button
            type="button"
            onClick={() => {
              setIsRegister(false);
              setError(null);
            }}
            className={`flex-1 pb-3 text-center font-bold tracking-wider border-b-2 transition-all ${
              !isRegister
                ? 'border-cyan-400 text-cyan-400 shadow-[0_2px_12px_rgba(6,182,212,0.4)]'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            }`}
          >
            ANALYST LOGIN
          </button>
          <button
            type="button"
            onClick={() => {
              setIsRegister(true);
              setError(null);
            }}
            className={`flex-1 pb-3 text-center font-bold tracking-wider border-b-2 transition-all ${
              isRegister
                ? 'border-cyan-400 text-cyan-400 shadow-[0_2px_12px_rgba(6,182,212,0.4)]'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            }`}
          >
            REGISTER ACCESS
          </button>
        </div>

        {/* Error and Success Alerts */}
        {error && (
          <div className="p-3 mb-4 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span className="leading-tight">{error}</span>
          </div>
        )}
        {success && (
          <div className="p-3 mb-4 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span className="leading-tight">{success}</span>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1.5">
              Analyst Call-Sign / Handle
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. secops_lead"
                className="w-full bg-slate-950/90 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1.5">
              Security Key / Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950/90 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 px-4 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs tracking-wider uppercase transition-all shadow-[0_0_24px_rgba(6,182,212,0.35)] disabled:opacity-50 flex items-center justify-center space-x-2"
          >
            {loading ? (
              <span className="animate-pulse flex items-center space-x-2">
                <Zap className="w-4 h-4" />
                <span>AUTHENTICATING HARDWARE SESSION...</span>
              </span>
            ) : isRegister ? (
              <span>ENROLL NEW ANALYST</span>
            ) : (
              <span>AUTHENTICATE SESSION</span>
            )}
          </button>
        </form>

        {/* Footer Academic Reference */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center text-[10px] text-slate-400 leading-relaxed">
          Complies with IEEE Access (2025) session control. All tokens bound to cryptographic device hardware keys.
        </div>
      </div>
    </div>
  );
};

export default Login;
