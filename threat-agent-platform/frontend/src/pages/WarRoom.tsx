import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Crown,
  Mail,
  FileText,
  Globe,
  Skull,
  ShieldCheck,
  Zap,
  Shield,
  Activity,
  Cpu,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Layers,
  AlertTriangle,
  Radio,
  Crosshair,
  Loader2,
  Lock,
} from 'lucide-react';
import { SCENARIO_A_COORDINATED, SCENARIO_B_BENIGN } from '../components/TelemetryIngestion';
import { API_BASE_URL } from '../context/AuthContext';

// ─────────────────────────────────────────────────────────────────────────────
// Agent Design System Configuration & Accents
// ─────────────────────────────────────────────────────────────────────────────
interface AgentStyling {
  name: string;
  role: string;
  icon: React.ElementType;
  badgeClass: string;
  borderLeftColor: string;
  accentColor: string;
  avatarBg: string;
  isAdversary?: boolean;
}

const AGENT_CONFIG: Record<string, AgentStyling> = {
  LeadSupervisor: {
    name: 'LeadSupervisor',
    role: 'Orchestrator & Swarm Conductor',
    icon: Crown,
    badgeClass: 'badge-amber',
    borderLeftColor: 'var(--amber)',
    accentColor: 'var(--amber)',
    avatarBg: 'rgba(255, 170, 0, 0.12)',
  },
  EmailHunter: {
    name: 'EmailHunter',
    role: 'Phishing & Header Specialist',
    icon: Mail,
    badgeClass: 'badge-cyan',
    borderLeftColor: 'var(--cyan)',
    accentColor: 'var(--cyan)',
    avatarBg: 'rgba(0, 240, 255, 0.12)',
  },
  LogForensics: {
    name: 'LogForensics',
    role: 'Syslog & Auth Forensics Specialist',
    icon: FileText,
    badgeClass: 'badge-emerald',
    borderLeftColor: 'var(--emerald)',
    accentColor: 'var(--emerald)',
    avatarBg: 'rgba(0, 229, 153, 0.12)',
  },
  NetworkRecon: {
    name: 'NetworkRecon',
    role: 'Attack Surface & Daemon Specialist',
    icon: Globe,
    badgeClass: 'badge-cyan',
    borderLeftColor: 'var(--cyan)',
    accentColor: 'var(--cyan)',
    avatarBg: 'rgba(0, 240, 255, 0.12)',
  },
  RedTeamAdversarySim: {
    name: 'RedTeamAdversarySim',
    role: 'Offensive Adversary Simulation',
    icon: Skull,
    badgeClass: 'badge-crimson',
    borderLeftColor: 'var(--crimson)',
    accentColor: 'var(--crimson)',
    avatarBg: 'rgba(255, 30, 68, 0.15)',
    isAdversary: true,
  },
  RedTeamSim: {
    name: 'RedTeamAdversarySim',
    role: 'Offensive Adversary Simulation',
    icon: Skull,
    badgeClass: 'badge-crimson',
    borderLeftColor: 'var(--crimson)',
    accentColor: 'var(--crimson)',
    avatarBg: 'rgba(255, 30, 68, 0.15)',
    isAdversary: true,
  },
  BlueTeamCommander: {
    name: 'BlueTeamCommander',
    role: 'Active Mitigation & SOAR Playbooks',
    icon: ShieldCheck,
    badgeClass: 'badge-violet',
    borderLeftColor: 'var(--violet)',
    accentColor: 'var(--violet)',
    avatarBg: 'rgba(139, 92, 246, 0.12)',
  },
};

const DEFAULT_AGENT_CONFIG: AgentStyling = {
  name: 'SecurityAgent',
  role: 'Swarm Worker',
  icon: Shield,
  badgeClass: 'badge-neutral',
  borderLeftColor: 'var(--cyan)',
  accentColor: 'var(--cyan)',
  avatarBg: 'rgba(255, 255, 255, 0.08)',
};

// ─────────────────────────────────────────────────────────────────────────────
// Typed Contracts
// ─────────────────────────────────────────────────────────────────────────────
interface AgentMessageItem {
  sender: string;
  recipient: string;
  action_type: string;
  content: string;
  artifacts?: Record<string, any>;
  timestamp: string;
}

interface SpecialistFindingItem {
  agent_id: string;
  is_malicious: boolean;
  confidence_score?: number;
  confidence?: number;
  summary: string;
  technical_indicators?: string[];
}

interface SwarmReport {
  threat_severity: string;
  consensus_confidence: number;
  root_cause_analysis: string;
  correlated_entities: Record<string, any>;
  containment_commands: string[];
}

export const WarRoom: React.FC = () => {
  // Telemetry Input States
  const [emailText, setEmailText] = useState(SCENARIO_A_COORDINATED.email_text);
  const [logText, setLogText] = useState(SCENARIO_A_COORDINATED.log_text);
  const [targetNetwork, setTargetNetwork] = useState(SCENARIO_A_COORDINATED.target_network);
  const [showTelemetryDrawer, setShowTelemetryDrawer] = useState(false);

  // Swarm Execution States
  const [messages, setMessages] = useState<AgentMessageItem[]>([]);
  const [findings, setFindings] = useState<SpecialistFindingItem[]>([]);
  const [report, setReport] = useState<SwarmReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [iterationCount, setIterationCount] = useState<number>(0);
  const [activeScenario, setActiveScenario] = useState<'A' | 'B' | 'CUSTOM'>('A');

  // Right Drawer Tab State
  const [rightTab, setRightTab] = useState<'specialists' | 'containment'>('specialists');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedChip, setCopiedChip] = useState<string | null>(null);
  const [expandedSpecialists, setExpandedSpecialists] = useState<Record<string, boolean>>({
    EmailHunter: true,
    LogForensics: true,
    NetworkRecon: true,
  });

  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll message feed
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Load Scenario A: Coordinated Multi-Stage Breach
  const handleLoadScenarioA = () => {
    setEmailText(SCENARIO_A_COORDINATED.email_text);
    setLogText(SCENARIO_A_COORDINATED.log_text);
    setTargetNetwork(SCENARIO_A_COORDINATED.target_network);
    setActiveScenario('A');
  };

  // Load Scenario B: Benign Routine Telemetry
  const handleLoadScenarioB = () => {
    setEmailText(SCENARIO_B_BENIGN.email_text);
    setLogText(SCENARIO_B_BENIGN.log_text);
    setTargetNetwork(SCENARIO_B_BENIGN.target_network);
    setActiveScenario('B');
  };

  // Execute Swarm Investigation
  const handleEngageSwarm = async () => {
    setIsLoading(true);
    setMessages([]);
    setFindings([]);
    setReport(null);
    setIterationCount(1);

    try {
      const res = await axios.post(`${API_BASE_URL}/api/v1/swarm/investigate`, {
        raw_email: emailText,
        raw_logs: logText,
        target_cidr: targetNetwork,
      });

      const data = res.data;
      setMessages(data.messages || []);
      setFindings(data.specialist_findings || []);
      setReport(data.report || null);
      setIterationCount(Math.min(8, Math.max(3, (data.messages || []).length)));

      // Auto-switch to SOAR Playbook if malicious consensus reached
      if (data.report && data.report.threat_severity !== 'BENIGN') {
        setRightTab('containment');
      }
    } catch (err: any) {
      console.error('War room execution failed:', err);
      alert('Swarm investigation failed. Ensure backend server is running on http://127.0.0.1:8080');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyChip = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedChip(val);
    setTimeout(() => setCopiedChip(null), 1500);
  };

  const toggleSpecialist = (agentId: string) => {
    setExpandedSpecialists((prev) => ({
      ...prev,
      [agentId]: !prev[agentId],
    }));
  };

  // Extract structured artifact chips from message artifacts
  const renderArtifactChips = (artifacts?: Record<string, any>) => {
    if (!artifacts) return null;
    const chips: { label: string; value: string; color: string }[] = [];

    if (artifacts.ips && Array.isArray(artifacts.ips)) {
      artifacts.ips.forEach((ip: string) =>
        chips.push({ label: 'IP', value: ip, color: 'text-cyan-400 border-cyan-500/40 bg-cyan-950/40' })
      );
    }
    if (artifacts.cves && Array.isArray(artifacts.cves)) {
      artifacts.cves.forEach((cve: string) =>
        chips.push({ label: 'CVE', value: cve, color: 'text-crimson border-crimson/40 bg-crimson-950/40' })
      );
    }
    if (artifacts.domains && Array.isArray(artifacts.domains)) {
      artifacts.domains.forEach((d: string) =>
        chips.push({ label: 'DOMAIN', value: d, color: 'text-amber-400 border-amber-500/40 bg-amber-950/40' })
      );
    }
    if (artifacts.technique_id) {
      chips.push({
        label: 'MITRE',
        value: String(artifacts.technique_id),
        color: 'text-violet-400 border-violet-500/40 bg-violet-950/40',
      });
    }

    if (chips.length === 0) return null;

    return (
      <div
        className="flex flex-wrap items-center gap-1.5 mt-2.5 pt-2"
        style={{ borderTop: '1px solid var(--edge-subtle)' }}
      >
        <span className="font-mono text-[9px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
          Discovered Entities:
        </span>
        {chips.map((chip, i) => (
          <button
            key={i}
            onClick={() => handleCopyChip(chip.value)}
            className={`data-chip transition-all hover:scale-105 active:scale-95 cursor-pointer ${chip.color}`}
            title="Click to copy entity"
          >
            <span className="font-bold opacity-75">{chip.label}:</span>
            <span>{chip.value}</span>
            {copiedChip === chip.value ? (
              <Check className="w-2.5 h-2.5 text-emerald-400" />
            ) : null}
          </button>
        ))}
      </div>
    );
  };

  const consensusReached = Boolean(report);
  const isMalicious = report && report.threat_severity !== 'BENIGN';

  // Extract RedTeam MITRE technique if present in findings or report
  const adversaryTechnique =
    report?.correlated_entities?.mitre_technique ||
    messages.find((m) => m.sender.includes('RedTeam'))?.artifacts?.technique_id ||
    (isMalicious ? 'T1078 Valid Accounts (SSH Harvested)' : 'T1595 Active Scanning (Mitigated)');

  return (
    <div
      className="h-full flex flex-col font-mono overflow-hidden select-none"
      style={{
        background: 'var(--canvas)',
        color: 'var(--text-primary)',
      }}
    >
      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* 1. Top HUD Strip                                                    */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      <header
        className="px-5 py-3 flex flex-wrap items-center justify-between gap-3 shrink-0 z-20"
        style={{
          background: 'var(--surface)',
          borderBottom: '1px solid var(--edge)',
        }}
      >
        {/* Left: Scenario Presets & Telemetry Toggle */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Scenario Trigger A */}
          <button
            onClick={handleLoadScenarioA}
            disabled={isLoading}
            className={`btn text-xs ${
              activeScenario === 'A'
                ? 'btn-danger shadow-glow-crimson'
                : 'btn-ghost'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-crimson" />
            <span>⚡ Scenario A: Coordinated Multi-Stage Breach</span>
          </button>

          {/* Scenario Trigger B */}
          <button
            onClick={handleLoadScenarioB}
            disabled={isLoading}
            className={`btn text-xs ${
              activeScenario === 'B'
                ? 'border-emerald-500/60 bg-emerald-950/40 text-emerald-300 shadow-glow-emerald'
                : 'btn-ghost'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>🛡️ Scenario B: Benign Routine Telemetry</span>
          </button>

          {/* Collapsible Telemetry Inspector Toggle */}
          <button
            onClick={() => setShowTelemetryDrawer(!showTelemetryDrawer)}
            className="btn btn-ghost text-xs"
            title="Inspect or modify raw input telemetry"
          >
            <Terminal className="w-3.5 h-3.5" style={{ color: 'var(--cyan)' }} />
            <span>Input Telemetry</span>
            {showTelemetryDrawer ? (
              <ChevronUp className="w-3 h-3 ml-1" />
            ) : (
              <ChevronDown className="w-3 h-3 ml-1" />
            )}
          </button>
        </div>

        {/* Right: Model status, Iterations, Consensus, Primary CTA */}
        <div className="flex items-center gap-2.5">
          {/* Active Model Indicator with live-dot */}
          <div
            className="hidden lg:flex items-center gap-2 px-2.5 py-1.5 rounded-md"
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--edge)',
            }}
          >
            <span className="live-dot" style={{ color: 'var(--cyan)' }} />
            <Cpu className="w-3.5 h-3.5" style={{ color: 'var(--cyan)' }} />
            <span className="font-mono text-[10px] tracking-wide" style={{ color: 'var(--text-secondary)' }}>
              LLaMA 3.3-70B via Groq
            </span>
          </div>

          {/* Iteration Counter */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md"
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--edge)',
            }}
          >
            <Activity className="w-3.5 h-3.5" style={{ color: 'var(--amber)' }} />
            <span className="font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
              ITERATIONS:{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{iterationCount} / 8</strong>
            </span>
          </div>

          {/* Consensus Badge */}
          <div>
            {isLoading ? (
              <span className="badge badge-amber animate-pulse">
                <span className="live-dot" style={{ color: 'var(--amber)' }} />
                DELIBERATING
              </span>
            ) : consensusReached ? (
              <span className={`badge ${isMalicious ? 'severity-critical' : 'badge-emerald'}`}>
                <span className="live-dot" style={{ color: isMalicious ? 'var(--crimson)' : 'var(--emerald)' }} />
                {report?.threat_severity || 'CONSENSUS'} ({Math.round(report?.consensus_confidence * 100)}%)
              </span>
            ) : (
              <span className="badge badge-neutral">STANDBY</span>
            )}
          </div>

          {/* Primary Action Button: ENGAGE AGENT SWARM */}
          <button
            onClick={handleEngageSwarm}
            disabled={isLoading}
            className="btn btn-primary py-2 px-3.5 text-xs shadow-glow-cyan"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-cyan" />
                <span>SWARM ACTIVE...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                <span>🚀 ENGAGE AGENT SWARM</span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* Collapsible Raw Telemetry Inspector Drawer                         */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {showTelemetryDrawer && (
        <div
          className="p-4 shrink-0 transition-all z-10 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs animate-fade-up"
          style={{
            background: 'var(--surface-2)',
            borderBottom: '1px solid var(--edge)',
          }}
        >
          <div>
            <label
              className="block font-mono text-[10px] font-bold uppercase mb-1"
              style={{ color: 'var(--cyan)' }}
            >
              Raw Phishing Lure / Email Telemetry
            </label>
            <textarea
              rows={3}
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
              className="input-field text-[11px]"
              placeholder="Paste raw email RFC-822 headers or phishing text..."
            />
          </div>
          <div>
            <label
              className="block font-mono text-[10px] font-bold uppercase mb-1"
              style={{ color: 'var(--emerald)' }}
            >
              Raw Authentication / Syslog Stream
            </label>
            <textarea
              rows={3}
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              className="input-field text-[11px]"
              placeholder="Paste SSH auth.log, failed password, or daemon syslog telemetry..."
            />
          </div>
          <div>
            <label
              className="block font-mono text-[10px] font-bold uppercase mb-1"
              style={{ color: 'var(--amber)' }}
            >
              Target Network CIDR / Subnet Scope
            </label>
            <input
              type="text"
              value={targetNetwork}
              onChange={(e) => setTargetNetwork(e.target.value)}
              className="input-field text-[11px]"
              placeholder="192.168.1.105 or 10.0.0.0/24"
            />
            <p className="font-mono text-[9px] mt-1.5" style={{ color: 'var(--text-tertiary)' }}>
              Scope bound to single-host or CIDR perimeter for active daemon scanning.
            </p>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* Main Split Layout: 65% Mission Control Stream & 35% Specialist Drawer */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      <div className="flex-1 flex overflow-hidden">
        {/* ── Left Panel (65% width): Mission Control Dialogue Stream ── */}
        <div
          className="w-[65%] flex flex-col h-full overflow-hidden"
          style={{
            background: 'var(--canvas)',
            borderRight: '1px solid var(--edge)',
          }}
        >
          {/* Panel Header */}
          <div
            className="section-header shrink-0"
            style={{ borderRadius: 0 }}
          >
            <div className="flex items-center gap-2">
              <span className="live-dot" style={{ color: 'var(--emerald)' }} />
              <span className="section-title">WAR-ROOM DIALOGUE STREAM</span>
              <span
                className="font-mono text-[10px] font-semibold"
                style={{ color: 'var(--text-tertiary)' }}
              >
                ({messages.length} exchanges recorded)
              </span>
            </div>

            {/* Specialist Legend */}
            <div className="hidden md:flex items-center gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1.5" style={{ color: 'var(--amber)' }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--amber)' }} />
                Supervisor
              </span>
              <span className="flex items-center gap-1.5" style={{ color: 'var(--cyan)' }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--cyan)' }} />
                Specialists
              </span>
              <span className="flex items-center gap-1.5" style={{ color: 'var(--crimson)' }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--crimson)' }} />
                Red Team
              </span>
              <span className="flex items-center gap-1.5" style={{ color: 'var(--violet)' }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: 'var(--violet)' }} />
                Blue Team
              </span>
            </div>
          </div>

          {/* Dialogue Messages Stream with auto-scroll */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3 panel-scroll scroll-terminal">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center p-8 text-center">
                <div
                  className="p-4 rounded-xl mb-3"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--edge)',
                  }}
                >
                  <Radio className="w-8 h-8 animate-pulse" style={{ color: 'var(--cyan)' }} />
                </div>
                <h3 className="font-mono text-sm font-bold tracking-wide" style={{ color: 'var(--text-primary)' }}>
                  War Room Channel Silent
                </h3>
                <p
                  className="font-mono text-xs max-w-md mt-1 leading-relaxed"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  Stage telemetry using <strong style={{ color: 'var(--text-secondary)' }}>Scenario A</strong> or{' '}
                  <strong style={{ color: 'var(--text-secondary)' }}>B</strong>, then click{' '}
                  <strong style={{ color: 'var(--cyan)' }}>[🚀 ENGAGE AGENT SWARM]</strong> to trigger autonomous
                  multi-agent debate.
                </p>
                <div className="terminal-cursor font-mono text-xs mt-3" style={{ color: 'var(--cyan)' }}>
                  awaiting_telemetry_signal
                </div>
              </div>
            ) : (
              messages.map((msg, index) => {
                const config = AGENT_CONFIG[msg.sender] || DEFAULT_AGENT_CONFIG;
                const IconComponent = config.icon;
                const actionType = msg.action_type || 'ANALYZE';

                return (
                  <div
                    key={index}
                    className="p-3.5 transition-all animate-stream-in relative group"
                    style={{
                      background: 'var(--surface)',
                      border: '1px solid var(--edge)',
                      borderLeft: `3px solid ${config.borderLeftColor}`,
                      borderRadius: '6px',
                    }}
                  >
                    {/* Header Row: Avatar, Sender, Recipient, Action Chip, Timestamp */}
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2 min-w-0">
                        {/* Avatar */}
                        <div
                          className="w-7 h-7 rounded flex items-center justify-center shrink-0 border"
                          style={{
                            background: config.avatarBg,
                            borderColor: config.borderLeftColor,
                            color: config.accentColor,
                          }}
                          title={`${config.name} (${config.role})`}
                        >
                          <IconComponent className="w-4 h-4" />
                        </div>

                        {/* Agent Sender Badge */}
                        <span className={`badge ${config.badgeClass}`}>
                          {msg.sender}
                        </span>

                        {/* Direction Arrow */}
                        <span className="font-mono text-xs" style={{ color: 'var(--text-tertiary)' }}>➔</span>

                        {/* Target / Recipient Badge */}
                        <span
                          className="data-chip font-semibold"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {msg.recipient}
                        </span>

                        {/* Action Type Chip */}
                        <span
                          className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider uppercase"
                          style={{
                            background: 'var(--surface-2)',
                            border: '1px solid var(--edge)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          [{actionType}]
                        </span>

                        {/* Red Team Pulsating Warning Tag */}
                        {config.isAdversary && (
                          <span className="badge severity-critical animate-pulse text-[9px]">
                            <AlertTriangle className="w-2.5 h-2.5" />
                            OFFENSIVE ADVERSARY SIMULATION
                          </span>
                        )}
                      </div>

                      {/* Timestamp */}
                      <span
                        className="font-mono text-[10px] tabular-nums shrink-0"
                        style={{ color: 'var(--text-tertiary)' }}
                      >
                        {msg.timestamp ? msg.timestamp.slice(11, 19) + ' UTC' : ''}
                      </span>
                    </div>

                    {/* Content Text */}
                    <p
                      className="font-mono text-xs leading-relaxed whitespace-pre-wrap pl-9"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {msg.content}
                    </p>

                    {/* Discovered Entities Footer */}
                    <div className="pl-9">
                      {renderArtifactChips(msg.artifacts)}
                    </div>
                  </div>
                );
              })
            )}
            <div ref={chatBottomRef} />
          </div>
        </div>

        {/* ── Right Drawer (35% width): Specialist Gauges & Playbook ── */}
        <div
          className="w-[35%] flex flex-col h-full overflow-hidden"
          style={{
            background: 'var(--surface)',
          }}
        >
          {/* Drawer Tab Strip */}
          <div
            className="flex shrink-0"
            style={{ borderBottom: '1px solid var(--edge)' }}
          >
            <button
              onClick={() => setRightTab('specialists')}
              className={`flex-1 py-3 px-3 text-xs font-mono font-bold tracking-wider border-b-2 flex items-center justify-center gap-2 transition-all ${
                rightTab === 'specialists'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
              style={{
                background: rightTab === 'specialists' ? 'var(--cyan-subtle)' : 'transparent',
              }}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>SPECIALIST GAUGES</span>
              {findings.length > 0 && (
                <span className="badge badge-cyan text-[9px]">
                  {findings.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setRightTab('containment')}
              className={`flex-1 py-3 px-3 text-xs font-mono font-bold tracking-wider border-b-2 flex items-center justify-center gap-2 transition-all ${
                rightTab === 'containment'
                  ? 'border-violet-400 text-violet-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
              style={{
                background: rightTab === 'containment' ? 'var(--violet-subtle)' : 'transparent',
              }}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>SOAR PLAYBOOK</span>
              {report?.containment_commands && (
                <span className="badge badge-violet text-[9px]">
                  {report.containment_commands.length}
                </span>
              )}
            </button>
          </div>

          {/* Drawer Body Scroll */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 panel-scroll">
            {rightTab === 'specialists' ? (
              /* ───────────────────────────────────────────────────────── */
              /* TAB 1: Specialist Risk Gauges & Adversary Trajectory      */
              /* ───────────────────────────────────────────────────────── */
              <div className="space-y-4">
                {/* 1. Adversary Trajectory Card */}
                <div
                  className="glass-card p-3.5 space-y-2.5 relative overflow-hidden"
                  style={{
                    borderLeft: '3px solid var(--crimson)',
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className="font-mono text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5"
                      style={{ color: 'var(--crimson)' }}
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                      ADVERSARY TRAJECTORY & NEXT MOVE
                    </span>
                    <span className="badge severity-critical text-[9px]">
                      MITRE ATT&CK
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span style={{ color: 'var(--text-tertiary)' }}>Predicted Technique:</span>
                      <span className="data-chip text-crimson font-bold">
                        {adversaryTechnique}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span style={{ color: 'var(--text-tertiary)' }}>Target Node / Daemon:</span>
                      <span className="data-chip font-mono text-cyan-400">
                        {targetNetwork}:22 (OpenSSH)
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span style={{ color: 'var(--text-tertiary)' }}>Kill-Chain Phase:</span>
                      <span className="badge badge-amber text-[9px]">
                        LATERAL EXPLOITATION
                      </span>
                    </div>
                  </div>
                </div>

                {/* 2. Specialist Findings Accordion / Mini Risk Cards */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="section-title">Specialist Risk Gauges</span>
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                      3 vectors audited
                    </span>
                  </div>

                  {findings.length === 0 ? (
                    <div
                      className="p-6 text-center text-xs rounded-md"
                      style={{
                        background: 'var(--surface-2)',
                        border: '1px solid var(--edge)',
                        color: 'var(--text-tertiary)',
                      }}
                    >
                      <Activity className="w-6 h-6 mx-auto mb-2 opacity-50 animate-pulse" />
                      Awaiting swarm execution to calculate domain threat gauges.
                    </div>
                  ) : (
                    findings.map((f, i) => {
                      const isExpanded = expandedSpecialists[f.agent_id] ?? true;
                      const confidence = f.confidence_score ?? f.confidence ?? 0.85;
                      const pct = Math.round(confidence * 100);

                      return (
                        <div
                          key={i}
                          className="glass-card overflow-hidden transition-all"
                          style={{
                            borderLeft: f.is_malicious
                              ? '3px solid var(--crimson)'
                              : '3px solid var(--emerald)',
                          }}
                        >
                          {/* Accordion Header */}
                          <div
                            onClick={() => toggleSpecialist(f.agent_id)}
                            className="p-3 flex items-center justify-between cursor-pointer transition-colors"
                            style={{ background: 'var(--surface-2)' }}
                          >
                            <div className="flex items-center gap-2">
                              <span
                                className="live-dot"
                                style={{
                                  color: f.is_malicious ? 'var(--crimson)' : 'var(--emerald)',
                                }}
                              />
                              <span className="font-mono font-bold text-xs" style={{ color: 'var(--text-primary)' }}>
                                {f.agent_id}
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <span
                                className={`badge text-[9px] ${
                                  f.is_malicious ? 'severity-critical' : 'badge-emerald'
                                }`}
                              >
                                {f.is_malicious ? 'MALICIOUS' : 'BENIGN'} ({pct}%)
                              </span>
                              {isExpanded ? (
                                <ChevronUp className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                              ) : (
                                <ChevronDown className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                              )}
                            </div>
                          </div>

                          {/* Progress bar gauge */}
                          <div className="px-3 pt-2">
                            <div className="progress-bar">
                              <div
                                className="progress-fill"
                                style={{
                                  width: `${pct}%`,
                                  background: f.is_malicious ? 'var(--crimson)' : 'var(--emerald)',
                                }}
                              />
                            </div>
                          </div>

                          {/* Collapsible Content */}
                          {isExpanded && (
                            <div className="p-3 text-xs space-y-2">
                              <p
                                className="font-mono text-[11px] leading-relaxed"
                                style={{ color: 'var(--text-secondary)' }}
                              >
                                {f.summary}
                              </p>

                              {/* Technical Indicators */}
                              {f.technical_indicators && f.technical_indicators.length > 0 && (
                                <div className="pt-2" style={{ borderTop: '1px solid var(--edge-subtle)' }}>
                                  <span
                                    className="font-mono text-[9px] uppercase tracking-wider block mb-1 font-semibold"
                                    style={{ color: 'var(--text-tertiary)' }}
                                  >
                                    Captured Indicators:
                                  </span>
                                  <div className="flex flex-wrap gap-1">
                                    {f.technical_indicators.map((ind, indIdx) => (
                                      <span
                                        key={indIdx}
                                        className="data-chip text-[10px]"
                                        style={{ color: 'var(--cyan)' }}
                                      >
                                        {ind}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            ) : (
              /* ───────────────────────────────────────────────────────── */
              /* TAB 2: SOAR Containment Playbook                          */
              /* ───────────────────────────────────────────────────────── */
              <div className="space-y-4">
                {!report ? (
                  <div
                    className="p-8 text-center text-xs rounded-md"
                    style={{
                      background: 'var(--surface-2)',
                      border: '1px solid var(--edge)',
                      color: 'var(--text-tertiary)',
                    }}
                  >
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    Awaiting multi-agent consensus to synthesize verified containment playbooks.
                  </div>
                ) : (
                  <>
                    {/* Verdict Card */}
                    <div
                      className="glass-card p-4 space-y-3"
                      style={{
                        borderLeft: isMalicious
                          ? '3px solid var(--crimson)'
                          : '3px solid var(--emerald)',
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] uppercase font-bold tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
                          Consensus Verdict
                        </span>
                        <span
                          className={`badge ${
                            isMalicious ? 'severity-critical' : 'badge-emerald'
                          }`}
                        >
                          {report.threat_severity} ({Math.round(report.consensus_confidence * 100)}%)
                        </span>
                      </div>

                      <div className="pt-2" style={{ borderTop: '1px solid var(--edge-subtle)' }}>
                        <span
                          className="font-mono text-[10px] uppercase font-bold block mb-1"
                          style={{ color: 'var(--cyan)' }}
                        >
                          Root Cause Analysis
                        </span>
                        <p
                          className="font-mono text-xs leading-relaxed"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {report.root_cause_analysis || 'Autonomous multi-domain threat correlation confirmed.'}
                        </p>
                      </div>
                    </div>

                    {/* Containment Shell Commands Block */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span
                          className="font-mono text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5"
                          style={{ color: 'var(--violet)' }}
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Containment Playbook Commands</span>
                        </span>
                        <span
                          className="font-mono text-[10px]"
                          style={{ color: 'var(--text-tertiary)' }}
                        >
                          {report.containment_commands?.length || 0} rules
                        </span>
                      </div>

                      {report.containment_commands && report.containment_commands.length > 0 ? (
                        <div className="space-y-2">
                          {report.containment_commands.map((cmd, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-md flex items-center justify-between gap-2 group transition-all"
                              style={{
                                background: 'var(--surface-2)',
                                border: '1px solid var(--edge)',
                              }}
                            >
                              <div
                                className="font-mono text-[11px] truncate select-all pr-2"
                                style={{ color: 'var(--emerald)' }}
                              >
                                <span className="select-none mr-2 font-bold opacity-50" style={{ color: 'var(--text-tertiary)' }}>
                                  #
                                </span>
                                {cmd}
                              </div>
                              <button
                                onClick={() => handleCopyCommand(cmd, idx)}
                                className="btn btn-icon btn-ghost shrink-0"
                                title="Copy rule to clipboard"
                              >
                                {copiedIndex === idx ? (
                                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div
                          className="p-4 rounded text-center text-xs"
                          style={{
                            background: 'var(--surface-2)',
                            border: '1px solid var(--edge)',
                            color: 'var(--text-tertiary)',
                          }}
                        >
                          No containment actions required for benign telemetry.
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default WarRoom;
