import React, { useState } from 'react';
import {
  Mail,
  FileText,
  Network,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronUp,
  Tag,
  Hash,
  Globe,
  Bug,
  Terminal,
} from 'lucide-react';
import { AgentFinding } from '../types/soc';

export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed';

interface AgentSwarmCardsProps {
  findings?: AgentFinding[];
  agentStatuses?: {
    email_worker?: AgentStatus;
    log_worker?: AgentStatus;
    ip_worker?: AgentStatus;
  };
}

interface CardConfig {
  key: 'email' | 'log' | 'ip';
  workerStep: 'email_worker' | 'log_worker' | 'ip_worker';
  title: string;
  subtitle: string;
  agentIds: string[];
  icon: React.ReactNode;
}

const CARDS_CONFIG: CardConfig[] = [
  {
    key: 'email',
    workerStep: 'email_worker',
    title: 'Email Intelligence',
    subtitle: 'DNS MX/A • TextBlob Urgency • FAISS Vector RAG',
    agentIds: ['EmailIntelligenceAgent', 'email_agent', 'EmailAgent'],
    icon: <Mail className="h-5 w-5 text-soc-accent" />,
  },
  {
    key: 'log',
    workerStep: 'log_worker',
    title: 'Behavioral Log Forensics',
    subtitle: 'Auth Velocity • Sudo Priv-Esc • HTTP 500s',
    agentIds: ['BehavioralLogAgent', 'log_agent', 'LogAgent'],
    icon: <FileText className="h-5 w-5 text-soc-warning" />,
  },
  {
    key: 'ip',
    workerStep: 'ip_worker',
    title: 'Network Surface Profiler',
    subtitle: 'Nmap Banners • NIST NVD CVEs (CVSS >= 7.0)',
    agentIds: ['NetworkReconAgent', 'ip_agent', 'IPAgent'],
    icon: <Network className="h-5 w-5 text-soc-success" />,
  },
];

export const AgentSwarmCards: React.FC<AgentSwarmCardsProps> = ({
  findings = [],
  agentStatuses = {},
}) => {
  // Collapsible disclosure states for raw JSON evidence
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});

  const toggleEvidence = (cardKey: string) => {
    setExpandedEvidence((prev) => ({
      ...prev,
      [cardKey]: !prev[cardKey],
    }));
  };

  const findFindingForCard = (config: CardConfig): AgentFinding | undefined => {
    return findings.find((f) =>
      config.agentIds.some(
        (id) => id.toLowerCase() === f.agent_id.toLowerCase()
      )
    );
  };

  const getRiskBadge = (score: number) => {
    const pct = Math.round(score * 100);
    if (score >= 0.7) {
      return {
        label: `${pct}% HIGH RISK`,
        bg: 'bg-soc-danger/15 text-soc-danger border-soc-danger/40',
        barColor: 'bg-soc-danger',
        icon: <ShieldAlert className="h-3.5 w-3.5 text-soc-danger" />,
      };
    }
    if (score >= 0.4) {
      return {
        label: `${pct}% MEDIUM RISK`,
        bg: 'bg-soc-warning/15 text-soc-warning border-soc-warning/40',
        barColor: 'bg-soc-warning',
        icon: <AlertTriangle className="h-3.5 w-3.5 text-soc-warning" />,
      };
    }
    return {
      label: `${pct}% LOW RISK`,
      bg: 'bg-soc-success/15 text-soc-success border-soc-success/40',
      barColor: 'bg-soc-success',
      icon: <ShieldCheck className="h-3.5 w-3.5 text-soc-success" />,
    };
  };

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex items-center justify-between border-b border-soc-border pb-3">
        <div>
          <div className="flex items-center space-x-2 text-soc-accent font-mono text-xs uppercase tracking-wider mb-1">
            <Terminal className="h-3.5 w-3.5" />
            <span>LangGraph Domain Workers</span>
          </div>
          <h2 className="text-lg font-bold text-slate-100">
            Specialized Forensic Agent Swarm
          </h2>
        </div>
        <div className="text-xs font-mono text-slate-400">
          3 Parallel Forensic Nodes • IEEE Access (2025)
        </div>
      </div>

      {/* 3-Column Responsive Grid Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {CARDS_CONFIG.map((config) => {
          const finding = findFindingForCard(config);
          const rawStatus = agentStatuses[config.workerStep] || (finding ? 'completed' : 'idle');
          const isAnalyzing = rawStatus === 'running';
          const isCompleted = rawStatus === 'completed' || Boolean(finding);
          const isIdle = !isAnalyzing && !isCompleted;

          const riskBadge = finding ? getRiskBadge(finding.risk_score) : null;
          const isExpanded = Boolean(expandedEvidence[config.key]);

          return (
            <div
              key={config.key}
              className={`glass-card rounded-xl border flex flex-col justify-between transition-all duration-300 shadow-xl ${
                isAnalyzing
                  ? 'border-soc-accent shadow-soc-glow/30 ring-1 ring-soc-accent/40'
                  : finding?.is_malicious
                  ? 'border-soc-danger/50'
                  : 'border-soc-border'
              }`}
            >
              {/* Card Header */}
              <div className="p-5 border-b border-soc-border space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border shadow-inner">
                      {config.icon}
                    </div>
                    <div>
                      <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                        {config.title}
                      </h3>
                      <p className="text-[11px] text-slate-400 font-mono">
                        {config.subtitle}
                      </p>
                    </div>
                  </div>

                  {/* Agent Status Badge */}
                  <div>
                    {isAnalyzing && (
                      <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-soc-accent/15 border border-soc-accent/40 text-soc-accent text-[11px] font-mono font-semibold animate-pulse shadow-soc-glow">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        <span>ANALYZING</span>
                      </span>
                    )}
                    {isCompleted && (
                      <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-soc-success/15 border border-soc-success/40 text-soc-success text-[11px] font-mono font-semibold">
                        <span className="h-1.5 w-1.5 rounded-full bg-soc-success"></span>
                        <span>COMPLETED</span>
                      </span>
                    )}
                    {isIdle && (
                      <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-slate-400 text-[11px] font-mono font-semibold">
                        <span className="h-1.5 w-1.5 rounded-full bg-slate-500"></span>
                        <span>IDLE</span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Risk Meter Badge & Progress Bar */}
                {finding && riskBadge && (
                  <div className="space-y-1.5 pt-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono text-slate-400">
                        ASSESSED RISK SCORE
                      </span>
                      <span
                        className={`flex items-center space-x-1 px-2 py-0.5 rounded border text-[11px] font-mono font-bold ${riskBadge.bg}`}
                      >
                        {riskBadge.icon}
                        <span>{riskBadge.label}</span>
                      </span>
                    </div>
                    {/* Visual Meter Bar */}
                    <div className="h-1.5 w-full bg-soc-bg rounded-full overflow-hidden border border-soc-border">
                      <div
                        className={`h-full ${riskBadge.barColor} transition-all duration-700`}
                        style={{ width: `${Math.round(finding.risk_score * 100)}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Card Body */}
              <div className="p-5 space-y-4 flex-1">
                {finding ? (
                  <>
                    {/* Detected Indicators List */}
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-300">
                        <Tag className="h-3.5 w-3.5 text-soc-accent" />
                        <span>Detected Indicators ({finding.indicators.length})</span>
                      </div>
                      {finding.indicators.length > 0 ? (
                        <ul className="space-y-1">
                          {finding.indicators.map((ind, idx) => (
                            <li
                              key={idx}
                              className="text-[11px] font-mono bg-soc-bg/80 border border-soc-border px-2.5 py-1.5 rounded text-slate-200 flex items-start space-x-2"
                            >
                              <span className="text-soc-accent mt-0.5">•</span>
                              <span className="break-all">{ind}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div className="text-[11px] font-mono text-slate-500 italic bg-soc-bg/40 p-2 rounded border border-soc-border/50">
                          No deterministic threat indicators flagged.
                        </div>
                      )}
                    </div>

                    {/* Extracted Artifacts Chips */}
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-300">
                        <Hash className="h-3.5 w-3.5 text-soc-warning" />
                        <span>Extracted Forensic Artifacts</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {/* IP Chips */}
                        {finding.artifacts?.ips?.map((ip, i) => (
                          <span
                            key={`ip-${i}`}
                            className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800/80 text-sky-300 text-[11px] font-mono"
                          >
                            <Globe className="h-3 w-3 text-sky-400" />
                            <span>{ip}</span>
                          </span>
                        ))}

                        {/* Domain / URL Chips */}
                        {finding.artifacts?.domains?.map((dom, i) => (
                          <span
                            key={`dom-${i}`}
                            className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-800/80 text-indigo-300 text-[11px] font-mono"
                          >
                            <span>{dom}</span>
                          </span>
                        ))}

                        {/* Open Port Chips */}
                        {finding.artifacts?.ports?.map((port, i) => (
                          <span
                            key={`port-${i}`}
                            className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 text-[11px] font-mono"
                          >
                            <span>Port {port}</span>
                          </span>
                        ))}

                        {/* CVE Chips */}
                        {finding.artifacts?.cves?.map((cve, i) => (
                          <span
                            key={`cve-${i}`}
                            className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/80 text-rose-300 text-[11px] font-mono font-semibold"
                          >
                            <Bug className="h-3 w-3 text-rose-400" />
                            <span>{cve}</span>
                          </span>
                        ))}

                        {(!finding.artifacts?.ips?.length &&
                          !finding.artifacts?.domains?.length &&
                          !finding.artifacts?.ports?.length &&
                          !finding.artifacts?.cves?.length) && (
                          <span className="text-[11px] font-mono text-slate-500 italic">
                            None extracted
                          </span>
                        )}
                      </div>
                    </div>

                    {/* LLM Forensic Narrative Block (Typewriter styling) */}
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-300">
                        <Terminal className="h-3.5 w-3.5 text-soc-accent" />
                        <span>LLM Semantic Synthesis</span>
                      </div>
                      <div className="bg-soc-bg border-l-2 border-soc-accent p-3 rounded-r-lg border-y border-r border-soc-border text-xs font-mono text-slate-200 leading-relaxed terminal-scroll max-h-36 overflow-y-auto">
                        <p className="whitespace-pre-wrap">{finding.analyst_summary}</p>
                      </div>
                    </div>
                  </>
                ) : (
                  /* Placeholder when node is idle or analyzing */
                  <div className="h-44 flex flex-col items-center justify-center text-center p-4 rounded-lg bg-soc-bg/40 border border-dashed border-soc-border space-y-2">
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="h-6 w-6 animate-spin text-soc-accent" />
                        <span className="text-xs font-mono text-soc-accent">
                          Executing forensic heuristics & tool lookups...
                        </span>
                      </>
                    ) : (
                      <>
                        <Terminal className="h-6 w-6 text-slate-600" />
                        <span className="text-xs font-mono text-slate-500">
                          Awaiting telemetry dispatch...
                        </span>
                      </>
                    )}
                  </div>
                )}
              </div>

              {/* Collapsible Disclosure for Raw JSON Evidence */}
              {finding && finding.raw_evidence && (
                <div className="p-4 border-t border-soc-border bg-soc-surface/50 rounded-b-xl">
                  <button
                    type="button"
                    onClick={() => toggleEvidence(config.key)}
                    className="w-full flex items-center justify-between text-xs font-mono text-slate-400 hover:text-slate-200 transition"
                  >
                    <span>Raw Forensic Evidence JSON</span>
                    {isExpanded ? (
                      <ChevronUp className="h-3.5 w-3.5" />
                    ) : (
                      <ChevronDown className="h-3.5 w-3.5" />
                    )}
                  </button>
                  {isExpanded && (
                    <div className="mt-2.5 pt-2.5 border-t border-soc-border/60">
                      <pre className="text-[11px] font-mono bg-soc-bg p-3 rounded border border-soc-border text-slate-300 overflow-x-auto max-h-48 terminal-scroll">
                        {JSON.stringify(finding.raw_evidence, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AgentSwarmCards;
