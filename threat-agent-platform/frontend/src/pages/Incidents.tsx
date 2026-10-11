import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import {
  Database,
  Search,
  Download,
  Eye,
  RefreshCw,
  X,
  ShieldAlert,
  Terminal,
  MessageSquare,
  ChevronLeft,
  ChevronRight,
  Copy,
  Check,
  Crown,
  Mail,
  FileText,
  Globe,
  Skull,
  ShieldCheck,
  Shield,
} from 'lucide-react';
import { API_BASE_URL } from '../context/AuthContext';

interface WarRoomMessageRecord {
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
  confidence: number;
  summary: string;
  technical_indicators?: string[];
}

interface IncidentRecordItem {
  id: string;
  created_at: string;
  severity: string;
  confidence_score: number;
  root_cause: string;
  correlated_entities: Record<string, any>;
  containment_commands: string[];
  messages?: WarRoomMessageRecord[];
  findings?: SpecialistFindingItem[];
}

const AGENT_CONFIG: Record<
  string,
  {
    icon: React.ElementType;
    badgeBg: string;
    badgeText: string;
    borderColor: string;
  }
> = {
  LeadSupervisor: {
    icon: Crown,
    badgeBg: 'bg-amber-950/60',
    badgeText: 'text-amber-300',
    borderColor: 'border-amber-500/40',
  },
  EmailHunter: {
    icon: Mail,
    badgeBg: 'bg-cyan-950/60',
    badgeText: 'text-cyan-300',
    borderColor: 'border-cyan-500/40',
  },
  LogForensics: {
    icon: FileText,
    badgeBg: 'bg-emerald-950/60',
    badgeText: 'text-emerald-300',
    borderColor: 'border-emerald-500/40',
  },
  NetworkRecon: {
    icon: Globe,
    badgeBg: 'bg-blue-950/60',
    badgeText: 'text-blue-300',
    borderColor: 'border-blue-500/40',
  },
  RedTeamAdversarySim: {
    icon: Skull,
    badgeBg: 'bg-rose-950/70',
    badgeText: 'text-rose-300',
    borderColor: 'border-rose-500/50',
  },
  RedTeamSim: {
    icon: Skull,
    badgeBg: 'bg-rose-950/70',
    badgeText: 'text-rose-300',
    borderColor: 'border-rose-500/50',
  },
  BlueTeamCommander: {
    icon: ShieldCheck,
    badgeBg: 'bg-purple-950/60',
    badgeText: 'text-purple-300',
    borderColor: 'border-purple-500/40',
  },
};

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentRecordItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 8;

  // Modal inspection state
  const [selectedIncident, setSelectedIncident] = useState<IncidentRecordItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<number | null>(null);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE_URL}/api/v1/incidents`);
      setIncidents(res.data || []);
    } catch (err) {
      console.error('Failed to load incident audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  // Filter and search computation
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesSearch =
        inc.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.severity.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (inc.root_cause && inc.root_cause.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesSeverity =
        severityFilter === 'ALL' || inc.severity.toUpperCase() === severityFilter.toUpperCase();

      return matchesSearch && matchesSeverity;
    });
  }, [incidents, searchTerm, severityFilter]);

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredIncidents.length / pageSize));
  const paginatedIncidents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredIncidents.slice(start, start + pageSize);
  }, [filteredIncidents, currentPage, pageSize]);

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(idx);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  // Export full JSON forensic report
  const handleExportJSON = (incident: IncidentRecordItem) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(incident, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `incident_${incident.id.slice(0, 8)}_report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-300 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-500/50 shadow-[0_0_10px_rgba(249,115,22,0.2)]';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-300 border-blue-500/50';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]';
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs text-slate-100">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-xl font-bold tracking-wider text-slate-100">
              INCIDENT ARCHIVE <span className="text-cyan-400">//</span> FORENSIC AUDIT
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-400">
              PERSISTENT DATABASE
            </span>
          </div>
          <p className="text-slate-400 mt-1">
            Historical swarm war-room consensus records, containment playbooks, and recorded agent debates.
          </p>
        </div>

        <button
          onClick={fetchIncidents}
          className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>REFRESH AUDIT TRAIL</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 rounded-xl p-3">
        {/* Search Input */}
        <div className="flex items-center space-x-2.5 w-full md:w-96 bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-2">
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search by UUID, severity, or root cause..."
            className="w-full bg-transparent text-slate-200 placeholder-slate-500 focus:outline-none text-xs"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center space-x-1.5 self-start md:self-auto overflow-x-auto w-full md:w-auto">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'BENIGN'].map((sev) => (
            <button
              key={sev}
              onClick={() => {
                setSeverityFilter(sev);
                setCurrentPage(1);
              }}
              className={`px-2.5 py-1.5 rounded-lg text-[10px] font-bold tracking-wider border transition-all ${
                severityFilter === sev
                  ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/40'
                  : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-slate-300'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Forensic Audit Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        {loading ? (
          <div className="p-16 text-center text-slate-400">
            <RefreshCw className="w-7 h-7 animate-spin mx-auto mb-3 text-cyan-400" />
            Retrieving persistent forensic records from SQLite/PostgreSQL...
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="p-16 text-center text-slate-400">
            <Database className="w-10 h-10 mx-auto mb-3 text-slate-600" />
            <h3 className="text-sm font-bold text-slate-300 mb-1">No Historical Incidents Found</h3>
            <p className="text-slate-500 max-w-md mx-auto">
              Execute a scenario investigation from the Live War Room to capture forensic audits in the persistent database.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-950/90 border-b border-slate-800 text-slate-400 text-[10px] uppercase tracking-wider">
                  <th className="p-3.5 pl-5">Incident ID</th>
                  <th className="p-3.5">Timestamp (UTC)</th>
                  <th className="p-3.5">Severity</th>
                  <th className="p-3.5">Consensus Confidence</th>
                  <th className="p-3.5">Root Cause Summary</th>
                  <th className="p-3.5">Correlated Artifacts</th>
                  <th className="p-3.5 pr-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {paginatedIncidents.map((inc) => {
                  const confPct = Math.round((inc.confidence_score || 0) * 100);
                  const ips = inc.correlated_entities?.ips || [];

                  return (
                    <tr
                      key={inc.id}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      {/* UUID Snippet */}
                      <td className="p-3.5 pl-5 font-bold text-cyan-400">
                        <div className="flex items-center space-x-1.5">
                          <span title={inc.id}>{inc.id.slice(0, 8)}...</span>
                          <button
                            onClick={() => handleCopyId(inc.id)}
                            className="text-slate-500 hover:text-cyan-400 transition-colors"
                            title="Copy full UUID"
                          >
                            {copiedId === inc.id ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Timestamp */}
                      <td className="p-3.5 text-slate-400 text-[11px] whitespace-nowrap">
                        {inc.created_at ? inc.created_at.slice(0, 19).replace('T', ' ') : '—'}
                      </td>

                      {/* Severity Badge */}
                      <td className="p-3.5">
                        <span
                          className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getSeverityBadge(
                            inc.severity
                          )}`}
                        >
                          {inc.severity}
                        </span>
                      </td>

                      {/* Confidence Meter */}
                      <td className="p-3.5">
                        <div className="space-y-1 w-28">
                          <div className="flex justify-between text-[10px]">
                            <span className="text-slate-300 font-bold">{confPct}%</span>
                            <span className="text-slate-500">verdict</span>
                          </div>
                          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                confPct >= 80
                                  ? 'bg-gradient-to-r from-cyan-500 to-emerald-400'
                                  : confPct >= 50
                                  ? 'bg-gradient-to-r from-amber-500 to-yellow-400'
                                  : 'bg-slate-600'
                              }`}
                              style={{ width: `${confPct}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Root Cause Summary */}
                      <td className="p-3.5 text-slate-300 text-[11px] max-w-xs truncate" title={inc.root_cause}>
                        {inc.root_cause || 'Cross-domain threat correlation verified.'}
                      </td>

                      {/* Correlated Artifacts Chips */}
                      <td className="p-3.5">
                        <div className="flex flex-wrap gap-1 max-w-[180px]">
                          {ips.length > 0 ? (
                            ips.slice(0, 2).map((ip: string, idx: number) => (
                              <span
                                key={idx}
                                className="px-1.5 py-0.2 rounded bg-slate-950 border border-slate-800 text-cyan-300 text-[10px]"
                              >
                                {ip}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500 text-[10px]">No pivot IPs</span>
                          )}
                          {ips.length > 2 && (
                            <span className="text-[9px] text-slate-500 font-bold self-center">
                              +{ips.length - 2}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="p-3.5 pr-5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => setSelectedIncident(inc)}
                            className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 hover:border-cyan-500 hover:text-cyan-300 text-slate-300 text-[11px] font-bold flex items-center space-x-1.5 transition-colors"
                            title="Inspect complete War Room dialogue & containment"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>[Inspect War Room]</span>
                          </button>
                          <button
                            onClick={() => handleExportJSON(inc)}
                            className="p-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                            title="Export JSON Report"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {filteredIncidents.length > 0 && (
          <div className="p-4 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing{' '}
              <strong className="text-slate-200">
                {(currentPage - 1) * pageSize + 1}-
                {Math.min(currentPage * pageSize, filteredIncidents.length)}
              </strong>{' '}
              of <strong className="text-slate-200">{filteredIncidents.length}</strong> incidents
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-slate-200"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 font-bold text-xs">
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-slate-200"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Full War Room Modal Dialogue Drilldown */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 max-h-[90vh] flex flex-col justify-between overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800 shrink-0">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-500/40 text-cyan-400">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-sm">
                    RECORDED WAR ROOM: {selectedIncident.id}
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Timestamp: {selectedIncident.created_at?.replace('T', ' ').slice(0, 19)} UTC
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleExportJSON(selectedIncident)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 hover:text-cyan-300 text-xs font-bold flex items-center space-x-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>[Export JSON]</span>
                </button>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Verdict and Telemetry Summary Chips */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 my-4 shrink-0">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                  Threat Verdict
                </span>
                <span
                  className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                    selectedIncident.severity
                  )}`}
                >
                  {selectedIncident.severity}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                  Consensus Confidence
                </span>
                <span className="text-sm font-bold text-cyan-400">
                  {Math.round(selectedIncident.confidence_score * 100)}%
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                  Containment Rules
                </span>
                <span className="text-sm font-bold text-purple-400">
                  {selectedIncident.containment_commands?.length || 0} active rules
                </span>
              </div>
            </div>

            {/* Scrollable Center: Recorded Dialogue Messages */}
            <div className="flex-1 overflow-y-auto space-y-3 pr-2 my-2 min-h-[220px]">
              <div className="flex items-center space-x-2 text-[11px] text-slate-400 pb-1 border-b border-slate-800/80">
                <MessageSquare className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-200">INTER-AGENT DEBATE TRANSCRIPT</span>
              </div>

              {selectedIncident.messages && selectedIncident.messages.length > 0 ? (
                selectedIncident.messages.map((m, idx) => {
                  const agentCfg = AGENT_CONFIG[m.sender] || {
                    icon: Shield,
                    badgeBg: 'bg-slate-800',
                    badgeText: 'text-slate-300',
                    borderColor: 'border-slate-700',
                  };
                  const Icon = agentCfg.icon;

                  return (
                    <div
                      key={idx}
                      className={`p-3.5 rounded-xl border bg-slate-950/70 space-y-1.5 ${agentCfg.borderColor}`}
                    >
                      <div className="flex items-center justify-between text-[10px]">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 rounded font-bold border flex items-center space-x-1 ${agentCfg.badgeBg} ${agentCfg.badgeText} ${agentCfg.borderColor}`}
                          >
                            <Icon className="w-3 h-3 inline mr-1" />
                            <span>{m.sender}</span>
                          </span>
                          <span className="text-slate-500">➔</span>
                          <span className="text-slate-400">{m.recipient}</span>
                          <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-[9px] text-slate-400 uppercase font-bold">
                            [{m.action_type}]
                          </span>
                        </div>
                        <span className="text-slate-500">
                          {m.timestamp?.slice(11, 19)} UTC
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                        {m.content}
                      </p>
                    </div>
                  );
                })
              ) : (
                <div className="p-8 text-center text-slate-500">
                  No recorded messages stored for this incident.
                </div>
              )}
            </div>

            {/* SOAR Containment Playbook Commands */}
            {selectedIncident.containment_commands && selectedIncident.containment_commands.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-800 shrink-0">
                <span className="text-[10px] text-purple-400 uppercase font-bold flex items-center space-x-1 mb-2">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Mitigation Playbook Generated by BlueTeamCommander</span>
                </span>
                <div className="space-y-1.5 max-h-28 overflow-y-auto pr-1">
                  {selectedIncident.containment_commands.map((cmd, i) => (
                    <div
                      key={i}
                      className="p-2 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-[11px]"
                    >
                      <span className="text-emerald-300 truncate">
                        <span className="text-slate-500 select-none mr-2">$</span>
                        {cmd}
                      </span>
                      <button
                        onClick={() => handleCopyCommand(cmd, i)}
                        className="p-1 rounded bg-slate-900 text-slate-400 hover:text-purple-300"
                        title="Copy command"
                      >
                        {copiedCmd === i ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Incidents;
