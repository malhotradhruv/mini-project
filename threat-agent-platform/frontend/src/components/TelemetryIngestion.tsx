import React from 'react';
import {
  Mail,
  FileText,
  Globe,
  Zap,
  Shield,
  Loader2,
  Play,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { TriageRequest } from '../types/soc';

interface TelemetryIngestionProps {
  emailText: string;
  setEmailText: (val: string) => void;
  logText: string;
  setLogText: (val: string) => void;
  targetNetwork: string;
  setTargetNetwork: (val: string) => void;
  onExecute: () => void;
  isLoading: boolean;
}

// Preset Telemetry Scenarios aligned with IEEE Access (Hmimou et al., 2025)
export const SCENARIO_A_COORDINATED: TriageRequest = {
  email_text:
    "URGENT: Critical security update required immediately.\n" +
    "Download security patch from http://192.168.1.105/patch.php\n" +
    "or your workstation will be locked within 24 hours. IT Support.",
  log_text:
    "Oct 10 02:14:01 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n" +
    "Oct 10 02:14:03 srv1 sshd[102]: Failed password for root from 192.168.1.105 port 22\n" +
    "Oct 10 02:14:05 srv1 sshd[102]: Accepted password for root from 192.168.1.105 port 22\n" +
    "Oct 10 02:14:10 srv1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)",
  target_network: "192.168.1.105",
};

export const SCENARIO_B_BENIGN: TriageRequest = {
  email_text:
    "Hi team,\n\n" +
    "Please find attached the meeting minutes and release notes from yesterday's sync.\n" +
    "Let me know if there are any agenda items for next Tuesday.\n\n" +
    "Best regards,\nEngineering Operations",
  log_text:
    "Oct 10 04:00:01 srv1 CRON[401]: (root) CMD (/usr/local/bin/backup-sync.sh)\n" +
    "Oct 10 04:05:00 srv1 systemd[1]: Started Daily apt upgrade and system health checks.\n" +
    "Oct 10 04:15:22 srv1 kernel: [ 451.201] TCP: eth0 link up 1000Mbps Full Duplex\n" +
    "Oct 10 04:20:01 srv1 CRON[415]: (sysstat) CMD (/usr/lib/sysstat/sa1 1 1)",
  target_network: "10.0.0.1",
};

export const TelemetryIngestion: React.FC<TelemetryIngestionProps> = ({
  emailText,
  setEmailText,
  logText,
  setLogText,
  targetNetwork,
  setTargetNetwork,
  onExecute,
  isLoading,
}) => {
  const handleLoadScenarioA = () => {
    setEmailText(SCENARIO_A_COORDINATED.email_text);
    setLogText(SCENARIO_A_COORDINATED.log_text);
    setTargetNetwork(SCENARIO_A_COORDINATED.target_network);
  };

  const handleLoadScenarioB = () => {
    setEmailText(SCENARIO_B_BENIGN.email_text);
    setLogText(SCENARIO_B_BENIGN.log_text);
    setTargetNetwork(SCENARIO_B_BENIGN.target_network);
  };

  const handleClearAll = () => {
    setEmailText('');
    setLogText('');
    setTargetNetwork('');
  };

  const isPayloadProvided =
    emailText.trim() !== '' || logText.trim() !== '' || targetNetwork.trim() !== '';

  return (
    <div className="glass-card rounded-xl border border-soc-border p-6 space-y-6 shadow-2xl">
      {/* Header and Quick-Load Presets */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-soc-border pb-5">
        <div>
          <div className="flex items-center space-x-2 text-soc-accent font-mono text-xs uppercase tracking-wider mb-1">
            <Sparkles className="h-3.5 w-3.5" />
            <span>Multi-Vector Telemetry Ingestion</span>
          </div>
          <h2 className="text-lg font-bold text-slate-100">
            Security Event Feed & Threat Surface Input
          </h2>
          <p className="text-xs text-slate-400">
            Ingest heterogeneous signals across email, auth logs, and target hosts for LangGraph cross-agent correlation.
          </p>
        </div>

        {/* Preset Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={handleLoadScenarioA}
            disabled={isLoading}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-soc-danger/10 hover:bg-soc-danger/20 border border-soc-danger/40 text-soc-danger text-xs font-mono font-medium transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed shadow-soc-danger-glow/20"
          >
            <Zap className="h-3.5 w-3.5 text-soc-danger animate-pulse" />
            <span>⚡ Load Scenario A: Coordinated Multi-Stage Attack</span>
          </button>

          <button
            type="button"
            onClick={handleLoadScenarioB}
            disabled={isLoading}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-soc-success/10 hover:bg-soc-success/20 border border-soc-success/40 text-soc-success text-xs font-mono font-medium transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Shield className="h-3.5 w-3.5 text-soc-success" />
            <span>🛡️ Load Scenario B: Benign Isolated Traffic</span>
          </button>

          {isPayloadProvided && (
            <button
              type="button"
              onClick={handleClearAll}
              disabled={isLoading}
              title="Clear all telemetry inputs"
              className="p-2 rounded-lg bg-soc-surface hover:bg-slate-800 border border-soc-border text-slate-400 hover:text-slate-200 text-xs transition duration-200"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* 3-Column Monospace Ingestion Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Vector 1: Email Inspector */}
        <div className="flex flex-col space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <label className="flex items-center space-x-2 font-mono text-slate-200 font-semibold">
              <Mail className="h-4 w-4 text-soc-accent" />
              <span>1. EMAIL TELEMETRY</span>
            </label>
            <span className="text-[11px] font-mono text-slate-400">
              {emailText.length} chars
            </span>
          </div>
          <div className="relative flex-1">
            <textarea
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
              disabled={isLoading}
              rows={8}
              placeholder="Paste raw email body, headers, or phishing alert lure (e.g., URGENT: verify credentials at http://...)..."
              className="w-full h-full min-h-[180px] p-3.5 rounded-lg bg-soc-bg border border-soc-border focus:border-soc-accent focus:ring-1 focus:ring-soc-accent outline-none text-xs font-mono text-slate-200 placeholder-slate-600 resize-none terminal-scroll transition duration-200"
            />
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono">
            <span>Evaluates DNS MX/A, Urgency, FAISS</span>
            <span className="text-soc-accent">EmailAgent</span>
          </div>
        </div>

        {/* Vector 2: Audit Log Stream */}
        <div className="flex flex-col space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <label className="flex items-center space-x-2 font-mono text-slate-200 font-semibold">
              <FileText className="h-4 w-4 text-soc-warning" />
              <span>2. AUDIT LOG STREAM</span>
            </label>
            <span className="text-[11px] font-mono text-slate-400">
              {logText ? logText.split('\n').filter((l) => l.trim()).length : 0} lines
            </span>
          </div>
          <div className="relative flex-1">
            <textarea
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              disabled={isLoading}
              rows={8}
              placeholder="Paste auth.log, syslog, or HTTP server access stream (e.g., Failed password for root from 192.168.1.105)..."
              className="w-full h-full min-h-[180px] p-3.5 rounded-lg bg-soc-bg border border-soc-border focus:border-soc-warning focus:ring-1 focus:ring-soc-warning outline-none text-xs font-mono text-slate-200 placeholder-slate-600 resize-none terminal-scroll transition duration-200"
            />
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono">
            <span>Evaluates Brute-Force, Sudo, 500s</span>
            <span className="text-soc-warning">LogAgent</span>
          </div>
        </div>

        {/* Vector 3: Attack Surface Target */}
        <div className="flex flex-col space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <label className="flex items-center space-x-2 font-mono text-slate-200 font-semibold">
              <Globe className="h-4 w-4 text-soc-success" />
              <span>3. SUBNET / TARGET HOST</span>
            </label>
            <span className="text-[11px] font-mono text-slate-400">
              IPv4 / CIDR
            </span>
          </div>
          <div className="relative flex-1 flex flex-col justify-between space-y-3">
            <input
              type="text"
              value={targetNetwork}
              onChange={(e) => setTargetNetwork(e.target.value)}
              disabled={isLoading}
              placeholder="Enter Target Host IP or CIDR (e.g., 192.168.1.105)..."
              className="w-full p-3.5 rounded-lg bg-soc-bg border border-soc-border focus:border-soc-success focus:ring-1 focus:ring-soc-success outline-none text-xs font-mono text-slate-200 placeholder-slate-600 transition duration-200"
            />

            {/* Quick Helper Target Suggestions */}
            <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border text-xs font-mono space-y-2">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">
                Preset Network Targets:
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setTargetNetwork('192.168.1.105')}
                  disabled={isLoading}
                  className="px-2 py-1 rounded bg-soc-bg hover:bg-slate-800 border border-soc-border text-slate-300 text-[11px] font-mono hover:text-soc-accent transition"
                >
                  192.168.1.105 (Pivot IP)
                </button>
                <button
                  type="button"
                  onClick={() => setTargetNetwork('10.0.0.1')}
                  disabled={isLoading}
                  className="px-2 py-1 rounded bg-soc-bg hover:bg-slate-800 border border-soc-border text-slate-300 text-[11px] font-mono hover:text-soc-success transition"
                >
                  10.0.0.1 (Internal Gateway)
                </button>
              </div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono">
            <span>Evaluates Open Ports, NIST CVEs</span>
            <span className="text-soc-success">IPAgent</span>
          </div>
        </div>
      </div>

      {/* Primary Action Button Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-3 border-t border-soc-border">
        <div className="text-xs text-slate-400 font-mono">
          {isLoading ? (
            <span className="text-soc-accent flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              LangGraph worker nodes dispatching and correlating...
            </span>
          ) : isPayloadProvided ? (
            <span className="text-slate-300">
              Telemetry staged. Ready to trigger LangGraph parallel workflow.
            </span>
          ) : (
            <span>Load a preset scenario or enter custom telemetry to begin investigation.</span>
          )}
        </div>

        <button
          type="button"
          onClick={onExecute}
          disabled={isLoading || !isPayloadProvided}
          className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-gradient-to-r from-soc-accent via-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-slate-950 font-bold text-sm tracking-wide shadow-lg shadow-sky-500/25 transition duration-200 flex items-center justify-center space-x-2.5 disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
        >
          {isLoading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin text-slate-950" />
              <span>Orchestrating Agent Swarm...</span>
            </>
          ) : (
            <>
              <Play className="h-4 w-4 fill-slate-950 text-slate-950" />
              <span>🚀 Execute Multi-Agent SOC Investigation</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default TelemetryIngestion;
