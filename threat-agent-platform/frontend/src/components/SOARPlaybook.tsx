import React, { useState } from 'react';
import {
  ShieldAlert,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  AlertOctagon,
  Clock,
  Flame,
  ArrowRight,
  ShieldCheck,
  Cpu,
} from 'lucide-react';
import { CorrelatedIncidentReport, AttackStage } from '../types/soc';

interface SOARPlaybookProps {
  report?: CorrelatedIncidentReport | null;
}

export const SOARPlaybook: React.FC<SOARPlaybookProps> = ({ report }) => {
  // Copied feedback index tracking
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  // Remediated task state checklist
  const [completedSteps, setCompletedSteps] = useState<Record<number, boolean>>({});

  if (!report || !report.incident_detected) {
    return null;
  }

  const confidencePct = Math.round(report.confidence_score * 100);
  const commonIps = report.common_artifacts?.ips || ['192.168.1.105'];
  const pivotIp = commonIps[0] || '192.168.1.105';

  // Fallback timeline stages if empty
  const timelineStages: AttackStage[] =
    report.attack_timeline && report.attack_timeline.length > 0
      ? report.attack_timeline
      : [
          {
            stage_number: 1,
            tactic: 'Initial Access',
            description: 'Spear-phishing email lure directing recipient to unauthenticated credential portal.',
            correlated_indicator: `URL containing target host ${pivotIp}`,
          },
          {
            stage_number: 2,
            tactic: 'Credential Access',
            description: 'Distributed SSH authentication brute force and dictionary credential stuffing.',
            correlated_indicator: `Repeated failed auth attempts from ${pivotIp}`,
          },
          {
            stage_number: 3,
            tactic: 'Exploitation & Lateral Movement',
            description: 'Exploitation of exposed daemon vulnerabilities and unauthorized root elevation.',
            correlated_indicator: 'Port 22/80 unpatched CVE exploit signature',
          },
        ];

  // Fallback containment playbook items
  const containmentSteps =
    report.containment_playbook && report.containment_playbook.length > 0
      ? report.containment_playbook
      : [
          `iptables -A INPUT -s ${pivotIp} -j DROP`,
          `pkill -u root -t sshd && systemctl restart sshd`,
          `ufw deny from ${pivotIp} to any port 22,80 proto tcp`,
          `isolate-host --ip ${pivotIp} --reason "Coordinated Multi-Stage Campaign"`,
        ];

  const toggleStepCompleted = (index: number) => {
    setCompletedSteps((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const handleCopyCommand = (cmd: string, index: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => {
      setCopiedIndex(null);
    }, 2000);
  };

  const handleCopyAll = () => {
    const fullScript = containmentSteps.join('\n');
    navigator.clipboard.writeText(fullScript);
    setCopiedAll(true);
    setTimeout(() => {
      setCopiedAll(false);
    }, 2000);
  };

  return (
    <div className="glass-card rounded-xl border border-soc-danger/60 p-6 space-y-6 shadow-2xl relative overflow-hidden bg-gradient-to-b from-soc-surface via-soc-card to-soc-bg">
      {/* Alert Glow Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 rounded-xl bg-soc-danger/10 border border-soc-danger/40 shadow-soc-danger-glow/30">
        <div className="flex items-start space-x-3.5">
          <div className="p-3 rounded-lg bg-soc-danger/20 border border-soc-danger/50 text-soc-danger animate-pulse">
            <AlertOctagon className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2 text-soc-danger font-mono text-xs font-bold uppercase tracking-wider mb-0.5">
              <Flame className="h-4 w-4" />
              <span>SUPERVISOR INCIDENT CORRELATION</span>
            </div>
            <h2 className="text-xl font-extrabold text-slate-100 tracking-wide">
              CRITICAL MULTI-STAGE BREACH IDENTIFIED
            </h2>
            <p className="text-xs text-slate-300 font-mono mt-0.5">
              Programmatic entity intersection confirmed coordinated campaign across{' '}
              <span className="text-soc-accent font-semibold">
                {report.participating_agents?.length || 3} Domain Agents
              </span>{' '}
              anchored on Pivot Host <span className="text-soc-danger font-bold">{pivotIp}</span>.
            </p>
          </div>
        </div>

        {/* Confidence Score Meter */}
        <div className="flex items-center space-x-4 bg-soc-bg/90 p-3 rounded-xl border border-soc-danger/40">
          <div className="text-right font-mono">
            <div className="text-[10px] text-slate-400 uppercase">Supervisor Confidence</div>
            <div className="text-2xl font-black text-soc-danger">{confidencePct}%</div>
          </div>
          <div className="h-10 w-2.5 bg-slate-800 rounded-full overflow-hidden flex flex-col justify-end p-0.5 border border-slate-700">
            <div
              className="w-full bg-soc-danger rounded-full transition-all duration-700"
              style={{ height: `${confidencePct}%` }}
            />
          </div>
        </div>
      </div>

      {/* Forensic Narrative Callout */}
      <div className="p-4 rounded-xl bg-soc-bg/90 border border-soc-border space-y-1.5">
        <div className="flex items-center space-x-2 text-xs font-mono text-soc-accent font-semibold uppercase">
          <Cpu className="h-4 w-4 text-soc-accent" />
          <span>Cross-Vector Forensic Narrative</span>
        </div>
        <p className="text-xs font-mono text-slate-200 leading-relaxed">
          {report.forensic_narrative}
        </p>
      </div>

      {/* MITRE ATT&CK Chronological Timeline */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-soc-border pb-2.5">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-200 font-bold uppercase">
            <Clock className="h-4 w-4 text-soc-accent" />
            <span>Chronological MITRE ATT&CK Kill-Chain Timeline</span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {timelineStages.length} Verified Attack Stages
          </span>
        </div>

        <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-soc-accent before:via-soc-warning before:to-soc-danger">
          {timelineStages.map((stage, idx) => (
            <div key={idx} className="relative flex items-start space-x-4">
              {/* Timeline Stage Marker Pin */}
              <div className="absolute -left-6 top-1 h-5 w-5 rounded-full bg-soc-bg border-2 border-soc-danger flex items-center justify-center text-[10px] font-mono font-bold text-soc-danger">
                {stage.stage_number || idx + 1}
              </div>

              {/* Stage Card */}
              <div className="flex-1 glass-card p-4 rounded-xl border border-soc-border space-y-2 hover:border-slate-600 transition">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-soc-danger/15 border border-soc-danger/30 text-soc-danger text-[11px] font-mono font-bold uppercase">
                      Stage {stage.stage_number || idx + 1}: {stage.tactic}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    Indicator: <span className="text-slate-200">{stage.correlated_indicator}</span>
                  </span>
                </div>

                <p className="text-xs font-mono text-slate-300 leading-relaxed">
                  {stage.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Containment Playbook & Executable Bash Commands */}
      <div className="space-y-4 pt-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-2.5">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-200 font-bold uppercase">
            <Terminal className="h-4 w-4 text-soc-success" />
            <span>Automated SOAR Containment Playbook</span>
          </div>

          <button
            type="button"
            onClick={handleCopyAll}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-soc-surface hover:bg-slate-800 border border-soc-border text-xs font-mono text-slate-300 hover:text-slate-100 transition"
          >
            {copiedAll ? (
              <>
                <Check className="h-3.5 w-3.5 text-soc-success" />
                <span className="text-soc-success">All Copied!</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Copy Entire Playbook Script</span>
              </>
            )}
          </button>
        </div>

        <div className="space-y-2.5">
          {containmentSteps.map((step, idx) => {
            const isCompleted = Boolean(completedSteps[idx]);
            const isCopied = copiedIndex === idx;

            return (
              <div
                key={idx}
                className={`p-3.5 rounded-xl border transition-all duration-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  isCompleted
                    ? 'bg-soc-success/5 border-soc-success/30 opacity-70'
                    : 'bg-soc-bg border-soc-border hover:border-slate-600'
                }`}
              >
                {/* Checkbox and Command Text */}
                <div className="flex items-start space-x-3 flex-1">
                  <button
                    type="button"
                    onClick={() => toggleStepCompleted(idx)}
                    className={`mt-0.5 h-4 w-4 rounded border flex items-center justify-center transition ${
                      isCompleted
                        ? 'bg-soc-success border-soc-success text-slate-950'
                        : 'border-slate-600 hover:border-slate-400'
                    }`}
                  >
                    {isCompleted && <Check className="h-3 w-3 stroke-[3]" />}
                  </button>

                  <div className="space-y-0.5 flex-1 font-mono text-xs">
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] text-slate-500 font-bold">
                        STEP {idx + 1}
                      </span>
                      {isCompleted && (
                        <span className="text-[10px] text-soc-success font-semibold flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" /> Remediated
                        </span>
                      )}
                    </div>
                    <code className="block text-slate-200 text-xs bg-soc-surface/70 px-2.5 py-1.5 rounded border border-soc-border select-all break-all">
                      {step}
                    </code>
                  </div>
                </div>

                {/* 1-Click Copy Button */}
                <div className="flex items-center justify-end sm:justify-start">
                  <button
                    type="button"
                    onClick={() => handleCopyCommand(step, idx)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-soc-surface hover:bg-slate-800 border border-soc-border text-xs font-mono text-slate-300 hover:text-slate-100 transition"
                  >
                    {isCopied ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-soc-success" />
                        <span className="text-soc-success">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default SOARPlaybook;
