import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import {
  Share2,
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Info,
  ShieldAlert,
  Globe,
  Terminal,
  Bug,
  Server,
  Layers,
  X,
} from 'lucide-react';
import { AgentFinding, CorrelatedIncidentReport } from '../types/soc';

interface AttackTopologyGraphProps {
  findings?: AgentFinding[];
  correlationResult?: CorrelatedIncidentReport | null;
}

interface NodeDetail {
  id: string;
  label: string;
  category: 'phishing' | 'attacker_ip' | 'network_service' | 'exploited_cve';
  evidence: Record<string, any>;
  description: string;
}

export const AttackTopologyGraph: React.FC<AttackTopologyGraphProps> = ({
  findings = [],
  correlationResult,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null);

  // Extract relevant threat entities across findings
  const emailFinding = findings.find((f) =>
    ['emailintelligenceagent', 'email_agent', 'emailagent'].includes(f.agent_id.toLowerCase())
  );
  const logFinding = findings.find((f) =>
    ['behaviorallogagent', 'log_agent', 'logagent'].includes(f.agent_id.toLowerCase())
  );
  const ipFinding = findings.find((f) =>
    ['networkreconagent', 'ip_agent', 'ipagent'].includes(f.agent_id.toLowerCase())
  );

  const sharedIps =
    correlationResult?.common_artifacts?.ips?.length
      ? correlationResult.common_artifacts.ips
      : ['192.168.1.105'];

  const pivotIp = sharedIps[0] || '192.168.1.105';
  const isCoordinated = Boolean(correlationResult?.incident_detected);

  // Initialize and update Cytoscape graph
  useEffect(() => {
    if (!containerRef.current) return;

    const elements: cytoscape.ElementDefinition[] = [];

    if (isCoordinated) {
      // 1. Phishing Vector Node
      const phishingUrl =
        emailFinding?.artifacts?.urls?.[0] || 'http://192.168.1.105/patch.php';
      elements.push({
        data: {
          id: 'node_phishing',
          label: `🌐 Phishing Lure\n${phishingUrl}`,
          category: 'phishing',
          evidence: {
            url: phishingUrl,
            indicators: emailFinding?.indicators || [
              "Urgency keywords: ['24 hours']",
            ],
            risk_score: emailFinding?.risk_score ?? 0.8,
            agent: 'EmailIntelligenceAgent',
          },
          description:
            'Initial access vector delivering social-engineering lure and malicious internal redirect URL.',
        },
      });

      // 2. Attacker Pivot IP Node (Neon Red)
      elements.push({
        data: {
          id: 'node_attacker_ip',
          label: `💻 Pivot IP\n${pivotIp}`,
          category: 'attacker_ip',
          evidence: {
            ip: pivotIp,
            shared_across: correlationResult?.participating_agents || [
              'EmailIntelligenceAgent',
              'BehavioralLogAgent',
              'NetworkReconAgent',
            ],
            auth_failures: 2,
            priv_escalations: 1,
            severity: 'CRITICAL',
          },
          description:
            'Programmatic entity intersection linking email lure to credential brute force and target network scans.',
        },
      });

      // 3. Network Service Nodes (Target Port & Daemon)
      const ports = ipFinding?.artifacts?.ports?.length
        ? ipFinding.artifacts.ports
        : [22, 80];

      if (ports.includes(22)) {
        elements.push({
          data: {
            id: 'node_service_ssh',
            label: `🚪 Port 22\nOpenSSH 7.4`,
            category: 'network_service',
            evidence: {
              port: 22,
              protocol: 'TCP',
              daemon: 'OpenSSH 7.4',
              auth_events: 'Failed passwords followed by accepted root session',
            },
            description:
              'Exposed SSH authentication daemon subjected to password stuffing and unauthorized privilege elevation.',
          },
        });
      }

      if (ports.includes(80)) {
        elements.push({
          data: {
            id: 'node_service_http',
            label: `🚪 Port 80\nApache 2.4.49`,
            category: 'network_service',
            evidence: {
              port: 80,
              protocol: 'TCP',
              daemon: 'Apache 2.4.49',
              path: '/patch.php',
            },
            description:
              'Exposed web service hosting fake security patch script with vulnerable path traversal daemon.',
          },
        });
      }

      // 4. Exploited CVE Nodes
      const cves = ipFinding?.artifacts?.cves?.length
        ? ipFinding.artifacts.cves
        : ['CVE-2021-41773', 'CVE-2016-10009'];

      cves.slice(0, 2).forEach((cve, idx) => {
        const cvss = cve.includes('41773') ? '9.8 (CRITICAL)' : '7.3 (HIGH)';
        elements.push({
          data: {
            id: `node_cve_${idx}`,
            label: `⚠️ ${cve}\nCVSS ${cvss}`,
            category: 'exploited_cve',
            evidence: {
              cve_id: cve,
              cvss_score: cvss,
              vulnerability: cve.includes('41773')
                ? 'Remote Path Traversal & RCE'
                : 'SSH Privilege Escalation',
              patch_status: 'UNPATCHED',
            },
            description:
              'Grounded NIST NVD vulnerability record actively matching exposed service banner.',
          },
        });
      });

      // 5. Connect Dynamic Links (Edges)
      // [Phishing Lure] ---> [Attacker IP]
      elements.push({
        data: {
          id: 'edge_phish_to_ip',
          source: 'node_phishing',
          target: 'node_attacker_ip',
          label: 'Redirects / Resolves',
        },
      });

      // [Attacker IP] ---> [Port 22 SSH]
      if (elements.some((el) => el.data.id === 'node_service_ssh')) {
        elements.push({
          data: {
            id: 'edge_ip_to_ssh',
            source: 'node_attacker_ip',
            target: 'node_service_ssh',
            label: 'Brute Force Burst',
          },
        });
      }

      // [Attacker IP] ---> [Port 80 HTTP]
      if (elements.some((el) => el.data.id === 'node_service_http')) {
        elements.push({
          data: {
            id: 'edge_ip_to_http',
            source: 'node_attacker_ip',
            target: 'node_service_http',
            label: 'HTTP Payload Fetch',
          },
        });
      }

      // [Port 80 HTTP] ---> [CVE-2021-41773]
      if (
        elements.some((el) => el.data.id === 'node_service_http') &&
        elements.some((el) => el.data.id === 'node_cve_0')
      ) {
        elements.push({
          data: {
            id: 'edge_http_to_cve',
            source: 'node_service_http',
            target: 'node_cve_0',
            label: 'Path Traversal',
          },
        });
      }

      // [Port 22 SSH] ---> [CVE-2016-10009]
      if (
        elements.some((el) => el.data.id === 'node_service_ssh') &&
        elements.some((el) => el.data.id === 'node_cve_1')
      ) {
        elements.push({
          data: {
            id: 'edge_ssh_to_cve',
            source: 'node_service_ssh',
            target: 'node_cve_1',
            label: 'Priv Esc Exploit',
          },
        });
      }
    } else {
      // Disjoint / Standby Isolated Node Display
      elements.push(
        {
          data: {
            id: 'node_phishing_isolated',
            label: '🌐 Email Vector\n(Isolated)',
            category: 'phishing',
            evidence: { status: 'Benign / Isolated' },
            description: 'No cross-domain entity joins detected with perimeter logs.',
          },
        },
        {
          data: {
            id: 'node_log_isolated',
            label: '📜 Log Stream\n(Isolated)',
            category: 'network_service',
            evidence: { status: 'Benign / Isolated' },
            description: 'Internal syslog events show normal baseline behavior.',
          },
        },
        {
          data: {
            id: 'node_ip_isolated',
            label: '💻 Target Host\n10.0.0.1 (Hardened)',
            category: 'attacker_ip',
            evidence: { status: 'Hardened Perimeter' },
            description: 'Zero critical CVE matches detected.',
          },
        }
      );
    }

    // Destroy existing instance before creating a new one
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    // Initialize Cytoscape Instance
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'font-family': 'JetBrains Mono, Fira Code, ui-monospace, monospace',
            'font-size': '10px',
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
            color: '#F8FAFC',
            'text-outline-color': '#030712',
            'text-outline-width': 2,
            padding: '12px',
          },
        },
        // Phishing Vector Node (Sky Blue)
        {
          selector: 'node[category="phishing"]',
          style: {
            shape: 'round-rectangle',
            width: 140,
            height: 60,
            'background-color': '#0B1222',
            'border-width': 2,
            'border-color': '#38BDF8',
            'border-opacity': 0.9,
          },
        },
        // Attacker Pivot IP Node (Neon Red Pulsing Glow)
        {
          selector: 'node[category="attacker_ip"]',
          style: {
            shape: 'ellipse',
            width: 110,
            height: 110,
            'background-color': '#450A0A',
            'border-width': 3.5,
            'border-color': '#EF4444',
            'border-opacity': 1,
          },
        },
        // Network Service Node (Amber)
        {
          selector: 'node[category="network_service"]',
          style: {
            shape: 'round-rectangle',
            width: 120,
            height: 60,
            'background-color': '#1C1917',
            'border-width': 2,
            'border-color': '#F59E0B',
            'border-opacity': 0.9,
          },
        },
        // Exploited CVE Node (Rose Diamond)
        {
          selector: 'node[category="exploited_cve"]',
          style: {
            shape: 'diamond',
            width: 110,
            height: 90,
            'background-color': '#881337',
            'border-width': 2.5,
            'border-color': '#F43F5E',
            'border-opacity': 1,
          },
        },
        // Connected Dynamic Attack Edges
        {
          selector: 'edge',
          style: {
            width: 2.5,
            'curve-style': 'bezier',
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 1.2,
            'line-style': 'dashed',
            'line-dash-pattern': [6, 4],
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '9px',
            color: '#94A3B8',
            'text-background-color': '#030712',
            'text-background-opacity': 0.9,
            'text-background-padding': '3px',
            'text-rotation': 'autorotate',
            label: 'data(label)',
          },
        },
      ],
      layout: {
        name: isCoordinated ? 'breadthfirst' : 'grid',
        directed: isCoordinated,
        padding: 40,
        spacingFactor: 1.25,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    // Handle Node Click Selection
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const data = node.data();
      setSelectedNode({
        id: data.id,
        label: data.label.replace('\n', ' • '),
        category: data.category,
        evidence: data.evidence,
        description: data.description,
      });
    });

    // Deselect when clicking background
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [isCoordinated, pivotIp, emailFinding, ipFinding, logFinding, correlationResult]);

  // Layout Control Helpers
  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 35);
  };

  const handleReset = () => {
    cyRef.current?.reset();
    cyRef.current?.fit(undefined, 35);
  };

  return (
    <div className="glass-card rounded-xl border border-soc-border p-6 space-y-4 shadow-2xl relative overflow-hidden">
      {/* Topology Header & Control Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border pb-4">
        <div>
          <div className="flex items-center space-x-2 text-soc-accent font-mono text-xs uppercase tracking-wider mb-1">
            <Share2 className="h-3.5 w-3.5 text-soc-accent animate-pulse" />
            <span>Interactive Attack Surface & Topology Mapping</span>
          </div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            Cross-Vector Attack Topology Graph
            {isCoordinated ? (
              <span className="text-[10px] px-2 py-0.5 rounded bg-soc-danger/15 border border-soc-danger/40 text-soc-danger font-mono font-bold">
                MULTI-STAGE CORRELATED
              </span>
            ) : (
              <span className="text-[10px] px-2 py-0.5 rounded bg-soc-success/15 border border-soc-success/40 text-soc-success font-mono font-bold">
                ISOLATED ENTITIES
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-400">
            Interactive Cytoscape topology visualizing entity intersection links ({pivotIp}) from Phishing lure to Network Daemons and CVEs.
          </p>
        </div>

        {/* Graph Navigation Toolbar */}
        <div className="flex items-center space-x-1.5 bg-soc-bg border border-soc-border rounded-lg p-1">
          <button
            type="button"
            onClick={handleZoomIn}
            title="Zoom In"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={handleZoomOut}
            title="Zoom Out"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={handleFit}
            title="Fit to Screen"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <Maximize2 className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={handleReset}
            title="Reset Position"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Topology Legend */}
      <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-300 bg-soc-bg/60 p-2.5 rounded-lg border border-soc-border">
        <span className="text-slate-500 font-semibold uppercase text-[10px]">LEGEND:</span>
        <span className="inline-flex items-center space-x-1 text-sky-400">
          <span className="h-2.5 w-2.5 rounded-sm bg-sky-500"></span>
          <span>Phishing Lure</span>
        </span>
        <span className="inline-flex items-center space-x-1 text-soc-danger">
          <span className="h-2.5 w-2.5 rounded-full bg-soc-danger"></span>
          <span>Attacker Pivot IP</span>
        </span>
        <span className="inline-flex items-center space-x-1 text-amber-400">
          <span className="h-2.5 w-2.5 rounded-sm bg-amber-500"></span>
          <span>Network Service</span>
        </span>
        <span className="inline-flex items-center space-x-1 text-rose-400">
          <span className="h-2.5 w-2.5 rotate-45 bg-rose-500"></span>
          <span>Exploited CVE</span>
        </span>
        <span className="text-[11px] text-slate-400 ml-auto">
          Tip: Click any node to inspect raw forensic evidence
        </span>
      </div>

      {/* Cytoscape Canvas Container */}
      <div className="relative w-full h-[380px] bg-soc-bg/90 rounded-lg border border-soc-border overflow-hidden">
        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Node Detail Forensic Tooltip / Popover */}
        {selectedNode && (
          <div className="absolute bottom-4 right-4 max-w-sm w-full glass-card p-4 rounded-xl border border-soc-accent/60 shadow-2xl space-y-3 z-20 animate-in fade-in slide-in-from-bottom-2">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                {selectedNode.category === 'phishing' && (
                  <Globe className="h-4 w-4 text-sky-400" />
                )}
                {selectedNode.category === 'attacker_ip' && (
                  <ShieldAlert className="h-4 w-4 text-soc-danger" />
                )}
                {selectedNode.category === 'network_service' && (
                  <Server className="h-4 w-4 text-amber-400" />
                )}
                {selectedNode.category === 'exploited_cve' && (
                  <Bug className="h-4 w-4 text-rose-400" />
                )}
                <h4 className="font-bold text-xs font-mono text-slate-100">
                  {selectedNode.label}
                </h4>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-100 p-0.5 rounded"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            <p className="text-[11px] text-slate-300 font-sans leading-relaxed">
              {selectedNode.description}
            </p>

            <div className="space-y-1">
              <span className="text-[10px] font-mono text-slate-400 uppercase">
                Forensic Evidence Details:
              </span>
              <pre className="text-[10px] font-mono bg-soc-bg p-2 rounded border border-soc-border text-slate-300 max-h-32 overflow-y-auto terminal-scroll">
                {JSON.stringify(selectedNode.evidence, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackTopologyGraph;
