import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
  BackgroundVariant,
  Node,
  Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Mail,
  Skull,
  Server,
  Bug,
  ShieldAlert,
  Terminal,
  X,
  RotateCcw,
  ExternalLink,
  Copy,
  Check,
  Radio,
  Layers,
  Crosshair,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// 1. CUSTOM NODE COMPONENTS (Registered with Sentinel-AI Design Tokens)
// ─────────────────────────────────────────────────────────────────────────────

// 1. Vector Node: Phishing Lure / Domain (Phosphor Cyan glow)
const VectorNode: React.FC<{ data: any; selected?: boolean }> = ({ data, selected }) => (
  <div
    className={`p-3.5 rounded-lg font-mono transition-all duration-200 min-w-[240px] relative ${
      selected ? 'ring-2 ring-[var(--cyan)] shadow-glow-cyan' : ''
    }`}
    style={{
      background: 'var(--surface)',
      border: '1px solid var(--cyan)',
      boxShadow: selected
        ? '0 0 25px -2px rgba(0, 240, 255, 0.45)'
        : '0 0 16px -4px rgba(0, 240, 255, 0.25)',
    }}
  >
    <Handle
      type="target"
      position={Position.Top}
      className="!w-2.5 !h-2.5 !bg-[var(--cyan)] !border !border-white/30"
    />
    <div className="flex items-center gap-2.5 mb-2">
      <div
        className="p-1.5 rounded-md"
        style={{
          background: 'var(--cyan-subtle)',
          border: '1px solid var(--cyan-dim)',
          color: 'var(--cyan)',
        }}
      >
        <Mail className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <span
          className="text-[9px] font-bold uppercase tracking-wider block"
          style={{ color: 'var(--cyan)' }}
        >
          ✉️ Initial Access // {data.technique || 'T1566.002'}
        </span>
        <span
          className="text-xs font-bold truncate block"
          style={{ color: 'var(--text-primary)' }}
        >
          {data.label}
        </span>
      </div>
    </div>
    <div
      className="pt-2 flex items-center justify-between text-[10px]"
      style={{ borderTop: '1px solid var(--edge)' }}
    >
      <span className="badge badge-cyan text-[8px]">PHISHING LURE</span>
      <span className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>
        Vector: SMTP
      </span>
    </div>
    <Handle
      type="source"
      position={Position.Bottom}
      className="!w-2.5 !h-2.5 !bg-[var(--cyan)] !border !border-white/30"
    />
  </div>
);

// 2. Threat Actor Node: Attacker IP (Cadmium Crimson glow with pulsating ring)
const ThreatActorNode: React.FC<{ data: any; selected?: boolean }> = ({ data, selected }) => (
  <div
    className={`p-3.5 rounded-lg font-mono transition-all duration-200 min-w-[240px] relative ${
      selected ? 'ring-2 ring-[var(--crimson)] shadow-glow-crimson' : ''
    }`}
    style={{
      background: 'var(--surface)',
      border: '1px solid var(--crimson)',
      boxShadow: selected
        ? '0 0 28px -2px rgba(255, 30, 68, 0.55)'
        : '0 0 18px -4px rgba(255, 30, 68, 0.30)',
    }}
  >
    {/* Pulsating border ring */}
    <div className="absolute -inset-1 rounded-lg border border-[var(--crimson)]/35 animate-pulse pointer-events-none" />

    <Handle
      type="target"
      position={Position.Top}
      className="!w-2.5 !h-2.5 !bg-[var(--crimson)] !border !border-white/30"
    />
    <div className="flex items-center gap-2.5 mb-2">
      <div
        className="p-1.5 rounded-md"
        style={{
          background: 'var(--crimson-subtle)',
          border: '1px solid var(--crimson-dim)',
          color: 'var(--crimson)',
        }}
      >
        <Skull className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <span
          className="text-[9px] font-bold uppercase tracking-wider block"
          style={{ color: 'var(--crimson)' }}
        >
          🚨 Threat Actor Entity
        </span>
        <span
          className="text-xs font-bold font-mono tabular-nums truncate block"
          style={{ color: 'var(--text-primary)' }}
        >
          {data.label}
        </span>
      </div>
    </div>
    <div
      className="pt-2 flex items-center justify-between text-[10px]"
      style={{ borderTop: '1px solid var(--edge)' }}
    >
      <span className="badge severity-critical text-[8px] animate-pulse">
        ATTACKER IP
      </span>
      <span className="text-[9px]" style={{ color: 'var(--crimson)' }}>
        {data.technique || 'T1110.001'} Brute-Force
      </span>
    </div>
    <Handle
      type="source"
      position={Position.Bottom}
      className="!w-2.5 !h-2.5 !bg-[var(--crimson)] !border !border-white/30"
    />
  </div>
);

// 3. Target Service Node: Host Exposure & Open Ports (Electric Amber)
const ServiceNode: React.FC<{ data: any; selected?: boolean }> = ({ data, selected }) => (
  <div
    className={`p-3.5 rounded-lg font-mono transition-all duration-200 min-w-[240px] relative ${
      selected ? 'ring-2 ring-[var(--amber)] shadow-glow-amber' : ''
    }`}
    style={{
      background: 'var(--surface)',
      border: '1px solid var(--amber)',
      boxShadow: selected
        ? '0 0 24px -2px rgba(255, 170, 0, 0.45)'
        : '0 0 16px -4px rgba(255, 170, 0, 0.25)',
    }}
  >
    <Handle
      type="target"
      position={Position.Top}
      className="!w-2.5 !h-2.5 !bg-[var(--amber)] !border !border-white/30"
    />
    <div className="flex items-center gap-2.5 mb-2">
      <div
        className="p-1.5 rounded-md"
        style={{
          background: 'var(--amber-subtle)',
          border: '1px solid var(--amber-dim)',
          color: 'var(--amber)',
        }}
      >
        <Server className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <span
          className="text-[9px] font-bold uppercase tracking-wider block"
          style={{ color: 'var(--amber)' }}
        >
          🖥️ Host Exposure
        </span>
        <span
          className="text-xs font-bold truncate block"
          style={{ color: 'var(--text-primary)' }}
        >
          {data.label}
        </span>
      </div>
    </div>
    <div
      className="pt-2 flex items-center justify-between text-[10px]"
      style={{ borderTop: '1px solid var(--edge)' }}
    >
      <span className="badge badge-amber text-[8px]">{data.status || 'EXPOSED'}</span>
      <span className="text-[9px] font-mono" style={{ color: 'var(--text-tertiary)' }}>
        {data.ports || 'Port 22 SSH / 80 HTTP'}
      </span>
    </div>
    <Handle
      type="source"
      position={Position.Bottom}
      className="!w-2.5 !h-2.5 !bg-[var(--amber)] !border !border-white/30"
    />
  </div>
);

// 4. Exploit Node: NIST NVD CVE Identifier (Laser Violet)
const ExploitNode: React.FC<{ data: any; selected?: boolean }> = ({ data, selected }) => (
  <div
    className={`p-3.5 rounded-lg font-mono transition-all duration-200 min-w-[240px] relative ${
      selected ? 'ring-2 ring-[var(--violet)] shadow-glow-violet' : ''
    }`}
    style={{
      background: 'var(--surface)',
      border: '1px solid var(--violet)',
      boxShadow: selected
        ? '0 0 24px -2px rgba(139, 92, 246, 0.45)'
        : '0 0 16px -4px rgba(139, 92, 246, 0.25)',
    }}
  >
    <Handle
      type="target"
      position={Position.Top}
      className="!w-2.5 !h-2.5 !bg-[var(--violet)] !border !border-white/30"
    />
    <div className="flex items-center gap-2.5 mb-2">
      <div
        className="p-1.5 rounded-md"
        style={{
          background: 'var(--violet-subtle)',
          border: '1px solid var(--violet-dim)',
          color: 'var(--violet)',
        }}
      >
        <Bug className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <span
          className="text-[9px] font-bold uppercase tracking-wider block"
          style={{ color: 'var(--violet)' }}
        >
          ⚡ Exploited Vulnerability
        </span>
        <span
          className="text-xs font-bold truncate block"
          style={{ color: 'var(--text-primary)' }}
        >
          {data.label}
        </span>
      </div>
    </div>
    <div
      className="pt-2 flex items-center justify-between text-[10px]"
      style={{ borderTop: '1px solid var(--edge)' }}
    >
      <span className="badge severity-critical text-[8px]">
        CVSS {data.cvss || '9.8'} CRITICAL
      </span>
      <span className="text-[9px]" style={{ color: 'var(--violet)' }}>
        NIST NVD
      </span>
    </div>
    <Handle
      type="source"
      position={Position.Bottom}
      className="!w-2.5 !h-2.5 !bg-[var(--violet)] !border !border-white/30"
    />
  </div>
);

// ─────────────────────────────────────────────────────────────────────────────
// 2. FALLBACK ATTACK CHAIN TOPOLOGY (Scenario A Demonstration Chain)
// ─────────────────────────────────────────────────────────────────────────────
const defaultDemonstrationNodes: Node[] = [
  {
    id: 'node-vector',
    type: 'vectorNode',
    position: { x: 300, y: 40 },
    data: {
      label: 'paypa1-support.com',
      technique: 'T1566.002',
      category: 'Initial Access Vector',
      agent: 'EmailHunter',
      timestamp: '2026-10-11T10:14:00Z',
      details: {
        domain: 'paypa1-support.com',
        sender: 'security@paypa1-support.com',
        mx_status: 'NO_MX_RECORDS',
        social_urgency_score: '0.94 (Critical)',
        threat_type: 'Spearphishing Credential Harvester',
        target_inbox: 'finance-admin@sentinel.internal',
      },
    },
  },
  {
    id: 'node-attacker',
    type: 'threatActorNode',
    position: { x: 300, y: 220 },
    data: {
      label: '192.168.1.105',
      technique: 'T1110.001',
      category: 'Threat Actor Entity',
      agent: 'LogForensics',
      timestamp: '2026-10-11T10:14:03Z',
      details: {
        attacker_ip: '192.168.1.105',
        failed_ssh_attempts: '3 Consecutive Failures',
        auth_status: 'Accepted password for root (Brute-forced)',
        subnet_zone: 'Untrusted Subnet (Perimeter Ingress)',
        mitre_tactic: 'Credential Access / Lateral Movement',
      },
    },
  },
  {
    id: 'node-service-ssh',
    type: 'serviceNode',
    position: { x: 140, y: 420 },
    data: {
      label: 'Port 22 SSH / Sudo (srv1)',
      technique: 'T1548.003',
      category: 'Host Exposure / Escalation',
      status: 'COMPROMISED',
      ports: 'Port 22 SSH (Open)',
      agent: 'NetworkRecon',
      timestamp: '2026-10-11T10:14:10Z',
      details: {
        daemon: 'OpenSSH 8.9p1 Ubuntu',
        port: '22 / TCP',
        escalation: 'sudo /bin/bash (uid=0 root)',
        service_state: 'COMPROMISED (Privilege Escalation)',
      },
    },
  },
  {
    id: 'node-web-service',
    type: 'serviceNode',
    position: { x: 460, y: 420 },
    data: {
      label: 'Port 80 Apache HTTPD',
      technique: 'T1190',
      category: 'Host Exposure / Web Service',
      status: 'EXPOSED',
      ports: 'Port 80 HTTP (Open)',
      agent: 'NetworkRecon',
      timestamp: '2026-10-11T10:14:15Z',
      details: {
        daemon: 'Apache HTTP Server 2.4.49',
        port: '80 / TCP',
        cve_vulnerable: 'CVE-2021-41773',
        service_state: 'VULNERABLE TO PATH TRAVERSAL',
      },
    },
  },
  {
    id: 'node-exploit',
    type: 'exploitNode',
    position: { x: 460, y: 620 },
    data: {
      label: 'CVE-2021-41773',
      cvss: '9.8',
      technique: 'T1190',
      category: 'Exploited Vulnerability',
      agent: 'NetworkRecon & LeadSupervisor',
      timestamp: '2026-10-11T10:14:22Z',
      details: {
        cve_id: 'CVE-2021-41773',
        cvss_score: '9.8 (CRITICAL)',
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        vuln_type: 'Path Traversal & Remote File Disclosure',
        remediation: 'Patch to Apache 2.4.51 or apply iptables DROP ingress rule',
      },
    },
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// 3. ANIMATED DIRECTIONAL CONNECTION EDGES
// Vector Node ➔ Threat Actor IP ➔ Exposed Service ➔ CVE Exploit
// ─────────────────────────────────────────────────────────────────────────────
const defaultDemonstrationEdges: Edge[] = [
  {
    id: 'edge-vector-attacker',
    source: 'node-vector',
    target: 'node-attacker',
    animated: true,
    style: { stroke: 'var(--crimson)', strokeWidth: 2 },
    label: 'DNS Spoof / Credential Harvest',
    labelStyle: {
      fill: 'var(--crimson)',
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 10,
      fontWeight: 700,
    },
    labelBgStyle: {
      fill: '#0B0E14',
      fillOpacity: 0.95,
      stroke: 'var(--crimson)',
      strokeWidth: 1,
    },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FF1E44' },
  },
  {
    id: 'edge-attacker-service-ssh',
    source: 'node-attacker',
    target: 'node-service-ssh',
    animated: true,
    style: { stroke: 'var(--crimson)', strokeWidth: 2 },
    label: 'SSH Brute-Force Auth (Port 22)',
    labelStyle: {
      fill: 'var(--crimson)',
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 10,
      fontWeight: 700,
    },
    labelBgStyle: {
      fill: '#0B0E14',
      fillOpacity: 0.95,
      stroke: 'var(--crimson)',
      strokeWidth: 1,
    },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FF1E44' },
  },
  {
    id: 'edge-attacker-web-service',
    source: 'node-attacker',
    target: 'node-web-service',
    animated: true,
    style: { stroke: 'var(--crimson)', strokeWidth: 2 },
    label: 'Port Scan & Recon (Port 80)',
    labelStyle: {
      fill: 'var(--crimson)',
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 10,
      fontWeight: 700,
    },
    labelBgStyle: {
      fill: '#0B0E14',
      fillOpacity: 0.95,
      stroke: 'var(--crimson)',
      strokeWidth: 1,
    },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FF1E44' },
  },
  {
    id: 'edge-web-exploit',
    source: 'node-web-service',
    target: 'node-exploit',
    animated: true,
    style: { stroke: 'var(--crimson)', strokeWidth: 2 },
    label: 'Path Traversal Exploit (CVE-2021-41773)',
    labelStyle: {
      fill: 'var(--crimson)',
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 10,
      fontWeight: 700,
    },
    labelBgStyle: {
      fill: '#0B0E14',
      fillOpacity: 0.95,
      stroke: 'var(--crimson)',
      strokeWidth: 1,
    },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FF1E44' },
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// 4. MAIN TOPOLOGY COMPONENT
// ─────────────────────────────────────────────────────────────────────────────
export const Topology: React.FC = () => {
  const navigate = useNavigate();

  const [nodes, setNodes, onNodesChange] = useNodesState(defaultDemonstrationNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(defaultDemonstrationEdges);
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Register all 4 custom node types (with serviceNode alias)
  const nodeTypes = useMemo(
    () => ({
      vectorNode: VectorNode,
      threatActorNode: ThreatActorNode,
      serviceNode: ServiceNode,
      targetServiceNode: ServiceNode, // backward compatibility
      exploitNode: ExploitNode,
    }),
    []
  );

  // Check localStorage for active incident topology, or default to Scenario A
  useEffect(() => {
    try {
      const savedTopology = localStorage.getItem('sentinel_active_topology');
      if (savedTopology) {
        const parsed = JSON.parse(savedTopology);
        if (parsed.nodes && parsed.nodes.length > 0) {
          setNodes(parsed.nodes);
        }
        if (parsed.edges && parsed.edges.length > 0) {
          setEdges(parsed.edges);
        }
      }
    } catch {
      // Fallback auto-layout to Scenario A
      setNodes(defaultDemonstrationNodes);
      setEdges(defaultDemonstrationEdges);
    }
  }, [setNodes, setEdges]);

  // Click node handler
  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNodeData(node.data);
  }, []);

  // Reset Graph View
  const handleResetLayout = () => {
    setNodes(defaultDemonstrationNodes);
    setEdges(defaultDemonstrationEdges);
    setSelectedNodeData(null);
  };

  // Copy entity value to clipboard
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    setTimeout(() => setCopiedValue(null), 1500);
  };

  // Filter War Room by this entity
  const handleFilterWarRoom = (entityLabel: string) => {
    sessionStorage.setItem('sentinel_warroom_filter', entityLabel);
    navigate('/war-room');
  };

  return (
    <div
      className="h-full flex flex-col font-mono overflow-hidden select-none"
      style={{
        background: 'var(--canvas)',
        color: 'var(--text-primary)',
      }}
    >
      {/* ───────────────────────────────────────────────────────────────── */}
      {/* Top Topology Controls Header                                      */}
      {/* ───────────────────────────────────────────────────────────────── */}
      <div
        className="px-5 py-3 flex flex-wrap items-center justify-between gap-3 shrink-0 z-10"
        style={{
          background: 'var(--surface)',
          borderBottom: '1px solid var(--edge)',
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="p-1.5 rounded-md"
            style={{
              background: 'var(--cyan-subtle)',
              border: '1px solid var(--cyan-dim)',
              color: 'var(--cyan)',
            }}
          >
            <Crosshair className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-wider" style={{ color: 'var(--text-primary)' }}>
                ATTACK TOPOLOGY <span style={{ color: 'var(--cyan)' }}>//</span> GRAPH CANVAS
              </h1>
              <span className="badge badge-cyan text-[9px]">
                CROSS-DOMAIN ATTACK CHAIN
              </span>
            </div>
            <p className="text-[10px] tracking-wide mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Interactive directed graph tracking initial access pivot, lateral movement, and exploit execution.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleResetLayout}
            className="btn btn-ghost text-xs"
            title="Reset attack chain layout to default coordinates"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>RESET GRAPH VIEW</span>
          </button>
        </div>
      </div>

      {/* ───────────────────────────────────────────────────────────────── */}
      {/* Main Graph Canvas Area                                            */}
      {/* ───────────────────────────────────────────────────────────────── */}
      <div className="flex-1 relative overflow-hidden flex">
        <div className="flex-1 h-full relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.2}
            maxZoom={2.5}
            proOptions={{ hideAttribution: true }}
          >
            {/* Subtle #10141E dot grid on obsidian canvas */}
            <Background
              variant={BackgroundVariant.Dots}
              color="#10141E"
              gap={20}
              size={1}
            />

            {/* Custom Minimap styled with obsidian glass */}
            <MiniMap
              nodeColor={(n) => {
                if (n.type === 'vectorNode') return '#00F0FF';
                if (n.type === 'threatActorNode') return '#FF1E44';
                if (n.type === 'serviceNode' || n.type === 'targetServiceNode') return '#FFAA00';
                if (n.type === 'exploitNode') return '#8B5CF6';
                return '#5C6480';
              }}
              maskColor="rgba(5, 6, 9, 0.85)"
              className="!bg-[#0B0E14] !border !border-white/[0.08] !rounded-lg !shadow-2xl"
            />

            {/* Zoom & Viewport Controls styled with obsidian glass */}
            <Controls className="!bg-[#0B0E14] !border !border-white/[0.08] !rounded-lg !shadow-2xl !fill-[var(--text-secondary)]" />
          </ReactFlow>

          {/* Canvas Cyber Legend */}
          <div
            className="absolute bottom-5 left-5 z-10 p-3 rounded-lg text-[11px] space-y-1.5 shadow-2xl backdrop-blur-md"
            style={{
              background: 'rgba(11, 14, 20, 0.90)',
              border: '1px solid var(--edge)',
            }}
          >
            <span
              className="font-mono text-[9px] uppercase font-bold tracking-wider block mb-1"
              style={{ color: 'var(--text-tertiary)' }}
            >
              Attack Vector Legend
            </span>
            <div className="flex items-center gap-2" style={{ color: 'var(--cyan)' }}>
              <span className="w-2 h-2 rounded-full" style={{ background: 'var(--cyan)' }} />
              <span className="text-[10px]">Vector Node (Phishing Domain)</span>
            </div>
            <div className="flex items-center gap-2" style={{ color: 'var(--crimson)' }}>
              <span className="w-2 h-2 rounded-full" style={{ background: 'var(--crimson)' }} />
              <span className="text-[10px]">Threat Actor Node (Attacker IP)</span>
            </div>
            <div className="flex items-center gap-2" style={{ color: 'var(--amber)' }}>
              <span className="w-2 h-2 rounded-full" style={{ background: 'var(--amber)' }} />
              <span className="text-[10px]">Target Service Node (Daemon/Port)</span>
            </div>
            <div className="flex items-center gap-2" style={{ color: 'var(--violet)' }}>
              <span className="w-2 h-2 rounded-full" style={{ background: 'var(--violet)' }} />
              <span className="text-[10px]">Exploit Node (NVD CVE Vulnerability)</span>
            </div>
          </div>
        </div>

        {/* ───────────────────────────────────────────────────────────── */}
        {/* Interactive Node Inspector (Slide-out Drawer)                 */}
        {/* ───────────────────────────────────────────────────────────── */}
        {selectedNodeData && (
          <aside
            className="w-96 flex flex-col justify-between shrink-0 z-20 p-5 backdrop-blur-xl animate-fade-up"
            style={{
              background: 'rgba(11, 14, 20, 0.95)',
              borderLeft: '1px solid var(--edge)',
            }}
          >
            <div className="space-y-4">
              {/* Drawer Header */}
              <div
                className="flex items-center justify-between pb-3"
                style={{ borderBottom: '1px solid var(--edge)' }}
              >
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4" style={{ color: 'var(--cyan)' }} />
                  <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-primary)' }}>
                    Entity Telemetry Inspector
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNodeData(null)}
                  className="p-1 rounded text-slate-400 hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Node Title & Label */}
              <div>
                <span
                  className="font-mono text-[9px] uppercase font-bold tracking-wider block mb-1"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  Entity Identifier
                </span>
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-bold font-mono truncate" style={{ color: 'var(--cyan)' }}>
                    {selectedNodeData.label}
                  </h3>
                  <button
                    onClick={() => handleCopy(selectedNodeData.label)}
                    className="btn btn-icon btn-ghost text-[10px]"
                    title="Copy entity to clipboard"
                  >
                    {copiedValue === selectedNodeData.label ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* Category & MITRE ATT&CK Tactic */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div
                  className="p-2.5 rounded-md"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--edge)' }}
                >
                  <span className="font-mono text-[9px] uppercase font-bold block mb-1" style={{ color: 'var(--text-tertiary)' }}>
                    Category
                  </span>
                  <span className="font-mono text-[10px] font-bold" style={{ color: 'var(--text-primary)' }}>
                    {selectedNodeData.category || 'Security Artifact'}
                  </span>
                </div>

                <div
                  className="p-2.5 rounded-md"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--edge)' }}
                >
                  <span className="font-mono text-[9px] uppercase font-bold block mb-1" style={{ color: 'var(--text-tertiary)' }}>
                    MITRE Technique
                  </span>
                  <span className="badge badge-cyan text-[9px]">
                    {selectedNodeData.technique || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Detection Timestamp & Associated Agent */}
              <div
                className="p-2.5 rounded-md space-y-1.5 text-xs"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--edge)' }}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                    Detected By:
                  </span>
                  <span className="data-chip text-[10px] font-bold" style={{ color: 'var(--cyan)' }}>
                    {selectedNodeData.agent || 'LeadSupervisor'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                    Timestamp:
                  </span>
                  <span className="font-mono text-[10px] tabular-nums" style={{ color: 'var(--text-secondary)' }}>
                    {selectedNodeData.timestamp || '2026-10-11T10:14:00Z'}
                  </span>
                </div>
              </div>

              {/* Raw Technical Telemetry Key-Values */}
              <div>
                <span
                  className="font-mono text-[9px] uppercase font-bold tracking-wider block mb-1.5"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  Raw Forensic Attributes
                </span>
                <div
                  className="rounded-lg p-3 space-y-2 text-xs"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--edge)',
                  }}
                >
                  {Object.entries(selectedNodeData.details || {}).map(([key, val]) => (
                    <div
                      key={key}
                      className="flex justify-between items-start gap-2 pb-1.5 last:pb-0"
                      style={{ borderBottom: '1px solid var(--edge-subtle)' }}
                    >
                      <span className="font-mono text-[10px] capitalize" style={{ color: 'var(--text-tertiary)' }}>
                        {key.replace(/_/g, ' ')}:
                      </span>
                      <span className="font-mono font-semibold text-[10px] text-right break-all" style={{ color: 'var(--text-primary)' }}>
                        {String(val)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Advisory Pill */}
              <div
                className="p-3 rounded-lg text-xs space-y-1"
                style={{
                  background: 'var(--crimson-subtle)',
                  border: '1px solid var(--crimson-dim)',
                  color: 'var(--crimson)',
                }}
              >
                <span className="font-bold flex items-center gap-1.5 text-[11px]">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Attack Path Correlated</span>
                </span>
                <p className="text-[10px] leading-relaxed opacity-90">
                  Entity linked across email phishing lures, SSH authentication failure bursts, and daemon port exposure.
                </p>
              </div>
            </div>

            {/* Bottom Actions */}
            <div
              className="pt-4 space-y-2"
              style={{ borderTop: '1px solid var(--edge)' }}
            >
              <button
                onClick={() => handleFilterWarRoom(selectedNodeData.label)}
                className="btn btn-primary w-full text-xs py-2 shadow-glow-cyan flex items-center justify-center gap-2"
              >
                <Radio className="w-3.5 h-3.5" />
                <span>FILTER WAR ROOM BY THIS ENTITY</span>
              </button>

              <button
                onClick={() => setSelectedNodeData(null)}
                className="btn btn-ghost w-full text-xs py-2"
              >
                CLOSE INSPECTOR
              </button>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
};

export default Topology;
