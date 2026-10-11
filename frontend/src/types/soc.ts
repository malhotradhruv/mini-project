/**
 * Strict TypeScript Data Contracts matching FastAPI & LangGraph Pydantic models.
 * Reference: IEEE Access (Hmimou et al., 2025).
 */

export interface ExtractedArtifacts {
  ips: string[];
  domains: string[];
  urls: string[];
  ports: number[];
  cves: string[];
  timestamps: string[];
}

export interface AgentFinding {
  agent_id: string;
  is_malicious: boolean;
  risk_score: number;
  artifacts: ExtractedArtifacts;
  indicators: string[];
  raw_evidence: Record<string, any>;
  analyst_summary: string;
}

export interface AttackStage {
  stage_number: number;
  tactic: string;
  description: string;
  correlated_indicator: string;
}

export type ThreatSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface CorrelatedIncidentReport {
  incident_detected: boolean;
  threat_severity: ThreatSeverity;
  confidence_score: number;
  participating_agents: string[];
  common_artifacts: ExtractedArtifacts;
  attack_timeline: AttackStage[];
  forensic_narrative: string;
  containment_playbook: string[];
}

export interface TriageRequest {
  email_text: string;
  log_text: string;
  target_network: string;
  task_id?: string;
}

export interface TriageResponse {
  task_id: string;
  raw_email: string;
  raw_logs: string;
  target_network: string;
  findings: AgentFinding[];
  correlation_result: CorrelatedIncidentReport | null;
  audit_trace: string[];
}

export interface SSEStreamEvent {
  step: "email_worker" | "log_worker" | "ip_worker" | "supervisor" | "error";
  status: "running" | "completed" | "failed";
  data?: AgentFinding | CorrelatedIncidentReport | null;
  error?: string;
}

export interface VectorIndexStatus {
  status: "ready" | "degraded";
  total_vectors: number;
  error?: string;
}

export interface HealthResponse {
  status: string;
  active_llm: string;
  vector_index: VectorIndexStatus;
  paper_alignment: string;
  timestamp: string;
}

export interface BenchmarkResponse {
  metadata: Record<string, any>;
  published_benchmarks: {
    system_accuracy_pct?: number;
    correlation_precision_pct?: number;
    false_positive_reduction_pct?: number;
    analyst_time_reduction_pct?: number;
    [key: string]: any;
  };
  platform_results: {
    system_accuracy_pct?: number;
    correlation_precision_pct?: number;
    false_positive_reduction_pct?: number;
    analyst_time_reduction_pct?: number;
    global_precision_pct?: number;
    global_recall_pct?: number;
    global_f1_score?: number;
    global_fpr_pct?: number;
    avg_latency_ms?: number;
    [key: string]: any;
  };
  confusion_matrix: {
    true_positives?: number;
    false_positives?: number;
    true_negatives?: number;
    false_negatives?: number;
    [key: string]: any;
  };
  agent_performance: Record<string, any>;
}
