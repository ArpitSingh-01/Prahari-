export type Scan = {
  id: string;
  name: string;
  file_size: number;
  status: "uploaded" | "parsing" | "complete" | "failed";
  progress: number;
  error: string | null;
  posture_score: number | null;
  grade: string | null;
  protocol_counts: Record<string, number>;
  session_count: number | null;
  created_at: string;
  completed_at: string | null;
};

export type Session = {
  session_id: string;
  protocol: string;
  transport: "implicit" | "starttls" | "plaintext";
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  server_host: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  kex_mechanism: string | null;
  pfs: boolean | null;
  offered_groups?: string[];
  negotiated_group?: string | null;
  key_exchange_group_size?: number | null;
  duration_ms: number;
  risk_score: number;
  rule_score: number;
  ml_adjustment: number;
  grade: string;
  is_anomaly: boolean;
  anomaly_score: number;
  anomaly_explanation: { feature: string; value: number; z: number }[];
  ml_risk: { label: string; proba: number[] } | null;
  reassembly_incomplete: boolean;
  truncated: boolean;
  bytes_c2s: number;
  bytes_s2c: number;
  alert_count: number;
  frames_c2s: number[];
  frames_s2c: number[];
  cleartext_creds: { kind: string; redacted: boolean; user?: string; password?: string }[];
  handshake_events: { kind: string; detail: Record<string, unknown> }[];
};

export type Finding = {
  rule_id: string;
  session_id: string | null;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  evidence: Record<string, unknown>;
  reference: string;
  remediation: string;
  weight: number;
  evidence_frames?: number[];
  evidence_hex?: string | null;
  /** Byte offset of the session's first evidence frame in the capture file. */
  packet_offset?: number | null;
  /** Classifier confidence (prob. mass on any bad risk class) for the
   *  finding's session; null for host-level findings. */
  ml_confidence?: number | null;
};

export type Advisory = Finding;

export type Certificate = {
  fingerprint_sha256: string;
  subject_cn: string;
  issuer_cn: string;
  self_signed: boolean;
  not_before: string;
  not_after: string;
  is_expired: boolean;
  days_to_expiry: number;
  key_algorithm: string;
  key_length: number;
  signature_hash: string;
  chain_issues: string[];
  san_entries: string[];
  pem: string;
  session_id: string;
  is_leaf?: boolean;
};

export type Posture = {
  rule_score: number;
  ml_adjustment: number;
  score: number;
  grade: string;
  ml?: {
    enabled: boolean;
    anomalous_sessions: number;
    risk_distribution: Record<string, number>;
  };
  severity_counts: Record<string, number>;
  servers: Record<string, { mean_score: number; sessions: number }>;
  pqc: { quantum_vulnerable_sessions: number; pqc_ready_sessions: number };
  credential_exposure: number;
};
export type ModelCard = {
  schema?: string;
  risk_classifier?: {
    model?: string;
    n_estimators?: number;
    features?: number;
    train_size?: number;
    test_size?: number;
    cv_accuracy?: number;
    holdout_accuracy?: number;
    per_class?: Record<string, { precision: number; recall: number; f1: number; support?: number }>;
    confusion_matrix?: { labels: string[]; matrix: number[][] };
    label_distribution?: Record<string, number>;
    labeling?: string;
  };
  anomaly_detector?: {
    model?: string;
    contamination?: number;
    baseline_sessions?: number;
    flag_rate_all?: number;
    flag_rate_clean_baseline?: number | null;
    corpus_sessions?: number;
    training?: string;
  };
  corpus?: { sessions: number; clean_sessions: number; source: string };
};

export type ScanResult = {
  sessions: Session[];
  findings: Finding[];
  advisories?: Advisory[];
  certificates: Certificate[];
  anomaly_explanations: {
    session_id: string;
    score: number;
    top_features: { feature: string; value: number; z: number }[];
  }[];
  posture: Posture;
  protocol_counts: Record<string, number>;
  meta: { packet_count: number; flow_count: number };
};
