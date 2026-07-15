"""
╔══════════════════════════════════════════════════════════════╗
║   AGENTIC AI ADAPTIVE SYSTEM GOVERNANCE                      ║
║   Zero-Day & DDoS Attack Prevention                          ║
║   DES Pune University — UNSW-NB15 Framework                  ║
╚══════════════════════════════════════════════════════════════╝

Authors: Lalit Kulkarni, Pranjal S Nalawade, Afra Inamdar, Sanket S Desai

─────────────────────────────────────────────────────────────────
 SYSTEM ARCHITECTURE (4-Layer Closed Loop)
─────────────────────────────────────────────────────────────────

 LAYER 0  ┌─────────────────────────────────────────────────┐
 Data     │ NetworkGraphBuilder  · UNSWNBSimulator          │
 Pipeline │ • Ingests raw network traffic + system logs     │
          │ • Min-max normalization, SMOTE oversampling     │
          │ • Sliding 60s temporal window                   │
          │ • Builds dynamic graph: nodes=IPs, edges=flows  │
          └──────────────────────┬──────────────────────────┘
                                 │ [N, 49] features + [N,N] adj
 LAYER 1  ┌──────────────────────▼───────────────────────────┐
 GNN      │ GraphSAGEGATHybrid                               │
 Detection│ • GraphSAGE: inductive embeddings for unseen     │
          │   nodes (no retraining on new devices)           │
          │ • GAT: attention weights neighbor by anomaly     │
          │ • MLP head: per-node anomaly scores [0,1]        │
          │ • Detects: DDoS fan-out, lateral movement paths  │
          │ • Self-adaptive threshold recalibration          │
          │ • Ref: Marfo et al. 2024 — 98% on UNSW-NB15      │
          └──────────────────────┬───────────────────────────┘
                                 │ anomaly scores + graph signals
 LAYER 2  ┌──────────────────────▼────────────────────────────┐
 DNN +    │ AttentionDNN · TemporalAnalyzer · FusionDetector  │
 Fusion   │ • AttentionDNN: 49→128→ResBlock→AttnGate          │
          │   →64→ResBlock→32→sigmoid                         │
          │ • TemporalAnalyzer (LSTM): sequential traffic     │
          │   dynamics for sustained DDoS detection           │
          │ • FusionDetector: w_gnn=0.45 + w_dnn=0.40         │
          │   + w_temporal=0.15 → joint threat assessment     │
          │ • Ref: Sharma & Sobti 2021, Berqia & Bouijij 2024 │
          └──────────────────────┬────────────────────────────┘
                                 │ ThreatEvent (structured)
 LAYER 3  ┌──────────────────────▼────────────────────────────┐
 Multi-   │  MonitoringAgent                                  │
 Agent    │  • Observes network state, temporal event history │
          │  • Classifies attack type from GNN signals        │
          │  • Emits ThreatEvent to ThreatAnalysisAgent       │
          │                                                   │
          │  ThreatAnalysisAgent (LLM semantic reasoning)     │
          │  • Pattern matching + system log correlation      │
          │  • Distinguishes genuine threats from benign      │
          │    mimics (CDN spikes, maintenance scans)         │
          │  • Generates human-readable attack narrative      │
          │  • Recommends action type                         │
          │                                                   │
          │  ResponseCoordAgent (Deep RL — Q-learning)        │
          │  • Q-table: 150 states × 10 action types          │
          │  • Pre-seeded with domain knowledge               │
          │  • Online learning from action outcomes           │
          │  • Executes: rate_limit, firewall_update,         │
          │    traffic_scrub, quarantine, block_ip_range      │
          │                                                   │
          │  GovernanceAgent                                  │
          │  • Policy enforcement (7 adaptive policies)       │
          │  • Global coherence check (no cross-vuln)         │
          │  • Preemptive adjacent node hardening             │
          │  • Self-adaptive threshold recalibration          │
          │  • Immutable append-only audit log                │
          └──────────────────────┬────────────────────────────┘
                                 │ feedback (threshold updates)
 LAYER 4  ┌──────────────────────▼──────────────────────────┐
 Human    │ SOC / Human Oversight                           │
 Oversight│ • Receives escalations for irreversible actions │
          │ • Veto authority over all autonomous decisions  |
          │ • Reviews audit log                             │
          └─────────────────────────────────────────────────┘
                    ↑ Continuous closed-loop feedback ↑

─────────────────────────────────────────────────────────────────
 FILE STRUCTURE
─────────────────────────────────────────────────────────────────

 agentic_governance/
 ├── main.py                      ← Entry point
 ├── orchestrator.py              ← AdaptiveGovernanceSystem
 ├── requirements.txt
 ├── gnn/
 │   ├── graph_sage_gat.py        ← GraphSAGEGATHybrid model
 │   └── network_graph.py         ← NetworkGraphBuilder + Simulator
 ├── detection/
 │   └── dnn_behavioral.py        ← AttentionDNN + LSTM + FusionDetector
 └── agents/
     └── multi_agent.py           ← 4 specialized agents + data structures

─────────────────────────────────────────────────────────────────
 QUICK START
─────────────────────────────────────────────────────────────────

 pip install -r requirements.txt

 # DDoS simulation
 python main.py demo ddos

 # Zero-day lateral movement simulation
 python main.py demo zeroday

 # Both attack types simultaneously
 python main.py demo combined

 # UNSW-NB15 evaluation metrics
 python main.py eval

 # Full run (demo + eval)
 python main.py full

─────────────────────────────────────────────────────────────────
 KEY MODULES
─────────────────────────────────────────────────────────────────

 GraphSAGEGATHybrid      gnn/graph_sage_gat.py
   .detect_anomalies(node_features, adj, node_ids) → Dict

 AttentionDNN            detection/dnn_behavioral.py
   .predict_batch(X) → Dict
   .fit_unsw_nb15(X, y) → training_history

 FusionDetector          detection/dnn_behavioral.py
   .fuse(gnn_score, dnn_score, temporal_score) → Dict

 MonitoringAgent         agents/multi_agent.py
   .observe(gnn_results, dnn_results, temporal, fusion) → ThreatEvent

 ThreatAnalysisAgent     agents/multi_agent.py
   .analyze(event, temporal_ctx, system_logs) → ThreatEvent

 ResponseCoordAgent      agents/multi_agent.py
   .execute(event) → List[DefensiveAction]

 GovernanceAgent         agents/multi_agent.py
   .process_actions(event, actions) → List[DefensiveAction]

─────────────────────────────────────────────────────────────────
 REFERENCES
─────────────────────────────────────────────────────────────────

 [1]  Sheth et al. — Agentic AI for Autonomous Cyber Threat Hunting (IEEE, 2025)
 [2]  Kisanga et al. — Network Anomaly Detection Using GNN (IEEE ICNC, 2023)
 [3]  Marfo et al. — Enhancing Network Anomaly Detection Using GNNs (IEEE, 2024)
 [7]  Sharma & Sobti — DNN for Intrusion Detection on UNSW-NB15 (IEEE, 2021)
 [10] Abdelkarim et al. — Enhanced DDoS Detection Using DL (IEEE, 2024)
 [13] Berqia & Bouijij — Predicting DoS/DDoS with Deep Learning (IEEE, 2024)
 [14] Rakesh et al. — NeuroShield: AI-Driven Real-Time Threat Detection (IEEE, 2024)
 [18] Halbouni et al. — ML and DL for CyberSecurity: A Review (IEEE Access, 2022)
"""

README = __doc__

if __name__ == "__main__":
    print(README)
