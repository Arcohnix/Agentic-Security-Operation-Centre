"""
Agentic AI Adaptive System Governance — Main Orchestrator
Paper: Agentic AI Based Adaptive System Governance for Zero-Day and DDoS Attack Prevention
Authors: Lalit Kulkarni, Pranjal S Nalawade, Afra Inamdar, Sanket S Desai
DES Pune University

Closed-loop architecture:
  Layer 0: Data Collection & Preprocessing     (NetworkGraphBuilder)
  Layer 1: GNN-Based Anomaly Detection         (GraphSAGEGATHybrid)
  Layer 2: DNN Behavioral Analysis             (AttentionDNN + TemporalAnalyzer)
  Layer 3: Agentic Multi-Agent Orchestration   (4 specialized agents)
  Layer 4: Adaptive Governance & Response      (GovernanceAgent + policies)
"""

import numpy as np
import time
import queue
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import asdict

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gnn.graph_sage_gat import GraphSAGEGATHybrid
from gnn.network_graph import NetworkGraphBuilder, UNSWNBSimulator, NetworkConnection
from detection.dnn_behavioral import AttentionDNN, TemporalAnalyzer, FusionDetector
from agents.multi_agent import (
    MonitoringAgent, ThreatAnalysisAgent, ResponseCoordAgent, GovernanceAgent,
    ThreatEvent, DefensiveAction, AgentMessage, ThreatLevel
)


class AdaptiveGovernanceSystem:
    """
    Top-level orchestrator for the Agentic AI Adaptive System Governance framework.

    Implements the 4-layer closed-loop described in the paper:
      Data → GNN Detection → Agentic Multi-Agent → Adaptive Governance → [Feedback loop]
    """

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        print("=" * 65)
        print("  AGENTIC AI ADAPTIVE SYSTEM GOVERNANCE")
        print("  DES Pune University — UNSW-NB15 Framework")
        print("=" * 65)

        # ── Layer 0: Data Pipeline ──────────────────────────
        print("\n[INIT] Layer 0: Data collection & preprocessing...")
        self.graph_builder = NetworkGraphBuilder(
            window_seconds=cfg.get("window_seconds", 60.0),
            max_nodes=cfg.get("max_nodes", 256),
        )
        self.simulator = UNSWNBSimulator(
            n_hosts=cfg.get("n_hosts", 20),
            rng_seed=cfg.get("seed", 42),
        )

        # ── Layer 1: GNN Detection ──────────────────────────
        print("[INIT] Layer 1: GraphSAGE-GAT hybrid GNN...")
        self.gnn = GraphSAGEGATHybrid(
            input_dim=49,
            hidden_dim=cfg.get("gnn_hidden", 64),
            embed_dim=cfg.get("gnn_embed", 32),
            n_heads=cfg.get("gnn_heads", 4),
        )

        # ── Layer 2: DNN + Temporal + Fusion ───────────────
        print("[INIT] Layer 2: Attention-DNN + LSTM temporal analyzer...")
        self.dnn = AttentionDNN(input_dim=49)
        self.temporal = TemporalAnalyzer(input_dim=8, hidden_dim=32, seq_len=10)
        self.fusion = FusionDetector(w_gnn=0.45, w_dnn=0.40, w_temporal=0.15)

        # ── Layer 3: Multi-Agent System ─────────────────────
        print("[INIT] Layer 3: Spawning 4 specialized agents...")
        self.message_bus: queue.PriorityQueue = queue.PriorityQueue()
        self.monitor = MonitoringAgent(self.message_bus)
        self.threat_analyst = ThreatAnalysisAgent(self.message_bus)
        self.responder = ResponseCoordAgent(self.message_bus)
        self.governor = GovernanceAgent(self.message_bus)

        # ── Layer 4: Adaptive Governance ────────────────────
        print("[INIT] Layer 4: Adaptive governance layer online...")

        # Performance tracking
        self.metrics = {
            "total_connections": 0,
            "total_threats_detected": 0,
            "ddos_detected": 0,
            "zeroday_detected": 0,
            "actions_taken": 0,
            "mttd_samples": [],       # Mean Time to Detect (seconds)
            "mttr_samples": [],       # Mean Time to Respond (seconds)
            "false_positives_avoided": 0,
        }

        print("\n[INIT] System ready.\n")

    # ─────────────────────────────────────────────────────────
    #  MAIN PROCESSING PIPELINE
    # ─────────────────────────────────────────────────────────

    def process_connection_batch(self, connections: List[NetworkConnection],
                                  system_logs: Optional[Dict] = None) -> Dict:
        """
        Full pipeline: ingest connections → detect → analyze → respond → govern.
        Returns a complete processing report.
        """
        t_start = time.time()
        self.metrics["total_connections"] += len(connections)

        # ── Layer 0: Ingest & build graph ─────────────────
        for conn in connections:
            self.graph_builder.ingest_connection(conn)

        node_features, adj, node_ids = self.graph_builder.build_graph()
        graph_stats = self.graph_builder.get_graph_stats()

        # ── Layer 1: GNN anomaly detection ────────────────
        gnn_results = self.gnn.detect_anomalies(node_features, adj, node_ids)

        # ── Layer 2a: DNN behavioral analysis ─────────────
        dnn_results = self.dnn.predict_batch(node_features)

        # ── Layer 2b: Temporal analysis (traffic snapshot) ─
        traffic_snapshot = self._build_traffic_snapshot(connections)
        temporal_score = self.temporal.ingest(traffic_snapshot)

        # ── Layer 2c: Score fusion ─────────────────────────
        gnn_max_score = gnn_results["max_score"]
        dnn_max_score = float(dnn_results["binary_scores"].max()) if len(
            dnn_results["binary_scores"]) > 0 else 0.0
        fusion_result = self.fusion.fuse(gnn_max_score, dnn_max_score, temporal_score)

        t_detect = time.time()
        mttd = t_detect - t_start

        # ── Layer 3: Agentic multi-agent processing ────────
        event = None
        actions = []

        if fusion_result["is_threat"]:
            self.metrics["total_threats_detected"] += 1

            # MonitoringAgent observes and emits event
            event = self.monitor.observe(gnn_results, dnn_results, temporal_score, fusion_result)

            if event:
                # Track attack types
                if event.attack_type == "DDoS":
                    self.metrics["ddos_detected"] += 1
                elif "ZeroDay" in event.attack_type or "Exploit" in event.attack_type:
                    self.metrics["zeroday_detected"] += 1

                # ThreatAnalysisAgent semantic reasoning
                temporal_ctx = self.monitor.get_temporal_context()
                event = self.threat_analyst.analyze(event, temporal_ctx, system_logs)

                # Check if benign mimic was avoided
                if event.context.get("is_benign_mimic"):
                    self.metrics["false_positives_avoided"] += 1
                else:
                    # ResponseCoordAgent executes actions
                    actions = self.responder.execute(event)
                    self.metrics["actions_taken"] += len(actions)

                    # GovernanceAgent enforces policies + global coherence
                    actions = self.governor.process_actions(event, actions)

                    # Update topology in governor
                    topology = self._extract_topology(adj, node_ids)
                    self.governor.update_topology(topology)

        t_respond = time.time()
        mttr = t_respond - t_start

        if fusion_result["is_threat"]:
            self.metrics["mttd_samples"].append(mttd)
            self.metrics["mttr_samples"].append(mttr)

        return {
            "timestamp": t_start,
            "connections_processed": len(connections),
            "graph": {
                "nodes": len(node_ids),
                "edges": int((adj > 0).sum() - len(node_ids)),  # exclude self-loops
                **graph_stats,
            },
            "gnn": {
                "max_anomaly_score": round(gnn_results["max_score"], 4),
                "mean_anomaly_score": round(gnn_results["mean_score"], 4),
                "anomalous_nodes": gnn_results["anomalous_nodes"],
                "ddos_candidates": gnn_results["ddos_candidates"],
                "lateral_movement": gnn_results["lateral_movement_candidates"],
                "threshold": round(gnn_results["threshold"], 4),
            },
            "dnn": {
                "max_score": round(dnn_max_score, 4),
                "attack_predictions": dnn_results["class_predictions"][:5],
            },
            "temporal": {"score": round(temporal_score, 4)},
            "fusion": fusion_result,
            "threat_event": self._serialize_event(event) if event else None,
            "actions": [self._serialize_action(a) for a in actions],
            "governance": self.governor.get_statistics(),
            "timing": {
                "mttd_sec": round(mttd, 4),
                "mttr_sec": round(mttr, 4),
            },
        }

    # ─────────────────────────────────────────────────────────
    #  DEMO SCENARIOS
    # ─────────────────────────────────────────────────────────

    def run_demo(self, scenario: str = "ddos"):
        """Run a canned demo scenario with printed output."""
        print(f"\n{'=' * 65}")
        print(f"  DEMO SCENARIO: {scenario.upper()}")
        print(f"{'=' * 65}")

        now = time.time()

        if scenario == "ddos":
            print("\nPhase 1/3 — Generating normal baseline traffic...")
            normal = self.simulator.generate_normal_traffic(80, base_time=now)
            r1 = self.process_connection_batch(normal)
            self._print_report(r1, "Baseline")

            print("\nPhase 2/3 — Launching DDoS attack (fan-out pattern)...")
            ddos = self.simulator.generate_ddos_traffic(200, base_time=now + 5)
            normal2 = self.simulator.generate_normal_traffic(20, base_time=now + 5)
            r2 = self.process_connection_batch(ddos + normal2)
            self._print_report(r2, "DDoS Active")

            print("\nPhase 3/3 — Governance response active, traffic scrubbed...")
            residual = self.simulator.generate_normal_traffic(30, base_time=now + 15)
            r3 = self.process_connection_batch(residual)
            self._print_report(r3, "Post-Mitigation")

        elif scenario == "zeroday":
            print("\nPhase 1/3 — Normal baseline...")
            normal = self.simulator.generate_normal_traffic(60, base_time=now)
            r1 = self.process_connection_batch(normal)
            self._print_report(r1, "Baseline")

            print("\nPhase 2/3 — Zero-day lateral movement injected...")
            lateral = self.simulator.generate_zeroday_lateral(base_time=now + 8)
            mixed = self.simulator.generate_normal_traffic(30, base_time=now + 8)
            r2 = self.process_connection_batch(lateral + mixed)
            self._print_report(r2, "Zero-Day Active")

            print("\nPhase 3/3 — Hosts quarantined, adjacent nodes hardened...")
            recovery = self.simulator.generate_normal_traffic(20, base_time=now + 60)
            r3 = self.process_connection_batch(recovery)
            self._print_report(r3, "Contained")

        elif scenario == "combined":
            print("\nRunning combined DDoS + Zero-Day scenario...")
            normal = self.simulator.generate_normal_traffic(50, base_time=now)
            ddos = self.simulator.generate_ddos_traffic(150, base_time=now + 3)
            lateral = self.simulator.generate_zeroday_lateral(base_time=now + 3)
            r = self.process_connection_batch(normal + ddos + lateral)
            self._print_report(r, "Combined Attack")

        print("\n" + "=" * 65)
        print("  FINAL SYSTEM METRICS")
        print("=" * 65)
        self._print_final_metrics()

    def _print_report(self, report: Dict, label: str):
        print(f"\n  ── {label} ──")
        g = report["gnn"]
        f = report["fusion"]
        print(f"  Connections: {report['connections_processed']:4d} | "
              f"Nodes: {report['graph']['nodes']:3d}")
        print(f"  GNN max anomaly: {g['max_anomaly_score']:.3f} | "
              f"DDoS candidates: {len(g['ddos_candidates'])} | "
              f"Lateral: {len(g['lateral_movement'])}")
        print(f"  Fusion score:    {f['fused_score']:.3f} | "
              f"Severity: {f['severity']:8s} | "
              f"Threat: {f['is_threat']}")
        if report["threat_event"]:
            ev = report["threat_event"]
            print(f"  Threat event:    {ev['event_id']} | {ev['attack_type']} | "
                  f"Level: {ev['threat_level']}")
        if report["actions"]:
            print(f"  Actions taken:   {len(report['actions'])}")
            for a in report["actions"][:3]:
                print(f"    [{a['action_type']:20s}] target={a['target']:16s} "
                      f"autonomous={a['autonomous']}")
        print(f"  MTTD: {report['timing']['mttd_sec']:.4f}s | "
              f"MTTR: {report['timing']['mttr_sec']:.4f}s")

    def _print_final_metrics(self):
        m = self.metrics
        g = self.governor.get_statistics()
        print(f"  Total connections:        {m['total_connections']}")
        print(f"  Total threats detected:   {m['total_threats_detected']}")
        print(f"  DDoS events:              {m['ddos_detected']}")
        print(f"  Zero-day events:          {m['zeroday_detected']}")
        print(f"  Actions taken:            {m['actions_taken']}")
        print(f"  Autonomous actions:       {g['autonomous_actions']}")
        print(f"  Human escalations:        {g['human_escalations']}")
        print(f"  Benign mimics avoided:    {m['false_positives_avoided']}")
        print(f"  Hardened nodes:           {g['hardened_nodes']}")
        print(f"  Audit log entries:        {g['audit_entries']}")
        if m["mttd_samples"]:
            print(f"  Mean MTTD:                {np.mean(m['mttd_samples']):.4f}s")
            print(f"  Mean MTTR:                {np.mean(m['mttr_samples']):.4f}s")
        print(f"  Global threat level:      {g['global_threat_level']}")
        print(f"\n  Active policies:")
        for name, enabled in self.governor.get_policy_status().items():
            status = "ON " if enabled else "OFF"
            print(f"    [{status}] {name}")

    # ─────────────────────────────────────────────────────────
    #  EVALUATION (UNSW-NB15)
    # ─────────────────────────────────────────────────────────

    def evaluate_unsw_nb15(self, n_samples: int = 500) -> Dict:
        """
        Simulate UNSW-NB15 evaluation with mixed attack/normal traffic.
        Returns precision, recall, F1, accuracy metrics.
        """
        print(f"\n[EVAL] Running UNSW-NB15 evaluation on {n_samples} samples...")
        rng = np.random.RandomState(0)

        now = time.time()
        true_labels = []
        fused_scores = []

        # Generate balanced dataset
        n_normal = n_samples // 2
        n_attack = n_samples - n_normal

        normal_conns = self.simulator.generate_normal_traffic(n_normal, base_time=now)
        ddos_conns = self.simulator.generate_ddos_traffic(n_attack // 2, base_time=now + 100)
        lateral_conns = self.simulator.generate_zeroday_lateral(base_time=now + 200)

        # Process in batches
        batch_size = 50
        all_conns = normal_conns + ddos_conns + lateral_conns
        all_labels = ([0] * n_normal + [1] * (n_attack // 2) +
                      [1] * len(lateral_conns))

        for i in range(0, len(all_conns), batch_size):
            batch = all_conns[i:i + batch_size]
            batch_labels = all_labels[i:i + batch_size]
            for conn in batch:
                self.graph_builder.ingest_connection(conn)
            nf, adj, nids = self.graph_builder.build_graph()
            gnn_r = self.gnn.detect_anomalies(nf, adj, nids)
            dnn_r = self.dnn.predict_batch(nf)
            snap = self._build_traffic_snapshot(batch)
            ts = self.temporal.ingest(snap)
            gnn_score = gnn_r["max_score"]
            dnn_score = float(dnn_r["binary_scores"].max()) if len(dnn_r["binary_scores"]) else 0.0
            fr = self.fusion.fuse(gnn_score, dnn_score, ts)
            for _ in batch_labels:
                fused_scores.append(fr["fused_score"])
                true_labels.append(1 if any(b.label == 1 for b in batch) else 0)

        true_labels = np.array(true_labels[:len(fused_scores)])
        fused_scores = np.array(fused_scores)
        metrics = self.fusion.evaluate(true_labels, fused_scores)

        print(f"\n  [EVAL RESULTS — UNSW-NB15 Simulation]")
        print(f"  Accuracy:    {metrics['accuracy']:.4f}  (paper ref: ~0.98)")
        print(f"  Precision:   {metrics['precision']:.4f}")
        print(f"  Recall:      {metrics['recall']:.4f}")
        print(f"  F1-Score:    {metrics['f1_score']:.4f}  (paper ref: ~0.97)")
        print(f"  FP Rate:     {metrics['false_positive_rate']:.4f}")
        print(f"  TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
        return metrics

    # ─────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────

    def _build_traffic_snapshot(self, connections: List[NetworkConnection]) -> Dict:
        if not connections:
            return {}
        total_dur = sum(c.duration for c in connections)
        n = len(connections)
        flags = [c.tcp_flags for c in connections]
        syn_ratio = sum(1 for f in flags if f & 0b00000010) / max(1, n)
        fin_ratio = sum(1 for f in flags if f & 0b00000001) / max(1, n)
        rst_ratio = sum(1 for f in flags if f & 0b00000100) / max(1, n)
        unique_srcs = len(set(c.src_ip for c in connections))
        unique_dsts = len(set(c.dst_ip for c in connections))
        return {
            "requests_per_sec": n / max(0.001, total_dur / n),
            "unique_srcs": unique_srcs,
            "unique_dsts": unique_dsts,
            "mean_pkt_size": np.mean([c.src_bytes + c.dst_bytes for c in connections]),
            "syn_ratio": syn_ratio,
            "fin_ratio": fin_ratio,
            "rst_ratio": rst_ratio,
            "duration_mean": total_dur / n,
        }

    def _extract_topology(self, adj: np.ndarray, node_ids: List[str]) -> Dict[str, List[str]]:
        topology = {}
        for i, src in enumerate(node_ids):
            neighbors = [node_ids[j] for j in range(len(node_ids)) if adj[i, j] > 0 and i != j]
            topology[src] = neighbors
        return topology

    def _serialize_event(self, event: Optional[ThreatEvent]) -> Optional[Dict]:
        if event is None:
            return None
        return {
            "event_id": event.event_id,
            "attack_type": event.attack_type,
            "threat_level": event.threat_level.name,
            "fused_score": round(event.fused_score, 4),
            "source_ip": event.source_ip,
            "anomalous_nodes": event.anomalous_nodes[:5],
            "narrative": event.narrative,
            "recommended_action": event.recommended_action.value if event.recommended_action else None,
        }

    def _serialize_action(self, action: DefensiveAction) -> Dict:
        return {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "autonomous": action.autonomous,
            "severity": action.severity,
        }
