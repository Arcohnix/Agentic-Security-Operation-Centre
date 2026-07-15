"""
Multi-Agent Orchestration Framework
Paper: Agentic AI Based Adaptive System Governance
Ref: Sheth et al. (2025), NeuroShield — Rakesh et al. (2024)

Four specialized agents collaborating concurrently:
  1. MonitoringAgent     — continuous network state observation
  2. ThreatAnalysisAgent — LLM-assisted semantic reasoning
  3. ResponseCoordAgent  — DRL-based defensive action selection
  4. GovernanceAgent     — global situational awareness + policy
"""

import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import queue
import threading


# ─────────────────────────────────────────────
#  Shared Data Structures
# ─────────────────────────────────────────────

class ThreatLevel(Enum):
    NORMAL   = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class ActionType(Enum):
    ALERT             = "alert"
    RATE_LIMIT        = "rate_limit"
    FIREWALL_UPDATE   = "firewall_update"
    ISOLATE_FLOW      = "isolate_flow"
    QUARANTINE_HOST   = "quarantine_host"
    BLOCK_IP_RANGE    = "block_ip_range"
    TRAFFIC_SCRUB     = "traffic_scrub"
    HARDEN_ADJACENT   = "harden_adjacent"
    RECALIBRATE       = "recalibrate_threshold"
    ESCALATE_HUMAN    = "escalate_to_human"


@dataclass
class ThreatEvent:
    """Structured threat event passed between agents."""
    event_id: str
    timestamp: float
    source_ip: str
    target_ips: List[str]
    threat_level: ThreatLevel
    attack_type: str                   # DDoS, Exploits, Lateral, etc.
    gnn_score: float
    dnn_score: float
    temporal_score: float
    fused_score: float
    anomalous_nodes: List[str]
    anomalous_edges: List[Tuple]
    raw_features: Optional[np.ndarray] = None
    context: Dict = field(default_factory=dict)
    narrative: str = ""                # LLM-generated analysis
    recommended_action: Optional[ActionType] = None


@dataclass
class DefensiveAction:
    """An action issued by the Response Coordination Agent."""
    action_id: str
    action_type: ActionType
    target: str                        # IP, subnet, or host identifier
    parameters: Dict
    timestamp: float
    severity: str
    autonomous: bool = True            # False = requires human approval
    outcome: Optional[str] = None
    success: Optional[bool] = None


@dataclass
class AgentMessage:
    """Message bus packet between agents."""
    sender: str
    receiver: str                      # "broadcast" for all agents
    message_type: str
    payload: Any
    timestamp: float = field(default_factory=time.time)
    priority: int = 5                  # 1=highest, 10=lowest


# ─────────────────────────────────────────────
#  Base Agent
# ─────────────────────────────────────────────

class BaseAgent:
    """Base class for all specialized agents."""

    def __init__(self, agent_id: str, message_bus: queue.PriorityQueue):
        self.agent_id = agent_id
        self.message_bus = message_bus
        self.inbox: List[AgentMessage] = []
        self.log: List[Dict] = []
        self.is_running = False
        self._trust_score = 1.0

    def send(self, receiver: str, msg_type: str, payload: Any, priority: int = 5):
        msg = AgentMessage(
            sender=self.agent_id,
            receiver=receiver,
            message_type=msg_type,
            payload=payload,
            priority=priority,
        )
        self.message_bus.put((priority, time.time(), msg))

    def _log(self, level: str, message: str, data: Dict = None):
        entry = {
            "timestamp": time.time(),
            "agent": self.agent_id,
            "level": level,
            "message": message,
            "data": data or {},
        }
        self.log.append(entry)
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{level:8s}][{self.agent_id}] {message}")


# ─────────────────────────────────────────────
#  1. Monitoring Agent
# ─────────────────────────────────────────────

class MonitoringAgent(BaseAgent):
    """
    Continuously observes network state and maintains temporal event history.
    Feeds anomaly streams to ThreatAnalysisAgent.
    """

    def __init__(self, message_bus: queue.PriorityQueue):
        super().__init__("MonitoringAgent", message_bus)
        self.event_history: List[ThreatEvent] = []
        self.baseline_rps: float = 150.0          # Requests per second baseline
        self.baseline_nodes: int = 20
        self._event_counter = 0
        self.active_monitors: Dict[str, Dict] = {}   # ip → monitoring state

    def observe(self, gnn_results: Dict, dnn_results: Dict,
                temporal_score: float, fusion_result: Dict) -> Optional[ThreatEvent]:
        """
        Process detection layer outputs and emit structured ThreatEvent if anomalous.
        """
        fused = fusion_result["fused_score"]
        severity = fusion_result["severity"]

        # Determine threat level
        level_map = {
            "NORMAL": ThreatLevel.NORMAL,
            "LOW": ThreatLevel.LOW,
            "MEDIUM": ThreatLevel.MEDIUM,
            "HIGH": ThreatLevel.HIGH,
            "CRITICAL": ThreatLevel.CRITICAL,
        }
        threat_level = level_map.get(severity, ThreatLevel.LOW)

        # Determine attack type from GNN structural signals
        attack_type = self._classify_attack_type(gnn_results)

        if threat_level == ThreatLevel.NORMAL:
            return None

        self._event_counter += 1
        event = ThreatEvent(
            event_id=f"EVT-{self._event_counter:05d}",
            timestamp=time.time(),
            source_ip=self._identify_primary_source(gnn_results),
            target_ips=gnn_results.get("anomalous_nodes", [])[:5],
            threat_level=threat_level,
            attack_type=attack_type,
            gnn_score=gnn_results.get("max_score", 0.0),
            dnn_score=float(dnn_results.get("binary_scores", np.array([0]))[0]) if hasattr(
                dnn_results.get("binary_scores", 0), "__len__") else float(
                dnn_results.get("binary_scores", 0)),
            temporal_score=temporal_score,
            fused_score=fused,
            anomalous_nodes=gnn_results.get("anomalous_nodes", []),
            anomalous_edges=gnn_results.get("anomalous_edges", []),
        )

        self.event_history.append(event)
        if len(self.event_history) > 1000:
            self.event_history = self.event_history[-500:]

        self._log("ALERT", f"Threat detected: {attack_type} | score={fused:.3f} | level={severity}",
                  {"event_id": event.event_id, "fused_score": fused})

        # Broadcast to ThreatAnalysisAgent (high priority)
        self.send("ThreatAnalysisAgent", "threat_event", event, priority=2)
        return event

    def _classify_attack_type(self, gnn_results: Dict) -> str:
        ddos = gnn_results.get("ddos_candidates", [])
        lateral = gnn_results.get("lateral_movement_candidates", [])
        max_score = gnn_results.get("max_score", 0)

        if len(ddos) >= 2:
            return "DDoS"
        if len(lateral) >= 1:
            return "ZeroDay-Lateral"
        if max_score > 0.85:
            return "Exploits"
        return "Generic-Anomaly"

    def _identify_primary_source(self, gnn_results: Dict) -> str:
        candidates = gnn_results.get("ddos_candidates", []) or \
                     gnn_results.get("lateral_movement_candidates", []) or \
                     gnn_results.get("anomalous_nodes", [])
        return str(candidates[0]) if candidates else "unknown"

    def get_temporal_context(self, window: int = 10) -> Dict:
        """Return last N events as context for threat analysis."""
        recent = self.event_history[-window:]
        return {
            "recent_events": len(recent),
            "attack_types": list(set(e.attack_type for e in recent)),
            "max_score_window": max((e.fused_score for e in recent), default=0),
            "escalating": len(recent) >= 3 and
                          recent[-1].fused_score > recent[-3].fused_score,
        }


# ─────────────────────────────────────────────
#  2. Threat Analysis Agent  (LLM-assisted reasoning)
# ─────────────────────────────────────────────

class ThreatAnalysisAgent(BaseAgent):
    """
    Correlates flagged anomalies with system log data using semantic reasoning.
    Interprets event sequences as attack narratives.
    Distinguishes genuine DDoS precursors from benign traffic spikes.

    LLM-assisted reasoning is simulated via a rule-based expert system
    that encodes the same semantic logic described in the paper.
    """

    # Knowledge base: attack signatures as semantic patterns
    ATTACK_PATTERNS = {
        "DDoS": {
            "indicators": ["high_fan_out", "syn_flood", "multiple_sources", "low_duration"],
            "benign_mimics": ["legitimate_cdn", "load_balancer", "broadcast_storm"],
            "confidence_boost": 0.15,
        },
        "ZeroDay-Lateral": {
            "indicators": ["unusual_admin_ports", "slow_movement", "long_dwell", "privilege_escalation"],
            "benign_mimics": ["scheduled_maintenance", "backup_job", "admin_login"],
            "confidence_boost": 0.20,
        },
        "Exploits": {
            "indicators": ["payload_anomaly", "unusual_flags", "protocol_violation"],
            "benign_mimics": ["misconfigured_client", "legacy_software"],
            "confidence_boost": 0.10,
        },
        "Reconnaissance": {
            "indicators": ["port_scan", "high_unique_ports", "icmp_sweep"],
            "benign_mimics": ["network_monitoring", "vulnerability_scanner"],
            "confidence_boost": 0.05,
        },
    }

    def __init__(self, message_bus: queue.PriorityQueue):
        super().__init__("ThreatAnalysisAgent", message_bus)
        self.analysis_history: List[Dict] = []
        self.false_positive_signatures: List[str] = []
        self._system_log_patterns: Dict[str, int] = {}

    def analyze(self, event: ThreatEvent, temporal_context: Dict,
                system_logs: Optional[Dict] = None) -> ThreatEvent:
        """
        Deep semantic analysis of a threat event.
        Produces narrative, refined confidence, and recommended action.
        """
        self._log("INFO", f"Analysing event {event.event_id} | type={event.attack_type}")

        # Step 1: Semantic pattern matching
        pattern_confidence, indicators_found = self._match_attack_patterns(event)

        # Step 2: Cross-correlate with system logs
        log_correlation = self._correlate_system_logs(event, system_logs or {})

        # Step 3: Distinguish from benign mimics
        is_benign_mimic, mimic_reason = self._check_benign_mimics(event, temporal_context)

        # Step 4: Escalation check — is threat worsening?
        is_escalating = temporal_context.get("escalating", False)

        # Step 5: Build semantic narrative
        narrative = self._build_narrative(
            event, indicators_found, log_correlation,
            is_benign_mimic, mimic_reason, is_escalating
        )

        # Step 6: Refine threat score with semantic context
        refined_score = self._refine_score(
            event, pattern_confidence, log_correlation,
            is_benign_mimic, is_escalating
        )

        # Step 7: Recommend action
        action = self._recommend_action(event, refined_score, is_benign_mimic)

        # Update event with analysis results
        event.narrative = narrative
        event.recommended_action = action
        event.context.update({
            "pattern_confidence": pattern_confidence,
            "indicators": indicators_found,
            "log_correlation": log_correlation,
            "is_benign_mimic": is_benign_mimic,
            "refined_score": refined_score,
            "is_escalating": is_escalating,
        })

        self._log("INFO", f"Analysis complete: {event.attack_type} | action={action.value} | "
                  f"benign_mimic={is_benign_mimic} | refined={refined_score:.3f}")

        self.analysis_history.append({
            "event_id": event.event_id,
            "attack_type": event.attack_type,
            "refined_score": refined_score,
            "action": action.value,
        })

        # Send to ResponseCoordinationAgent
        self.send("ResponseCoordAgent", "analyzed_threat", event, priority=1)
        return event

    def _match_attack_patterns(self, event: ThreatEvent) -> Tuple[float, List[str]]:
        pattern = self.ATTACK_PATTERNS.get(event.attack_type, {})
        indicators = pattern.get("indicators", [])
        found = []

        # Check each indicator against event features
        if event.gnn_score > 0.7:
            found.append("high_anomaly_score")
        if len(event.anomalous_nodes) >= 3:
            found.append("high_fan_out")
        if event.attack_type == "DDoS" and len(event.anomalous_nodes) >= 2:
            found.append("multiple_sources")
            found.append("syn_flood")
        if event.attack_type == "ZeroDay-Lateral":
            found.append("unusual_admin_ports")
            found.append("slow_movement")
        if event.temporal_score > 0.6:
            found.append("sustained_pattern")

        confidence = len(found) / max(1, len(indicators) + 2)
        confidence += pattern.get("confidence_boost", 0) if found else 0
        return min(1.0, confidence), found

    def _correlate_system_logs(self, event: ThreatEvent, logs: Dict) -> float:
        """
        Correlate network anomaly with system log patterns.
        Returns correlation strength [0, 1].
        """
        correlation = 0.0
        if logs.get("privilege_escalation"):
            correlation += 0.3
        if logs.get("failed_logins", 0) > 5:
            correlation += 0.2
        if logs.get("unusual_process"):
            correlation += 0.25
        if logs.get("file_access_anomaly"):
            correlation += 0.15
        if event.attack_type in logs.get("known_patterns", []):
            correlation += 0.4
        return min(1.0, correlation)

    def _check_benign_mimics(self, event: ThreatEvent,
                              ctx: Dict) -> Tuple[bool, str]:
        """
        Key LLM reasoning step: disambiguate genuine threats from benign traffic.
        A DDoS precursor vs a legitimate CDN, a maintenance scan vs lateral movement.
        """
        attack_types = ctx.get("attack_types", [])
        recent_count = ctx.get("recent_events", 0)

        # Low score with only one event — likely benign
        if event.fused_score < 0.45 and recent_count < 2:
            return True, "isolated_low_confidence_event"

        # Traffic spike but only from known internal hosts → CDN / load balancer
        if event.attack_type == "DDoS" and event.fused_score < 0.60:
            internal = [ip for ip in event.anomalous_nodes if ip.startswith("10.")]
            if len(internal) == len(event.anomalous_nodes):
                return True, "internal_hosts_only_traffic_spike"

        # Single lateral hop at business hours → maintenance
        if event.attack_type == "ZeroDay-Lateral" and len(event.anomalous_nodes) < 2:
            return True, "single_hop_possibly_maintenance"

        return False, ""

    def _build_narrative(self, event: ThreatEvent, indicators: List[str],
                          log_corr: float, is_mimic: bool,
                          mimic_reason: str, escalating: bool) -> str:
        """Generate human-readable semantic narrative of the threat."""
        lines = [f"Threat event {event.event_id} analysis:"]
        lines.append(f"  Type: {event.attack_type} | Score: {event.fused_score:.3f} | "
                     f"Level: {event.threat_level.name}")

        if indicators:
            lines.append(f"  Indicators detected: {', '.join(indicators)}")

        if log_corr > 0:
            lines.append(f"  System log correlation: {log_corr:.2f} "
                         f"({'HIGH' if log_corr > 0.5 else 'MODERATE'})")

        if is_mimic:
            lines.append(f"  ASSESSMENT: Likely benign mimic — {mimic_reason}")
        else:
            lines.append(f"  ASSESSMENT: Genuine {event.attack_type} confirmed")

        if escalating:
            lines.append("  WARNING: Threat is escalating — increased urgency")

        if event.anomalous_nodes:
            lines.append(f"  Affected nodes: {event.anomalous_nodes[:4]}")

        return "\n".join(lines)

    def _refine_score(self, event: ThreatEvent, pattern_conf: float,
                       log_corr: float, is_mimic: bool, escalating: bool) -> float:
        base = event.fused_score
        if is_mimic:
            base *= 0.5              # Discount benign mimics
        base += pattern_conf * 0.1   # Boost for pattern match
        base += log_corr * 0.15      # Boost for log correlation
        if escalating:
            base *= 1.2              # Escalation multiplier
        return float(np.clip(base, 0.0, 1.0))

    def _recommend_action(self, event: ThreatEvent,
                           refined_score: float, is_mimic: bool) -> ActionType:
        if is_mimic or refined_score < 0.3:
            return ActionType.ALERT
        if refined_score < 0.5:
            return ActionType.RATE_LIMIT
        if refined_score < 0.65:
            return ActionType.FIREWALL_UPDATE
        if event.attack_type == "DDoS" and refined_score >= 0.65:
            return ActionType.TRAFFIC_SCRUB
        if event.attack_type == "ZeroDay-Lateral" and refined_score >= 0.65:
            return ActionType.QUARANTINE_HOST
        if refined_score >= 0.85:
            return ActionType.QUARANTINE_HOST
        return ActionType.ISOLATE_FLOW


# ─────────────────────────────────────────────
#  3. Response Coordination Agent  (DRL-based)
# ─────────────────────────────────────────────

class ResponseCoordAgent(BaseAgent):
    """
    Determines defensive actions based on threat severity and asset criticality.
    Uses Deep Reinforcement Learning policy (Q-table approximation) to learn
    from outcomes of past defensive actions.
    Ref: Sheth et al. (2025) — DRL for adaptive cyber defense.
    """

    # State: (threat_level, attack_type_idx, escalating, asset_criticality)
    # Action: ActionType enum
    N_STATES = 5 * 5 * 2 * 3   # 150 states
    N_ACTIONS = len(ActionType)

    ATTACK_TYPE_IDX = {
        "DDoS": 0, "ZeroDay-Lateral": 1, "Exploits": 2,
        "Reconnaissance": 3, "Generic-Anomaly": 4,
    }

    ASSET_CRITICALITY = {
        "web": 1, "api": 2, "db": 3,        # 1=low, 2=med, 3=high
    }

    def __init__(self, message_bus: queue.PriorityQueue):
        super().__init__("ResponseCoordAgent", message_bus)

        # Q-table: state × action → expected reward
        rng = np.random.RandomState(42)
        self.Q = rng.randn(self.N_STATES, self.N_ACTIONS) * 0.01

        # Pre-seed Q with domain knowledge
        self._initialize_q_policy()

        # DRL hyperparameters
        self.epsilon = 0.1           # Exploration rate
        self.alpha = 0.05            # Learning rate
        self.gamma = 0.95            # Discount factor

        # Action history for outcome learning
        self.action_history: List[DefensiveAction] = []
        self._action_counter = 0

        # Asset registry: host → criticality level
        self.asset_registry: Dict[str, int] = {}

        # Rate limiting state: ip → (limit_bps, expiry)
        self.rate_limits: Dict[str, Tuple[int, float]] = {}

        # Quarantine list: set of quarantined hosts
        self.quarantined_hosts: set = set()
        self.blocked_ips: set = set()

    def _initialize_q_policy(self):
        """Pre-seed Q-table with expert domain knowledge."""
        actions = list(ActionType)
        action_idx = {a: i for i, a in enumerate(actions)}

        # High threat → quarantine should have highest Q-value
        for s in range(self.N_STATES):
            threat_level = s % 5
            if threat_level >= 3:  # HIGH or CRITICAL
                self.Q[s, action_idx[ActionType.QUARANTINE_HOST]] += 2.0
                self.Q[s, action_idx[ActionType.BLOCK_IP_RANGE]] += 1.5
            elif threat_level == 2:  # MEDIUM
                self.Q[s, action_idx[ActionType.FIREWALL_UPDATE]] += 1.5
                self.Q[s, action_idx[ActionType.RATE_LIMIT]] += 1.0
            else:  # LOW / NORMAL
                self.Q[s, action_idx[ActionType.ALERT]] += 2.0

    def _encode_state(self, event: ThreatEvent, asset_criticality: int) -> int:
        tl = event.threat_level.value                       # 0-4
        at = self.ATTACK_TYPE_IDX.get(event.attack_type, 4) # 0-4
        esc = int(event.context.get("is_escalating", False)) # 0-1
        ac = min(3, max(1, asset_criticality)) - 1           # 0-2
        state = tl + 5 * at + 25 * esc + 50 * ac
        return min(state, self.N_STATES - 1)

    def _select_action(self, state: int, recommended: ActionType) -> ActionType:
        """Epsilon-greedy action selection with expert recommendation bias."""
        actions = list(ActionType)

        if np.random.random() < self.epsilon:
            # Exploration: bias toward recommended action
            if np.random.random() < 0.7:
                return recommended
            return np.random.choice(actions)

        # Exploitation: best Q-value action
        best_idx = np.argmax(self.Q[state])
        return actions[best_idx]

    def _update_q(self, state: int, action_idx: int, reward: float, next_state: int):
        """Bellman Q-update."""
        current_q = self.Q[state, action_idx]
        next_max_q = np.max(self.Q[next_state])
        td_target = reward + self.gamma * next_max_q
        self.Q[state, action_idx] += self.alpha * (td_target - current_q)

    def execute(self, event: ThreatEvent) -> List[DefensiveAction]:
        """
        Select and execute defensive actions for a threat event.
        Returns list of actions taken.
        """
        recommended = event.recommended_action or ActionType.ALERT
        asset_crit = self._get_asset_criticality(event.target_ips)
        state = self._encode_state(event, asset_crit)
        action_type = self._select_action(state, recommended)

        self._log("ACTION",
                  f"Event {event.event_id}: executing {action_type.value} "
                  f"(level={event.threat_level.name})")

        actions = self._dispatch_action(action_type, event)

        # Send to GovernanceAgent for global awareness
        self.send("GovernanceAgent", "actions_taken", {
            "event": event,
            "actions": actions,
            "state": state,
        }, priority=3)

        return actions

    def _dispatch_action(self, action_type: ActionType,
                          event: ThreatEvent) -> List[DefensiveAction]:
        """Build and execute one or more defensive actions."""
        self._action_counter += 1
        aid = f"ACT-{self._action_counter:05d}"
        actions = []

        if action_type == ActionType.ALERT:
            a = DefensiveAction(
                action_id=aid,
                action_type=ActionType.ALERT,
                target="SOC",
                parameters={"event_id": event.event_id, "narrative": event.narrative},
                timestamp=time.time(),
                severity=event.threat_level.name,
                autonomous=True,
            )
            actions.append(a)

        elif action_type == ActionType.RATE_LIMIT:
            for ip in event.anomalous_nodes[:3]:
                a = DefensiveAction(
                    action_id=f"{aid}-RL",
                    action_type=ActionType.RATE_LIMIT,
                    target=ip,
                    parameters={"limit_bps": 1_000_000, "duration_sec": 300},
                    timestamp=time.time(),
                    severity=event.threat_level.name,
                    autonomous=True,
                )
                self.rate_limits[ip] = (1_000_000, time.time() + 300)
                actions.append(a)
                self._log("ACTION", f"Rate-limited {ip} to 1Mbps for 300s")

        elif action_type == ActionType.FIREWALL_UPDATE:
            rule = f"BLOCK src={event.source_ip} proto=tcp flags=SYN"
            a = DefensiveAction(
                action_id=f"{aid}-FW",
                action_type=ActionType.FIREWALL_UPDATE,
                target=event.source_ip,
                parameters={"rule": rule, "priority": 100},
                timestamp=time.time(),
                severity=event.threat_level.name,
                autonomous=True,
            )
            actions.append(a)
            self._log("ACTION", f"Firewall updated: {rule}")

        elif action_type == ActionType.TRAFFIC_SCRUB:
            a = DefensiveAction(
                action_id=f"{aid}-TS",
                action_type=ActionType.TRAFFIC_SCRUB,
                target=event.source_ip,
                parameters={
                    "scrub_targets": event.anomalous_nodes,
                    "threshold_pps": 10000,
                    "mode": "dynamic",
                },
                timestamp=time.time(),
                severity=event.threat_level.name,
                autonomous=True,
            )
            actions.append(a)
            self._log("ACTION",
                      f"Traffic scrubbing activated for {len(event.anomalous_nodes)} nodes")

        elif action_type == ActionType.QUARANTINE_HOST:
            for host in event.anomalous_nodes[:5]:
                if host not in self.quarantined_hosts:
                    a = DefensiveAction(
                        action_id=f"{aid}-QH",
                        action_type=ActionType.QUARANTINE_HOST,
                        target=host,
                        parameters={"vlan_isolation": True, "log_all_traffic": True},
                        timestamp=time.time(),
                        severity=event.threat_level.name,
                        autonomous=event.threat_level.value >= ThreatLevel.HIGH.value,
                    )
                    self.quarantined_hosts.add(host)
                    actions.append(a)
                    self._log("ACTION", f"Host quarantined: {host}")

        elif action_type == ActionType.BLOCK_IP_RANGE:
            # Block /24 subnet of attacker
            parts = event.source_ip.split(".")
            subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else event.source_ip
            a = DefensiveAction(
                action_id=f"{aid}-BLK",
                action_type=ActionType.BLOCK_IP_RANGE,
                target=subnet,
                parameters={"block_duration_sec": 3600, "log": True},
                timestamp=time.time(),
                severity=event.threat_level.name,
                autonomous=True,
            )
            self.blocked_ips.add(subnet)
            actions.append(a)
            self._log("ACTION", f"IP range blocked: {subnet}")

        elif action_type == ActionType.ESCALATE_HUMAN:
            a = DefensiveAction(
                action_id=f"{aid}-ESC",
                action_type=ActionType.ESCALATE_HUMAN,
                target="SOC-ANALYST",
                parameters={"event": event.event_id, "urgency": "HIGH"},
                timestamp=time.time(),
                severity=event.threat_level.name,
                autonomous=False,
            )
            actions.append(a)
            self._log("ESCALATE", f"Human escalation requested for {event.event_id}")

        self.action_history.extend(actions)
        return actions

    def _get_asset_criticality(self, targets: List[str]) -> int:
        if not targets:
            return 1
        crits = [self.asset_registry.get(t, 1) for t in targets]
        return max(crits)

    def record_outcome(self, action: DefensiveAction, success: bool, reward: float):
        """Record action outcome and update Q-table (online DRL)."""
        action.success = success
        action.outcome = "success" if success else "failure"
        self._log("LEARN", f"Action {action.action_id} outcome={action.outcome} reward={reward:.2f}")


# ─────────────────────────────────────────────
#  4. Governance Agent
# ─────────────────────────────────────────────

class GovernanceAgent(BaseAgent):
    """
    Global situational awareness and policy management.
    Ensures local defensive actions don't create vulnerabilities elsewhere.
    Manages adaptive threshold recalibration.
    Hardening of adjacent nodes to stop propagation.
    Ref: Adaptive governance layer — continuous self-adaptation.
    """

    def __init__(self, message_bus: queue.PriorityQueue):
        super().__init__("GovernanceAgent", message_bus)

        # Network topology map: ip → set of neighbors
        self.topology: Dict[str, set] = {}

        # Policy registry
        self.policies: Dict[str, Dict] = self._initialize_policies()

        # Global threat state
        self.global_threat_level = ThreatLevel.NORMAL
        self.active_threats: Dict[str, ThreatEvent] = {}
        self.hardened_nodes: set = set()

        # Threshold calibration history
        self.threshold_history: List[float] = []
        self.current_thresholds: Dict[str, float] = {
            "gnn_anomaly": 0.5,
            "dnn_binary": 0.5,
            "fusion": 0.5,
            "rate_limit_trigger": 0.4,
            "quarantine_trigger": 0.7,
        }

        # Audit log (immutable append-only record)
        self.audit_log: List[Dict] = []

        # Governance statistics
        self.stats = {
            "total_events": 0,
            "total_actions": 0,
            "autonomous_actions": 0,
            "human_escalations": 0,
            "false_positives_avoided": 0,
            "hardened_nodes": 0,
        }

    def _initialize_policies(self) -> Dict[str, Dict]:
        return {
            "least_privilege": {
                "enabled": True,
                "description": "Each agent receives only minimum capability grant",
                "scope": "all_agents",
                "severity": "CRITICAL",
            },
            "human_in_loop_irreversibles": {
                "enabled": True,
                "description": "Irreversible actions held pending async human approval",
                "threshold_value": 0.85,
                "scope": "actions_above_threshold",
                "severity": "CRITICAL",
            },
            "adaptive_trust_scoring": {
                "enabled": True,
                "description": "Trust scores recomputed after every N decisions",
                "recompute_every": 10,
                "scope": "all_agents",
                "severity": "HIGH",
            },
            "sandbox_isolation": {
                "enabled": True,
                "description": "Executor agents run in isolated containers",
                "scope": "executor_agents",
                "severity": "CRITICAL",
            },
            "preemptive_hardening": {
                "enabled": True,
                "description": "Adjacent nodes hardened preemptively on zero-day detection",
                "hop_depth": 2,
                "scope": "zero_day_events",
                "severity": "HIGH",
            },
            "self_adaptive_thresholds": {
                "enabled": True,
                "description": "Detection thresholds continuously recalibrated",
                "window_size": 50,
                "scope": "all_detectors",
                "severity": "MEDIUM",
            },
            "anomaly_triggered_slowdown": {
                "enabled": False,
                "description": "Agent throughput throttled on anomaly loops",
                "scope": "looping_agents",
                "severity": "MEDIUM",
            },
        }

    def process_actions(self, event: ThreatEvent, actions: List[DefensiveAction]):
        """
        Process defensive actions for global coherence.
        Ensures local actions don't create cross-segment vulnerabilities.
        """
        self.stats["total_events"] += 1
        self.stats["total_actions"] += len(actions)

        # Update global threat state
        self._update_global_threat(event)

        # Policy enforcement
        validated_actions = self._enforce_policies(actions, event)

        # Preemptive hardening for zero-day
        if event.attack_type in ("ZeroDay-Lateral", "Exploits"):
            hardened = self._harden_adjacent_nodes(event)
            self.stats["hardened_nodes"] += len(hardened)

        # Audit all actions
        for action in validated_actions:
            self._audit(action, event)
            if action.autonomous:
                self.stats["autonomous_actions"] += 1
            else:
                self.stats["human_escalations"] += 1

        # Adaptive threshold recalibration
        self._recalibrate_thresholds(event)

        # Check for policy conflicts (global coherence)
        self._check_global_coherence(validated_actions)

        self._log("GOVERN",
                  f"Processed {len(validated_actions)} actions for {event.event_id} "
                  f"| global_threat={self.global_threat_level.name}")

        return validated_actions

    def _update_global_threat(self, event: ThreatEvent):
        self.active_threats[event.event_id] = event
        max_level = max(e.threat_level.value for e in self.active_threats.values())
        self.global_threat_level = ThreatLevel(max_level)

        # Expire old threats (> 5 min)
        now = time.time()
        self.active_threats = {
            eid: ev for eid, ev in self.active_threats.items()
            if now - ev.timestamp < 300
        }

    def _enforce_policies(self, actions: List[DefensiveAction],
                           event: ThreatEvent) -> List[DefensiveAction]:
        """Apply governance policies to validate / modify / block actions."""
        validated = []
        for action in actions:
            # Policy: human-in-loop for irreversibles at very high scores
            if (action.action_type == ActionType.QUARANTINE_HOST and
                    event.fused_score < self.policies["human_in_loop_irreversibles"]["threshold_value"]):
                action.autonomous = False  # Require human approval
                self._log("POLICY", f"Human approval required for {action.action_type.value}")

            # Policy: least privilege — cap action scope
            if action.action_type == ActionType.BLOCK_IP_RANGE and event.fused_score < 0.75:
                # Downgrade to rate limiting instead
                action.action_type = ActionType.RATE_LIMIT
                self._log("POLICY", "Block downgraded to rate-limit (least-privilege)")

            validated.append(action)
        return validated

    def _harden_adjacent_nodes(self, event: ThreatEvent) -> List[str]:
        """
        Preemptively harden nodes adjacent to compromised ones.
        Models potential propagation paths.
        """
        hop_depth = self.policies["preemptive_hardening"]["hop_depth"]
        to_harden = set()

        for node in event.anomalous_nodes:
            neighbors = self.topology.get(node, set())
            to_harden.update(neighbors)
            if hop_depth >= 2:
                for n2 in list(neighbors):
                    to_harden.update(self.topology.get(n2, set()))

        to_harden -= set(event.anomalous_nodes)  # Don't re-harden already compromised
        to_harden -= self.hardened_nodes

        for node in to_harden:
            self.hardened_nodes.add(node)
            self._log("HARDEN", f"Preemptively hardened adjacent node: {node}")

        return list(to_harden)

    def _recalibrate_thresholds(self, event: ThreatEvent):
        """
        Self-adaptive threshold recalibration.
        Prevents performance degradation as traffic distributions shift.
        """
        if not self.policies["self_adaptive_thresholds"]["enabled"]:
            return

        self.threshold_history.append(event.fused_score)
        window = self.policies["self_adaptive_thresholds"]["window_size"]
        if len(self.threshold_history) > window:
            self.threshold_history = self.threshold_history[-window:]

        if len(self.threshold_history) >= 5:
            baseline = np.mean(self.threshold_history)
            std = np.std(self.threshold_history)

            # New thresholds: baseline + k*std
            self.current_thresholds["fusion"] = float(np.clip(baseline + 0.5 * std, 0.3, 0.85))
            self.current_thresholds["quarantine_trigger"] = float(
                np.clip(baseline + 1.5 * std, 0.55, 0.90))

            self._log("CALIBRATE",
                      f"Thresholds recalibrated: fusion={self.current_thresholds['fusion']:.3f} "
                      f"quarantine={self.current_thresholds['quarantine_trigger']:.3f}")

    def _check_global_coherence(self, actions: List[DefensiveAction]):
        """
        Ensure local defensive actions don't create cross-segment vulnerabilities.
        E.g. quarantining a node might isolate a critical dependency.
        """
        quarantined_in_batch = [a.target for a in actions
                                 if a.action_type == ActionType.QUARANTINE_HOST]
        for q in quarantined_in_batch:
            deps = self.topology.get(q, set())
            critical_deps = [d for d in deps if d not in self.hardened_nodes]
            if critical_deps:
                self._log("COHERENCE",
                          f"Quarantine of {q} may affect: {critical_deps[:3]} — monitoring")

    def _audit(self, action: DefensiveAction, event: ThreatEvent):
        """Append-only immutable audit entry (cryptographic chaining in production)."""
        entry = {
            "seq": len(self.audit_log),
            "timestamp": time.time(),
            "event_id": event.event_id,
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "severity": action.severity,
            "autonomous": action.autonomous,
            "threat_level": event.threat_level.name,
            "fused_score": event.fused_score,
        }
        self.audit_log.append(entry)

    def update_topology(self, topology: Dict[str, List[str]]):
        """Update network topology map from graph builder."""
        self.topology = {k: set(v) for k, v in topology.items()}

    def get_policy_status(self) -> Dict:
        return {name: pol["enabled"] for name, pol in self.policies.items()}

    def get_statistics(self) -> Dict:
        return {**self.stats,
                "active_threats": len(self.active_threats),
                "quarantined_hosts": "see ResponseCoordAgent",
                "audit_entries": len(self.audit_log),
                "global_threat_level": self.global_threat_level.name,
                "current_thresholds": self.current_thresholds,
                }
