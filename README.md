# Agentic Security Operations Centre (Agentic SOC)

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GNN](https://img.shields.io/badge/AI-GraphSAGE%20%2B%20GAT-FF6F00)](#-architecture)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

An autonomous, closed-loop cyber defense platform for **Zero-Day and DDoS attack prevention**. Built on the **UNSW-NB15** framework, the system pairs a hybrid **GNN + Attention-DNN** detection pipeline with **4 collaborating AI agents** to analyze threats, filter benign mimics, and execute real kernel-level `iptables` mitigations in real time.

---

## ⚡ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  Docker Virtual Network: attack_net (172.20.0.0/24)                    │
│                                                                        │
│  ┌────────────────────┐          ┌──────────────────────────────────┐  │
│  │   attacker_node    │─Attacks─►│          target_server           │  │
│  │   (172.20.0.30)    │          │  Nginx :8888  |  OpenSSH :2222   │  │
│  └────────────────────┘          └─────────────────┬────────────────┘  │
│                                                    │ Logs & Packets    │
│  ┌────────────────────┐                            ▼                   │
│  │  8x Normal Users   │─Traffic─►┌──────────────────────────────────┐  │
│  │ (.40 to .47)       │          │          governance_ai           │  │
│  └────────────────────┘          │          (172.20.0.20)           │  │
│                                  │  • GraphSAGE + GAT Hybrid GNN    │  │
│                                  │  • Attention-DNN + LSTM Fusion   │  │
│                                  │  • 4 Autonomous AI Agents        │  │
│                                  │  • Auto IPBlocker (iptables)     │  │
│                                  │  • Web UI: http://localhost:8080 │  │
│                                  └──────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### The 4-Layer Closed Loop
1. **Layer 0 (Ingestion)**: Sniffs live packets (`eth0`) & tails structured Nginx JSON logs into 49-dim UNSW-NB15 vectors across a 60s sliding graph window.
2. **Layer 1 & 2 (AI Detection)**:
   - **GraphSAGE + GAT**: Inductive node embeddings detect unseen IPs, DDoS fan-out, and lateral movement.
   - **Attention-DNN + Temporal Analyzer**: Residual blocks with self-attention gates combined with sequential traffic dynamics.
   - **Fusion**: Blends scores ($0.45 \cdot \text{GNN} + 0.40 \cdot \text{DNN} + 0.15 \cdot \text{Temporal}$) into unified threat levels.
3. **Layer 3 (Multi-Agent SOC)**:
   - **MonitoringAgent**: Classifies threat vectors and issues structured `ThreatEvents`.
   - **ThreatAnalysisAgent**: Semantic reasoning eliminates benign mimics (CDN spikes, admin jobs) and builds incident narratives.
   - **ResponseCoordAgent**: Q-learning RL policy selects tailored defensive actions.
   - **GovernanceAgent**: Enforces system policies, preemptively hardens adjacent nodes, and maintains an immutable audit log.
4. **Layer 4 (Enforcement & UI)**:
   - **Real `iptables` Blocking**: Drops offending IPs with automated unblock timers and clean shutdown flushes.
   - **Live Web Dashboard**: Interactive topology graph, threat feed, manual & auto-block controls.

---

## 🚀 Quick Start (Docker)

### 1. Prerequisites
- [Docker Engine 24+](https://docs.docker.com/engine/install/) & Docker Compose v2.20+

### 2. Launch Testbed
Clone the repo and start the complete environment (Target + Governance AI + 8 Benign Users + Attacker):

```bash
# Build all images
docker compose build

# Start core stack + attacker profile
docker compose --profile with-attacker up -d

# Verify running containers
docker compose ps
```

### 3. Open the Dashboard
Visit **[http://localhost:8080](http://localhost:8080)** to view:
- Live network connection graphs & active IP entities.
- Real-time threat detection stream.
- Instant **"🚫 Block"** / **"✅ Unblock"** buttons and Auto-Block toggle.

### 4. Monitor AI Decisions & Blocks
```bash
# Follow detection and blocking logs live
docker compose logs -f governance | grep -E "AUTO-BLOCK|BLOCK|HIGH|CRITICAL|fused"

# Inspect active iptables drop rules
docker compose exec governance iptables -L INPUT -n --line-numbers
```

---

## 🧪 Standalone Simulation Mode (No Docker)

You can also run the evaluation and attack simulations directly with Python:

```bash
cd governance
pip install -r requirements.txt

# Run attack simulations
python agentic_governance/main.py demo ddos
python agentic_governance/main.py demo zeroday
python agentic_governance/main.py demo combined

# Run evaluation on UNSW-NB15 dataset metrics (~98% accuracy, ~0.97 F1)
python agentic_governance/main.py eval
```

---

## 📁 Repository Structure

```
├── attacker/               # High-intensity attack generator (DDoS, scans, brute-force, SQLi/XSS)
├── governance/             # Core SOC AI Engine
│   ├── agentic_governance/
│   │   ├── agents/         # 4 collaborating agents (Monitor, Analyst, Responder, Governor)
│   │   ├── detection/      # Pure-NumPy Attention-DNN & LSTM Temporal Analyzer
│   │   ├── gnn/            # GraphSAGE-GAT hybrid model & NetworkGraphBuilder
│   │   └── realtime/       # Web dashboard server (Port 8080) & console monitor
│   ├── real_traffic_bridge.py # Live Scapy sniffer, log parser & iptables IPBlocker
│   └── Dockerfile
├── normal_users/           # 8 benign browser personas generating realistic background traffic
├── target/                 # Honeypot target server (Ubuntu + Nginx JSON logging + OpenSSH)
└── docker-compose.yml      # Orchestrates isolated 172.20.0.0/24 attack testbed
```

---

## 🛡️ Teardown

```bash
# Stop and remove all containers, networks, and volumes
docker compose down -v
```

---

## 👥 Authors
Developed at **DES Pune University**:
- Lalit Kulkarni
- Pranjal S Nalawade
- Afra Inamdar
- Sanket S Desai
