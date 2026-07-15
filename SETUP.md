# Agentic AI Adaptive System Governance — Docker Setup

## Architecture overview

```
┌──────────────────────────────────────────────────────────────────┐
│  Docker virtual network: attack_net  172.20.0.0/24               │
│                                                                  │
│  ┌──────────────────┐       ┌──────────────────────────────┐     │
│  │  attacker_node   │──────►│  target_server  172.20.0.10  │     │
│  │  172.20.0.30     │       │  Nginx (port 80)             │     │
│  │  attack.py       │       │  SSH   (port 22)             │     │
│  └──────────────────┘       └──────────┬─────────────────-─┘     │
│  (optional, profile)                   │ logs + packets          │
│                                        ▼                         │
│                          ┌───────────────────────────────────┐   │
│                          │  governance_ai  172.20.0.20       │   │
│                          │  AI pipeline:                     │   │
│                          │    GNN → DNN → Multi-Agent        │   │
│                          │  Real actions:                    │   │
│                          │    iptables block (IPBlocker)     │   │
│                          │  Dashboard: http://localhost:8080 │   │
│                          └───────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Prerequisites

```bash
# Docker Engine + Compose v2
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out and back in

docker --version          # Docker 24+
docker compose version    # v2.20+
```

## Step 1 — Build images

```bash
cd docker_setup_final
docker compose build
```

Expected (~3–5 min first time):
```
[+] Building  target_server   ... done
[+] Building  governance_ai   ... done
[+] Building  attacker_node   ... done
```

## Step 2 — Start (internet traffic mode, no internal attacker)

```bash
docker compose up -d
```

Services started:
- **target** on `172.20.0.10` — Nginx (port 8888 on host) + SSH (port 2222 on host)
- **governance** on `172.20.0.20` — AI detection + dashboard on port 8080

Check status:
```bash
docker compose ps
docker compose logs -f governance
```

## Step 3 — View the dashboard

Open in browser:
```
http://localhost:8080
```

The dashboard shows **real** IPs, live connection graphs, threat events, and a **"🚫 Block"** button next to each detected suspicious IP that fires real `iptables` rules inside the governance container.

## Step 4 — Generate real attack traffic

### Option A — Internal attacker container (safest, self-contained)

```bash
docker compose --profile with-attacker up -d
```

Change intensity in `docker-compose.yml`:
```yaml
environment:
  - ATTACK_MODE=mixed       # ddos | portscan | bruteforce | mixed
  - INTENSITY=medium        # low | medium | high
```

### Option B — Expose to real internet (on a VPS)

```bash
# On any VPS (EC2 free tier, DigitalOcean $4/mo, etc.)
git clone <your-repo>
cd docker_setup_final
docker compose up -d
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 8080/tcp
```

A public VPS gets scanned within seconds of getting a public IP.

### Option C — Port-forward via home router

Forward external 80 → `host-ip:8888` and external 22 → `host-ip:2222` in your router admin panel.

## Step 5 — Watch AI detect and block in real time

```bash
docker compose logs -f governance
```

Sample output:
```
[12:34:01][WARNING][bridge]  [THREAT] severity=HIGH fused=0.847
                              anomalous_nodes=['172.20.0.30']
[12:34:01][WARNING][IPBlocker] BLOCKING 172.20.0.30 for 3600s
[12:34:01][INFO   ][ResponseCoordAgent] Action: block_ip_range → 172.20.0.30
[12:34:01][INFO   ][GovernanceAgent]    Audit entry written.
```

To manually block an IP from the dashboard: click **"🚫 Block"** next to any suspicious IP in the dashboard UI.

## Useful commands

```bash
# Stop all
docker compose down

# Stop and wipe volumes (fresh start)
docker compose down -v

# Rebuild one service after code changes
docker compose build governance && docker compose up -d governance

# Shell into governance container
docker compose exec governance bash

# Check iptables rules added by governance
docker compose exec governance iptables -L INPUT -n --line-numbers

# Shell into target server
docker compose exec target bash

# Watch nginx access log live
docker compose exec target tail -f /var/log/nginx/access.log

# Check which IPs are hitting you most
docker compose exec target tail -f /var/log/nginx/access.log \
  | python3 -c "import sys,json; [print(json.loads(l)['remote_addr']) for l in sys.stdin]" \
  | sort | uniq -c | sort -rn
```

## Bug fixes applied in this version

| File | Bug | Fix |
|---|---|---|
| `agentic_governance/gnn/network_graph.py` | Duplicate `@dataclass` decorator on `NetworkConnection` causes `TypeError` at import | Removed the extra decorator |
| `agentic_governance/gnn/network_graph.py` | `UNSWNBSimulator.generate_*` passed `label=` and `attack_cat=` kwargs that `NetworkConnection` doesn't define | Removed those kwargs |
| `governance/real_traffic_bridge.py` | Stray `s` at end of `# Entry point` comment block | Removed |
| `governance/real_traffic_bridge.py` | IP blocking was logged but never actually executed via `iptables` | Added `IPBlocker` class; wired into `_run_governance()` and shutdown |
| `agentic_governance/realtime/dashboard.py` | Dashboard had no `do_POST` handler — "Block IP" UI had no backend | Added `do_POST` with `/api/block`, `/api/unblock`, `/api/blocked` routes |
| `agentic_governance/realtime/dashboard.py` | Suspicious IP table had no block button | Added `🚫 Block` button and `blockIP()` JS function |
| `governance/real_traffic_bridge.py` | Shutdown path never called `ip_blocker.flush()` — iptables rules would leak | Fixed `KeyboardInterrupt` handler |
