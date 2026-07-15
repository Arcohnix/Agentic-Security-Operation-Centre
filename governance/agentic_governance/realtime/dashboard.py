"""
dashboard.py
============
Self-contained dashboard server.

Uses DashStore — a simple copy-on-read data store — instead of
RealTimeNetworkScanner. The bridge writes snapshots into DashStore;
the HTTP server reads copies out. No shared locks, no deadlock possible.
"""

import json
import time
import copy
import threading
from collections import defaultdict, deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────
#  DashStore — lock-free-ish data store for dashboard state
# ─────────────────────────────────────────────────────────────────

# IPs that are never flagged suspicious or blocked
_IP_WHITELIST = {
    "192.168.65.1", "172.20.0.10", "172.20.0.20",
    "172.20.0.40", "172.20.0.41", "172.20.0.42", "172.20.0.43",
    "172.20.0.44", "172.20.0.45", "172.20.0.46", "172.20.0.47",
    "127.0.0.1", "0.0.0.0", "::1",
}

# Human-readable role labels shown on dashboard
_IP_ROLES = {
    "192.168.65.1": "Docker Gateway",
    "172.20.0.10":  "Target Server",
    "172.20.0.20":  "Governance AI",
    "172.20.0.30":  "Attacker",
    "172.20.0.40":  "User: alice",
    "172.20.0.41":  "User: bob",
    "172.20.0.42":  "User: carol",
    "172.20.0.43":  "User: dave",
    "172.20.0.44":  "User: eve",
    "172.20.0.45":  "User: frank",
    "172.20.0.46":  "User: grace",
    "172.20.0.47":  "User: heidi",
}

class DashStore:
    """
    Written to by the bridge (under a short lock).
    Read by the HTTP server (takes a snapshot copy, releases lock immediately).
    Never holds the lock during heavy computation.
    """

    def __init__(self):
        self._lock         = threading.Lock()
        self._stats        = {"total_connections": 0, "unique_ips": 0,
                              "suspicious_count": 0, "total_bytes": 0,
                              "active_connections": 0}
        self._ip_stats     = {}        # ip -> {connections, bytes, ports, suspicious, reasons, last_seen}
        self._recent       = deque(maxlen=50)   # recent connection dicts
        self._threats      = deque(maxlen=200)  # threat event dicts
        self._suspicious   = set()
        self._blocked      = set()
        self._auto_blocked = {}   # ip -> threat level that triggered auto-block

    # ── write API (called from bridge, fast) ──────────────────────

    def ingest_connections(self, connections):
        """Called every analysis cycle with real NetworkConnection objects."""
        now = time.time()
        with self._lock:
            for c in connections:
                for ip in (c.src_ip, c.dst_ip):
                    # ALL IPs are tracked and shown on the dashboard.
                    # Whitelisted IPs are shown as SAFE — never marked suspicious.
                    st = self._ip_stats.setdefault(ip, {
                        "connections": 0, "bytes": 0, "ports": set(),
                        "suspicious": False, "reasons": [], "last_seen": now,
                        "first_seen": now,
                        "whitelisted": ip in _IP_WHITELIST,
                        "role": _IP_ROLES.get(ip, "unknown"),
                    })
                    st["connections"] += 1
                    st["bytes"]       += c.src_bytes + c.dst_bytes
                    st["ports"].add(c.dst_port)
                    st["last_seen"]    = now

                self._recent.appendleft({
                    "src_ip":   c.src_ip,
                    "dst_ip":   c.dst_ip,
                    "src_port": c.src_port,
                    "dst_port": c.dst_port,
                    "protocol": c.protocol,
                    "state":    "ESTABLISHED",
                    "bytes":    c.src_bytes + c.dst_bytes,
                })

            # Recompute top-level stats
            self._stats["unique_ips"]         = len(self._ip_stats)
            self._stats["active_connections"] = len(self._recent)
            self._stats["total_connections"]  = sum(
                v["connections"] for v in self._ip_stats.values())
            self._stats["total_bytes"]        = sum(
                v["bytes"] for v in self._ip_stats.values())
            self._stats["suspicious_count"]   = len(self._suspicious)

    def ingest_threat(self, event, actions):
        """Called when MonitoringAgent fires a ThreatEvent."""
        now = time.time()
        action_name = actions[0].action_type.value if actions else "alert"
        entry = {
            "ts":     now,
            "type":   event.attack_type,
            "src":    event.source_ip,
            "score":  round(event.fused_score, 4),
            "level":  event.threat_level.name,
            "action": action_name,
        }
        with self._lock:
            self._threats.appendleft(entry)
            if event.fused_score > 0.4 and event.source_ip and event.source_ip not in _IP_WHITELIST:
                src = event.source_ip
                self._suspicious.add(src)
                if src in self._ip_stats:
                    self._ip_stats[src]["suspicious"] = True
                    self._ip_stats[src]["reasons"] = [
                        f"{event.attack_type} score={event.fused_score:.2f}"
                        f" [{event.threat_level.name}]"
                    ]
                self._stats["suspicious_count"] = len(self._suspicious)

    def mark_blocked(self, ip):
        with self._lock:
            self._blocked.add(ip)

    def mark_unblocked(self, ip):
        with self._lock:
            self._blocked.discard(ip)
            self._auto_blocked.pop(ip, None)

    def mark_auto_blocked(self, ip, level):
        with self._lock:
            self._blocked.add(ip)
            self._auto_blocked[ip] = level

    # ── read API (called from HTTP server, returns copies) ─────────

    def snapshot(self):
        with self._lock:
            stats   = dict(self._stats)
            top_ips = sorted(self._ip_stats.items(),
                             key=lambda kv: kv[1]["connections"], reverse=True)[:15]
            top = [{
                "ip":          ip,
                "connections": d["connections"],
                "bytes":       d["bytes"],
                "ports":       len(d["ports"]),
                "suspicious":  d["suspicious"],
                "whitelisted": d.get("whitelisted", False),
                "role":        d.get("role", _IP_ROLES.get(ip, "")),
                "reasons":     list(d["reasons"]),
                "duration":    round(d["last_seen"] - d["first_seen"], 1),
            } for ip, d in top_ips]
            recent = list(self._recent)[:20]
            susp   = sorted(self._suspicious)
        with self._lock:
            auto_blocked = dict(self._auto_blocked)
        return {
            "stats":              stats,
            "top_ips":            top,
            "recent_connections": recent,
            "suspicious_ips":     susp,
            "active_ips":         [r["ip"] for r in top],
            "auto_blocked":       auto_blocked,
        }

    def threats(self):
        with self._lock:
            return list(self._threats)

    def graph(self):
        with self._lock:
            top = sorted(self._ip_stats.items(),
                         key=lambda kv: kv[1]["connections"], reverse=True)[:30]
            nodes = [{"id": ip, "label": ip,
                      "connections": d["connections"],
                      "suspicious":  d["suspicious"],
                      "whitelisted": d.get("whitelisted", ip in _IP_WHITELIST),
                      "role":        d.get("role", _IP_ROLES.get(ip, "")),
                     } for ip, d in top]
            # edges between top IPs that share recent connections
            recent = list(self._recent)[:50]
            edges  = [{"from": r["src_ip"], "to": r["dst_ip"],
                       "protocol": r["protocol"], "port": r["dst_port"],
                       "bytes": r["bytes"]} for r in recent
                      if r["src_ip"] in self._ip_stats
                      and r["dst_ip"] in self._ip_stats]
        return {"nodes": nodes, "edges": edges}

    def blocked(self):
        with self._lock:
            return sorted(self._blocked)


# ─────────────────────────────────────────────────────────────────
#  HTTP request handler
# ─────────────────────────────────────────────────────────────────

class DashboardServer(BaseHTTPRequestHandler):

    store               = DashStore()   # shared singleton written by bridge
    ip_blocker          = None          # wired by bridge entry point
    auto_block_enabled  = True          # toggled by /api/autoblock
    threat_log          = []

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        p = urlparse(self.path).path
        if   p == "/":             self._html()
        elif p == "/api/snapshot": self._json(self.store.snapshot())
        elif p == "/api/graph":    self._json(self.store.graph())
        elif p == "/api/threats":  self._json({"threats": self.store.threats()})
        elif p == "/api/blocked":
            with self.store._lock:
                auto = dict(self.store._auto_blocked)
            self._json({"blocked_ips": self.store.blocked(), "auto_blocked": auto})
        elif p == "/api/ping":     self._json({"ok": True, "ts": time.time()})
        else:                      self.send_error(404)

    def do_POST(self):
        p      = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            body = {}

        if p == "/api/block":
            ip = body.get("ip", "").strip()
            if ip and self.ip_blocker:
                ok = self.ip_blocker.block(ip, duration_sec=3600)
                self.store.mark_blocked(ip)
                self._json({"success": ok, "blocked": ip})
            else:
                self._json({"success": False, "error": "no ip or blocker"})

        elif p == "/api/unblock":
            ip = body.get("ip", "").strip()
            if ip and self.ip_blocker:
                ok = self.ip_blocker.unblock(ip)
                self.store.mark_unblocked(ip)
                self._json({"success": ok, "unblocked": ip})
            else:
                self._json({"success": False, "error": "no ip or blocker"})

        elif p == "/api/autoblock":
            # Frontend toggle — stored as class var, bridge reads it
            DashboardServer.auto_block_enabled = body.get("enabled", True)
            self._json({"auto_block_enabled": DashboardServer.auto_block_enabled})

        else:
            self.send_error(404)

    def _json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        pass

    def _html(self):
        page = _HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


# ─────────────────────────────────────────────────────────────────
#  HTML / CSS / JS
# ─────────────────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agentic AI - Network Monitor</title>
<style>
:root{--bg:#0f172a;--sur:#1e293b;--bdr:#334155;--txt:#e2e8f0;--mut:#64748b;
      --grn:#22c55e;--red:#ef4444;--amb:#f59e0b;--blu:#38bdf8;--pur:#a78bfa}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
header{background:var(--sur);border-bottom:1px solid var(--bdr);padding:13px 26px;
       display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:9}
header h1{font-size:1.05rem;font-weight:600}
header h1 em{font-style:normal;color:var(--blu)}
.hdr-right{display:flex;align-items:center;gap:18px}
.live{display:flex;align-items:center;gap:7px;font-size:.72rem;color:var(--mut)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--grn);animation:blink 1.5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}
/* Auto-block toggle */
.ab-wrap{display:flex;align-items:center;gap:8px;font-size:.75rem}
.ab-lbl{color:var(--mut)}
.ab-lbl.on{color:#86efac;font-weight:600}
.toggle{position:relative;width:36px;height:20px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#334155;border-radius:20px;transition:.2s}
.slider:before{content:"";position:absolute;width:14px;height:14px;left:3px;top:3px;
               background:#fff;border-radius:50%;transition:.2s}
input:checked+.slider{background:#22c55e}
input:checked+.slider:before{transform:translateX(16px)}
main{padding:18px 26px;max-width:1480px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:14px}
.card{background:var(--sur);border:1px solid var(--bdr);border-radius:9px;padding:15px 18px}
.card-lbl{font-size:.67rem;color:var(--mut);text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px}
.card-val{font-size:1.85rem;font-weight:700}
.cg{color:var(--grn)}.cr{color:var(--red)}.ca{color:var(--amb)}.cb{color:var(--blu)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:11px;margin-bottom:11px}
.panel{background:var(--sur);border:1px solid var(--bdr);border-radius:9px;padding:15px}
.full{grid-column:1/-1}
.ph{font-size:.67rem;font-weight:600;color:var(--mut);text-transform:uppercase;
    letter-spacing:.08em;margin-bottom:11px;display:flex;align-items:center;gap:6px}
.cnt{background:var(--bdr);color:var(--txt);font-size:.62rem;padding:1px 6px;border-radius:10px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{color:var(--mut);font-weight:500;font-size:.65rem;text-transform:uppercase;
   letter-spacing:.06em;padding:5px 7px;border-bottom:1px solid var(--bdr);text-align:left}
td{padding:6px 7px;border-bottom:1px solid #1a2234;color:#94a3b8;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.018)}
.ip{font-family:'SF Mono',Consolas,monospace;font-size:.75rem;color:#7dd3fc;cursor:pointer}
.ip:hover{color:var(--blu);text-decoration:underline}
.b{display:inline-block;padding:1px 6px;border-radius:20px;font-size:.65rem;font-weight:600}
.bg{background:#052e16;color:#4ade80}.br{background:#450a0a;color:#f87171}
.bs{background:#0c1a3a;color:#93c5fd}
.ba{background:#431407;color:#fb923c}.bb{background:#0c1a3a;color:#60a5fa}
.bp{background:#2e1065;color:#c084fc}
/* auto-block badge */
.ab{background:#052e16;color:#4ade80;border:1px solid #16a34a;
    font-size:.6rem;padding:1px 5px;border-radius:20px;font-weight:700}
.sc td:first-child,.sh td:first-child{border-left:3px solid var(--red);padding-left:5px}
.sm td:first-child{border-left:3px solid var(--amb);padding-left:5px}
.sl td:first-child{border-left:3px solid var(--blu);padding-left:5px}
.btn{padding:2px 8px;border-radius:5px;font-size:.67rem;cursor:pointer;border:1px solid}
.btn-bl{background:#7f1d1d;color:#fca5a5;border-color:#991b1b}
.btn-bl:hover{background:#991b1b}
.chips{display:flex;flex-wrap:wrap;gap:3px;min-height:26px;align-items:flex-start;padding-top:2px}
.chip{display:inline-flex;align-items:center;gap:4px;border:1px solid;
      color:#fca5a5;padding:2px 7px;border-radius:20px;font-size:.68rem;font-family:monospace}
.chip.manual{background:#450a0a;border-color:#7f1d1d}
.chip.auto{background:#052e16;border-color:#16a34a;color:#86efac}
.chip button{background:none;border:none;cursor:pointer;font-size:.8rem}
.chip.manual button{color:#f87171}
.chip.auto button{color:#4ade80}
#gw{width:100%;height:360px;background:#080d18;border-radius:7px;overflow:hidden}
#gs{width:100%;height:100%}
.empty{color:#334155;font-size:.75rem;padding:16px;text-align:center}
footer{text-align:center;color:var(--bdr);font-size:.65rem;padding:16px}
@media(max-width:780px){.cards{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <h1>Agentic AI &mdash; <em>Real-Time Network Monitor</em></h1>
  <div class="hdr-right">
    <div class="ab-wrap">
      <label class="toggle">
        <input type="checkbox" id="ab-toggle" checked onchange="toggleAutoBlock(this.checked)">
        <span class="slider"></span>
      </label>
      <span class="ab-lbl on" id="ab-lbl">Auto-block HIGH/CRITICAL</span>
    </div>
    <div class="live"><div class="dot"></div>Live &bull; 3s</div>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="card-lbl">Flows Analyzed</div><div class="card-val cg" id="vt">-</div></div>
    <div class="card"><div class="card-lbl">Unique IPs</div><div class="card-val cb" id="vi">-</div></div>
    <div class="card"><div class="card-lbl">Suspicious IPs</div><div class="card-val cr" id="vs">-</div></div>
    <div class="card"><div class="card-lbl">Total Traffic</div><div class="card-val ca" id="vb">-</div></div>
  </div>
  <div class="row">
    <div class="panel">
      <div class="ph">Threat Events <span class="cnt" id="ct">0</span></div>
      <table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Score</th><th>Level</th><th>Action</th><th>Auto-block</th></tr></thead>
      <tbody id="tt"><tr><td colspan="7" class="empty">Waiting...</td></tr></tbody></table>
    </div>
    <div class="panel">
      <div class="ph">Top Active IPs <span class="cnt" id="ci">0</span></div>
      <table><thead><tr><th>IP</th><th>Conns</th><th>Data</th><th>Ports</th><th>Status</th><th>Action</th></tr></thead>
      <tbody id="ti"><tr><td colspan="6" class="empty">Waiting...</td></tr></tbody></table>
    </div>
  </div>
  <div class="row">
    <div class="panel">
      <div class="ph">Recent Connections <span class="cnt" id="cc">0</span></div>
      <table><thead><tr><th>Source</th><th>Dest</th><th>Port</th><th>Proto</th><th>State</th></tr></thead>
      <tbody id="tc"><tr><td colspan="5" class="empty">Waiting...</td></tr></tbody></table>
    </div>
    <div class="panel">
      <div class="ph">Blocked IPs <span class="cnt" id="cb2">0</span>
        <span style="margin-left:auto;display:flex;gap:6px;font-weight:400;text-transform:none;letter-spacing:0">
          <span class="b bg" style="font-size:.58rem">AUTO</span>=HIGH/CRIT auto-block
          &nbsp;
          <span class="b br" style="font-size:.58rem">MAN</span>=manual
        </span>
      </div>
      <div class="chips" id="chips"><span class="empty">None</span></div>
    </div>
  </div>
  <div class="panel full" id="sp" style="display:none;margin-bottom:11px">
    <div class="ph">Suspicious IPs <span class="cnt" id="csp">0</span></div>
    <table><thead><tr><th>IP</th><th>Conns</th><th>Ports</th><th>Reason</th><th>Status</th><th>Block</th></tr></thead>
    <tbody id="tsp"></tbody></table>
  </div>
  <div class="panel full">
    <div class="ph">Network Graph</div>
    <div id="gw"><svg id="gs" viewBox="0 0 800 360">
      <text x="400" y="185" text-anchor="middle" fill="#334155" font-size="13">No data yet</text>
    </svg></div>
    <div style="margin-top:5px;font-size:.65rem;color:var(--mut)">Green=normal &nbsp;|&nbsp; Red=suspicious/attacker &nbsp;|&nbsp; Blue=whitelisted (safe) &nbsp;|&nbsp; Size=connections</div>
  </div>
</main>
<footer>Last updated: <span id="lu">never</span> &mdash; Agentic AI Governance &mdash; DES Pune University</footer>
<script>
const Q=id=>document.getElementById(id);
const set=(id,v)=>{const e=Q(id);if(e)e.textContent=v;};
let autoBlockEnabled=true;
let autoBlocked={};

function toggleAutoBlock(on){
  autoBlockEnabled=on;
  const lbl=Q('ab-lbl');
  lbl.textContent=on?'Auto-block HIGH/CRITICAL':'Auto-block OFF';
  lbl.className='ab-lbl'+(on?' on':'');
  // Tell backend
  fetch('/api/autoblock',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({enabled:on})}).catch(()=>{});
}

function fb(n){if(!n)return'0 B';const u=['B','KB','MB','GB'];let i=0;
  while(n>=1024&&i<3){n/=1024;i++;}return n.toFixed(i?1:0)+' '+u[i];}
function ft(ts){return ts?new Date(ts*1000).toLocaleTimeString():'';}
function sc(s){s=+s||0;return s>=.8?'br':s>=.6?'ba':s>=.4?'bp':'bb';}
function lc(l){return{CRITICAL:'br',HIGH:'br',MEDIUM:'ba',LOW:'bb',NORMAL:'bg'}[(l||'').toUpperCase()]||'bb';}
function sr(l){return's'+((l||'l')[0].toLowerCase());}
function b(t,c){return`<span class="b ${c}">${t}</span>`;}
function api(p){return fetch(p,{signal:AbortSignal.timeout(4000)}).then(r=>{if(!r.ok)throw r;return r.json();});}

function doSnap(){
  api('/api/snapshot').then(d=>{
    const s=d.stats||{};
    autoBlocked=d.auto_blocked||{};
    set('vt',(s.total_connections||0).toLocaleString());
    set('vi',(s.unique_ips||0).toLocaleString());
    set('vs',(s.suspicious_count||0).toLocaleString());
    set('vb',fb(s.total_bytes||0));

    // Top IPs — now with Block button column
    const tips=d.top_ips||[];
    set('ci',tips.length);
    Q('ti').innerHTML=tips.length?tips.map(x=>{
      const isBlocked=!!(d.auto_blocked||{})[x.ip]||(d.blocked||[]).includes(x.ip);
      const role=x.role?`<span style="font-size:.65rem;color:var(--mut)"> ${x.role}</span>`:'';
      let statusBadge;
      if(x.suspicious)           statusBadge=b('THREAT','br');
      else if(x.whitelisted)     statusBadge=b('SAFE','bs');
      else                       statusBadge=b('OK','bg');
      const btn=x.whitelisted
        ?`<span style="font-size:.65rem;color:var(--mut)">—</span>`
        :isBlocked
          ?`<span class="b bg" style="font-size:.6rem">BLOCKED</span>`
          :`<button class="btn btn-bl" onclick="blk('${x.ip}')">Block</button>`;
      return`<tr>
        <td><span class="ip" onclick="pip('${x.ip}')">${x.ip}</span>${role}</td>
        <td>${(x.connections||0).toLocaleString()}</td><td>${fb(x.bytes||0)}</td>
        <td>${x.ports||0}</td>
        <td>${statusBadge}</td>
        <td>${btn}</td>
      </tr>`;}).join(''):'<tr><td colspan="6" class="empty">Waiting...</td></tr>';

    const rc=d.recent_connections||[];
    set('cc',rc.length);
    Q('tc').innerHTML=rc.length?rc.slice(0,10).map(c=>`<tr>
      <td><span class="ip">${c.src_ip}</span></td><td><span class="ip">${c.dst_ip}</span></td>
      <td>${c.dst_port}</td><td>${b(c.protocol,'bb')}</td><td>${c.state}</td>
    </tr>`).join(''):'<tr><td colspan="5" class="empty">Waiting...</td></tr>';

    const si=(d.top_ips||[]).filter(x=>x.suspicious);
    Q('sp').style.display=si.length?'block':'none';
    set('csp',si.length);
    Q('tsp').innerHTML=si.map(x=>{
      const isBlocked=!!(d.auto_blocked||{})[x.ip];
      return`<tr>
        <td><span class="ip">${x.ip}</span></td><td>${x.connections||0}</td><td>${x.ports||0}</td>
        <td style="font-size:.7rem">${(x.reasons||[]).join(', ')||'Anomaly'}</td>
        <td>${b('THREAT','br')}</td>
        <td>${isBlocked
          ?`<span class="b bg">AUTO-BLOCKED</span>`
          :`<button class="btn btn-bl" onclick="blk('${x.ip}')">Block</button>`}</td>
      </tr>`;}).join('');

    set('lu',new Date().toLocaleTimeString());
  }).catch(()=>{});
}

function doThreats(){
  api('/api/threats').then(d=>{
    const rows=d.threats||[];
    set('ct',rows.length);
    Q('tt').innerHTML=rows.length?rows.slice(0,15).map(t=>{
      const isAuto=!!(autoBlocked||{})[t.src];
      const autoBadge=isAuto?`<span class="ab">AUTO</span>`:'&mdash;';
      return`<tr class="${sr(t.level)}">
        <td style="font-size:.65rem;white-space:nowrap;color:var(--mut)">${ft(t.ts)}</td>
        <td>${b(t.type||'?','bp')}</td><td><span class="ip">${t.src||'?'}</span></td>
        <td>${b((+t.score||0).toFixed(3),sc(t.score))}</td>
        <td>${b(t.level||'LOW',lc(t.level))}</td>
        <td>${b(t.action||'alert','bb')}</td>
        <td>${autoBadge}</td>
      </tr>`;}).join(''):'<tr><td colspan="7" class="empty">Waiting...</td></tr>';
  }).catch(()=>{});
}

function doBlocked(){
  api('/api/blocked').then(d=>{
    const ips=d.blocked_ips||[];
    const autoMap=d.auto_blocked||autoBlocked||{};
    set('cb2',ips.length);
    Q('chips').innerHTML=ips.length?ips.map(ip=>{
      const isAuto=!!autoMap[ip];
      const cls=isAuto?'chip auto':'chip manual';
      const tag=isAuto?`<span class="b bg" style="font-size:.55rem">${autoMap[ip]}</span>`:'';
      return`<span class="${cls}">${tag}${ip}
        <button onclick="ublk('${ip}')" title="Unblock">&#10005;</button>
      </span>`;}).join('')
      :'<span class="empty">None</span>';
  }).catch(()=>{});
}

const gp={};
function doGraph(){
  api('/api/graph').then(d=>{
    const nodes=d.nodes||[],edges=d.edges||[];
    const svg=Q('gs'),W=Q('gw').clientWidth||800,H=360;
    svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
    nodes.forEach((n,i)=>{
      if(!gp[n.id]){const a=(i/Math.max(nodes.length,1))*2*Math.PI,r=Math.min(W,H)*.37;
        gp[n.id]={x:W/2+r*Math.cos(a),y:H/2+r*Math.sin(a)};}
    });
    let o='';
    edges.forEach(e=>{const a=gp[e.from],bv=gp[e.to];if(!a||!bv)return;
      o+=`<line x1="${a.x|0}" y1="${a.y|0}" x2="${bv.x|0}" y2="${bv.y|0}" stroke="#334155" stroke-width="1" opacity=".4"/>`;});
    nodes.forEach(n=>{const p=gp[n.id];if(!p)return;
      const isAB=!!(autoBlocked||{})[n.id];
      const r=Math.max(7,Math.min(22,8+Math.log1p(n.connections||1)*3));
      let fill,stroke,tc;
      if(n.suspicious){fill='#7f1d1d';stroke='#ef4444';tc='#fca5a5';}
      else if(n.whitelisted){fill='#0c1a3a';stroke='#38bdf8';tc='#93c5fd';}
      else{fill='#0f4c2a';stroke='#22c55e';tc='#86efac';}
      const shortId=(n.label||n.id||'').slice(-14);
      const roleLabel=n.role?n.role.replace('User: ',''):'';
      const displayLabel=roleLabel||shortId;
      const ring=isAB?`<circle cx="${p.x|0}" cy="${p.y|0}" r="${(r+5)|0}" fill="none" stroke="#22c55e" stroke-width="1.5" stroke-dasharray="3 2"/>`:'';
      o+=`${ring}<circle cx="${p.x|0}" cy="${p.y|0}" r="${r|0}" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>
          <text x="${p.x|0}" y="${(p.y+r+9)|0}" text-anchor="middle" font-size="9" fill="${tc}" font-family="monospace">${displayLabel}</text>`;});
    svg.innerHTML=o||'<text x="50%" y="50%" text-anchor="middle" fill="#334155" font-size="13">No data</text>';
  }).catch(()=>{});
}

function blk(ip){
  if(!confirm('Manually block '+ip+' for 1 hour?'))return;
  fetch('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})
    .then(r=>r.json()).then(d=>{
      if(d.success)alert('Blocked: '+ip);
      else alert('Failed: '+(d.error||'?'));
      doBlocked();doSnap();
    });
}
function ublk(ip){
  if(!confirm('Unblock '+ip+'?'))return;
  fetch('/api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})
    .then(r=>r.json()).then(()=>doBlocked());
}
function pip(ip){
  api('/api/snapshot').then(d=>{
    const f=(d.top_ips||[]).find(x=>x.ip===ip);
    if(f)alert('IP: '+f.ip+'\\nConns: '+f.connections+'\\nData: '+fb(f.bytes||0)+
      '\\nPorts: '+f.ports+'\\nSuspicious: '+f.suspicious+
      (f.reasons&&f.reasons.length?'\\nReason: '+f.reasons.join(', '):''));
  });
}
function tick(){doSnap();doThreats();doBlocked();doGraph();}
tick();setInterval(tick,3000);
</script>
</body>
</html>"""




# ─────────────────────────────────────────────────────────────────
#  Convenience wrapper
# ─────────────────────────────────────────────────────────────────

def start_dashboard_server(store, ip_blocker=None, port=8080):
    DashboardServer.store      = store
    DashboardServer.ip_blocker = ip_blocker
    srv = ThreadingHTTPServer(("0.0.0.0", port), DashboardServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
