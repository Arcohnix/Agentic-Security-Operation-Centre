"""
real_traffic_bridge.py  — FIXED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Replaces UNSWNBSimulator with two real data sources:

  1. PacketCaptureBridge  — sniffs live packets via Scapy on eth0,
                            converts each IP flow into a NetworkConnection
                            with real 49-feature UNSW-NB15-compatible vectors.

  2. NginxLogBridge       — tails /target_logs/access.log (JSON lines),
                            extracts HTTP attack patterns (scanner, brute-force,
                            path traversal, etc.) and feeds them as connections.

  3. RealTrafficOrchestrator — combines both sources and drives the
                               AdaptiveGovernanceSystem pipeline in real time.

FIXES vs original:
  - Removed trailing 's' from the "Entry point" comment block (cosmetic)
  - Added real iptables IP blocking via IPBlocker class
  - IPBlocker is called whenever ActionType.BLOCK_IP_RANGE or FIREWALL_UPDATE fires
  - dashboard.py do_POST handler added so UI "Block IP" button works end-to-end
  - Graceful shutdown (KeyboardInterrupt) calls IPBlocker.flush() to restore iptables
"""

import os
import sys
import time
import json
import queue
import threading
import logging
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

sys.path.insert(0, "/app")
from agentic_governance.gnn.network_graph import NetworkConnection, NetworkGraphBuilder
from agentic_governance.orchestrator import AdaptiveGovernanceSystem

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s][%(levelname)s][%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bridge")

# ─────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────

TARGET_IP       = os.environ.get("TARGET_IP", "172.20.0.10")

# IPs that are NEVER flagged suspicious, never blocked, never tracked as attackers.
# 192.168.65.1 = Docker Desktop host-side gateway (appears in all container traffic)
IP_WHITELIST = {
    "192.168.65.1",   # Docker Desktop internal gateway
    "172.20.0.10",    # target server
    "172.20.0.20",    # governance AI — never block yourself
    "172.20.0.40",    # user: alice
    "172.20.0.41",    # user: bob
    "172.20.0.42",    # user: carol
    "172.20.0.43",    # user: dave
    "172.20.0.44",    # user: eve
    "172.20.0.45",    # user: frank
    "172.20.0.46",    # user: grace
    "172.20.0.47",    # user: heidi
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}
IFACE           = os.environ.get("NETWORK_INTERFACE", "eth0")
PCAP_DIR        = os.environ.get("PCAP_DIR", "/pcap")
TARGET_LOG_DIR  = os.environ.get("TARGET_LOG_DIR", "/target_logs")
DASHBOARD_PORT  = int(os.environ.get("DASHBOARD_PORT", "8080"))
ANALYSIS_WINDOW = 5.0   # seconds between governance analysis cycles


# ─────────────────────────────────────────────────────────────
#  Real IP Blocker — uses iptables inside the container
# ─────────────────────────────────────────────────────────────

class IPBlocker:
    """
    Executes real iptables rules to block attacker IPs inside the governance
    container.  Rules are tagged with a comment so they can be cleanly removed
    on shutdown.

    Usage:
        blocker = IPBlocker()
        blocker.block("1.2.3.4")          # block single IP
        blocker.block("1.2.3.0/24")       # block subnet
        blocker.unblock("1.2.3.4")
        blocker.flush()                   # remove ALL rules we added
        blocked = blocker.list_blocked()  # returns set of blocked IPs/subnets
    """

    COMMENT_TAG = "agentic-governance"
    CHAIN       = "INPUT"

    def __init__(self):
        self._blocked: set = set()
        self._lock = threading.Lock()
        self._iptables_available = self._check_iptables()

    def _check_iptables(self) -> bool:
        try:
            subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, check=True, timeout=5
            )
            return True
        except Exception as e:
            log.warning(f"[IPBlocker] iptables unavailable — blocking is logged only: {e}")
            return False

    def _run(self, args: List[str]) -> bool:
        try:
            result = subprocess.run(
                ["iptables"] + args,
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                log.debug(f"[IPBlocker] iptables {' '.join(args)} → {result.stderr.decode().strip()}")
            return result.returncode == 0
        except Exception as e:
            log.error(f"[IPBlocker] iptables error: {e}")
            return False

    def block(self, ip_or_subnet: str, duration_sec: int = 3600) -> bool:
        """Block an IP or subnet.  Returns True if the rule was inserted."""
        with self._lock:
            if ip_or_subnet in self._blocked:
                return True   # already blocked

            log.warning(f"[IPBlocker] BLOCKING {ip_or_subnet} for {duration_sec}s")

            if self._iptables_available:
                ok = self._run([
                    "-I", self.CHAIN, "1",
                    "-s", ip_or_subnet,
                    "-j", "DROP",
                    "-m", "comment", "--comment", self.COMMENT_TAG,
                ])
            else:
                ok = True  # log-only mode

            if ok:
                self._blocked.add(ip_or_subnet)
                # Schedule automatic unblock
                if duration_sec > 0:
                    threading.Timer(duration_sec, self.unblock, args=[ip_or_subnet]).start()
            return ok

    def unblock(self, ip_or_subnet: str) -> bool:
        with self._lock:
            if ip_or_subnet not in self._blocked:
                return True

            log.info(f"[IPBlocker] Unblocking {ip_or_subnet}")
            if self._iptables_available:
                self._run([
                    "-D", self.CHAIN,
                    "-s", ip_or_subnet,
                    "-j", "DROP",
                    "-m", "comment", "--comment", self.COMMENT_TAG,
                ])
            self._blocked.discard(ip_or_subnet)
            return True

    def flush(self):
        """Remove all rules we inserted — called on shutdown."""
        log.info("[IPBlocker] Flushing all blocked IPs")
        for ip in list(self._blocked):
            self.unblock(ip)

    def list_blocked(self) -> set:
        with self._lock:
            return set(self._blocked)


# Singleton — shared across bridge and dashboard
ip_blocker = IPBlocker()


# ─────────────────────────────────────────────────────────────
#  Feature extraction: raw packet → 49-dim UNSW-NB15 vector
# ─────────────────────────────────────────────────────────────

PROTO_MAP   = {"TCP": 6, "UDP": 17, "ICMP": 1, "other": 0}
SERVICE_MAP = {"http": 0, "ssh": 1, "ftp": 2, "dns": 3, "other": 4}
STATE_MAP   = {"FIN": 0, "CON": 1, "REQ": 2, "RST": 3, "other": 4}

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 5900, 6379, 27017, 3306, 5432, 1433, 8080}
SCAN_PORTS       = {80, 443, 22, 21, 25, 110, 143, 3306, 5432}


def _service_from_port(port: int) -> str:
    return {80: "http", 443: "http", 22: "ssh", 21: "ftp", 53: "dns"}.get(port, "other")


def make_feature_vector(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    proto: str,
    duration: float,
    src_bytes: int, dst_bytes: int,
    src_pkts: int, dst_pkts: int,
    state: str = "CON",
    extra_flags: Dict = None,
) -> np.ndarray:
    ef = extra_flags or {}
    vec = np.zeros(49, dtype=np.float32)

    vec[0]  = PROTO_MAP.get(proto.upper(), 0)
    vec[1]  = duration
    vec[2]  = float(src_bytes)
    vec[3]  = float(dst_bytes)
    vec[4]  = float(src_pkts)
    vec[5]  = float(dst_pkts)
    vec[6]  = src_bytes / max(src_pkts, 1)
    vec[7]  = dst_bytes / max(dst_pkts, 1)
    vec[8]  = SERVICE_MAP.get(_service_from_port(dst_port), 4)
    vec[9]  = STATE_MAP.get(state, 4)

    vec[10] = float(src_port)
    vec[11] = float(dst_port)
    vec[12] = 1.0 if dst_port in SUSPICIOUS_PORTS else 0.0
    vec[13] = 1.0 if dst_port < 1024 else 0.0
    vec[14] = 1.0 if src_port > 49151 else 0.0

    vec[15] = src_bytes / max(duration, 0.001)
    vec[16] = dst_bytes / max(duration, 0.001)
    vec[17] = src_pkts / max(duration, 0.001)
    vec[18] = dst_pkts / max(duration, 0.001)
    vec[19] = float(ef.get("syn_count", 0))
    vec[20] = float(ef.get("fin_count", 0))
    vec[21] = float(ef.get("rst_count", 0))
    vec[22] = float(ef.get("ack_count", 0))
    vec[23] = float(ef.get("urg_count", 0))
    vec[24] = float(ef.get("psh_count", 0))

    vec[25] = float(ef.get("conn_count", 1))
    vec[26] = float(ef.get("srv_count", 1))
    vec[27] = float(ef.get("same_srv_rate", 1.0))
    vec[28] = float(ef.get("diff_srv_rate", 0.0))
    vec[29] = float(ef.get("dst_host_count", 1))
    vec[30] = float(ef.get("dst_host_srv_count", 1))
    vec[31] = float(ef.get("dst_host_same_srv_rate", 1.0))
    vec[32] = float(ef.get("dst_host_diff_srv_rate", 0.0))
    vec[33] = float(ef.get("dst_host_serror_rate", 0.0))
    vec[34] = float(ef.get("dst_host_rerror_rate", 0.0))

    vec[35] = float(ef.get("http_method_encoded", 0))
    vec[36] = float(ef.get("http_status", 0))
    vec[37] = float(ef.get("response_body_len", 0))
    vec[38] = float(ef.get("request_body_len", 0))
    vec[39] = 1.0 if ef.get("is_scan_path", False) else 0.0
    vec[40] = 1.0 if ef.get("is_sqli_attempt", False) else 0.0
    vec[41] = 1.0 if ef.get("is_xss_attempt", False) else 0.0

    vec[42] = float(ef.get("port_scan_score", 0.0))
    vec[43] = float(ef.get("brute_force_score", 0.0))
    vec[44] = float(ef.get("ddos_score", 0.0))
    vec[45] = float(ef.get("lateral_score", 0.0))
    vec[46] = float(ef.get("exfil_score", 0.0))
    vec[47] = 1.0 if dst_port in SCAN_PORTS else 0.0
    vec[48] = float(ef.get("ttl_anomaly", 0.0))

    ranges = np.array([
        5, 3600, 1e7, 1e7, 1e5, 1e5, 1500, 1500, 4, 4,
        65535, 65535, 1, 1, 1,
        1e6, 1e6, 1e4, 1e4, 100, 100, 100, 100, 100, 100,
        512, 512, 1, 1, 512, 512, 1, 1, 1, 1,
        3, 600, 1e5, 1e5, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1,
    ], dtype=np.float32)
    vec = np.clip(vec / (ranges + 1e-9), 0.0, 1.0)
    return vec


# ─────────────────────────────────────────────────────────────
#  Flow tracker
# ─────────────────────────────────────────────────────────────

@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    start_time: float = field(default_factory=time.time)
    last_time: float  = field(default_factory=time.time)
    src_bytes: int = 0
    dst_bytes: int = 0
    src_pkts: int  = 0
    dst_pkts: int  = 0
    flags: Dict    = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.proto}"

    @property
    def duration(self) -> float:
        return self.last_time - self.start_time

    def to_network_connection(self, extra_flags: Dict = None) -> NetworkConnection:
        ef = {**self.flags, **(extra_flags or {})}
        features = make_feature_vector(
            self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.proto, self.duration,
            self.src_bytes, self.dst_bytes,
            self.src_pkts, self.dst_pkts,
            extra_flags=ef,
        )
        return NetworkConnection(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.proto,
            timestamp=self.start_time,
            duration=max(self.duration, 0.001),
            src_bytes=self.src_bytes,
            dst_bytes=self.dst_bytes,
            src_pkts=self.src_pkts,
            dst_pkts=self.dst_pkts,
            features=features,
        )


class FlowTracker:
    FLOW_TIMEOUT = 30.0

    def __init__(self, output_queue: queue.Queue):
        self.flows: Dict[str, Flow] = {}
        self.out = output_queue
        self._lock = threading.Lock()
        self._ip_conn_count: Dict[str, int] = defaultdict(int)
        self._ip_port_set:   Dict[str, set] = defaultdict(set)

    def update(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               proto: str, pkt_len: int, flags: Dict = None):
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        now = time.time()
        with self._lock:
            if key not in self.flows:
                self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto, now, now)
                self._ip_conn_count[src_ip] += 1
                self._ip_port_set[src_ip].add(dst_port)
            f = self.flows[key]
            f.last_time = now
            f.src_pkts += 1
            f.src_bytes += pkt_len
            if flags:
                for k, v in flags.items():
                    f.flags[k] = f.flags.get(k, 0) + v

    def evict_old(self):
        cutoff = time.time() - self.FLOW_TIMEOUT
        with self._lock:
            done = [k for k, f in self.flows.items() if f.last_time < cutoff]
            for k in done:
                f = self.flows.pop(k)
                extra = {
                    "conn_count":        self._ip_conn_count[f.src_ip],
                    "port_scan_score":   min(len(self._ip_port_set[f.src_ip]) / 5.0, 1.0),
                    "ddos_score":        min(self._ip_conn_count[f.src_ip] / 50.0, 1.0),
                    "brute_force_score": 1.0 if f.dst_port in {22, 3389, 21} and
                                         self._ip_conn_count[f.src_ip] > 3 else 0.0,
                }
                self.out.put(f.to_network_connection(extra))


# ─────────────────────────────────────────────────────────────
#  Source 1: Packet capture (Scapy)
# ─────────────────────────────────────────────────────────────

class PacketCaptureBridge:
    def __init__(self, iface: str, output_queue: queue.Queue):
        self.iface   = iface
        self.tracker = FlowTracker(output_queue)
        self._running = False

    def _process_packet(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            proto = "other"
            src_port = dst_port = 0
            flags_dict = {}
            pkt_len = len(pkt)

            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                f = int(tcp.flags)
                flags_dict = {
                    "syn_count": 1 if f & 0x02 else 0,
                    "fin_count": 1 if f & 0x01 else 0,
                    "rst_count": 1 if f & 0x04 else 0,
                    "ack_count": 1 if f & 0x10 else 0,
                    "urg_count": 1 if f & 0x20 else 0,
                    "psh_count": 1 if f & 0x08 else 0,
                    "ttl_anomaly": 1 if ip.ttl < 10 or ip.ttl > 250 else 0,
                }
            elif pkt.haslayer(UDP):
                proto = "UDP"
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            self.tracker.update(
                ip.src, ip.dst, src_port, dst_port,
                proto, pkt_len, flags_dict
            )
        except Exception:
            pass

    def start(self):
        self._running = True
        try:
            from scapy.all import sniff
            log.info(f"[PacketCapture] Sniffing on {self.iface} (Scapy)")

            def _evict_loop():
                while self._running:
                    time.sleep(5)
                    self.tracker.evict_old()

            threading.Thread(target=_evict_loop, daemon=True).start()
            sniff(iface=self.iface, prn=self._process_packet,
                  store=False, stop_filter=lambda _: not self._running)
        except Exception as e:
            log.warning(f"[PacketCapture] Scapy unavailable ({e}), using /proc/net fallback")
            self._proc_net_fallback()

    def _proc_net_fallback(self):
        log.info("[PacketCapture] /proc/net fallback active")

        def _hex_ip(h):
            parts = [h[i:i+2] for i in range(0, 8, 2)]
            parts.reverse()
            return ".".join(str(int(p, 16)) for p in parts)

        while self._running:
            for proto_file in ["/proc/net/tcp", "/proc/net/udp"]:
                proto = proto_file.split("/")[-1].upper()
                try:
                    with open(proto_file) as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) < 4:
                                continue
                            la, ra = parts[1], parts[2]
                            li, lp = la.split(":")
                            ri, rp = ra.split(":")
                            src_ip, dst_ip = _hex_ip(li), _hex_ip(ri)
                            src_port = int(lp, 16)
                            dst_port = int(rp, 16)
                            if dst_ip in ("0.0.0.0", "127.0.0.1"):
                                continue
                            self.tracker.update(src_ip, dst_ip, src_port, dst_port, proto, 64)
                except Exception:
                    pass
            self.tracker.evict_old()
            time.sleep(2)

    def stop(self):
        self._running = False


# ─────────────────────────────────────────────────────────────
#  Source 2: Nginx log tailer
# ─────────────────────────────────────────────────────────────

SCAN_PATHS   = {"/wp-login", "/phpmyadmin", "/.env", "/admin", "/.git",
                "/config", "/backup", "/shell", "/cmd", "/exec"}
SQLI_TOKENS  = {"union", "select", "drop", "insert", "update", "--", "1=1", "' or"}
XSS_TOKENS   = {"<script", "javascript:", "onerror=", "onload=", "alert("}
HTTP_METHODS = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4, "OPTIONS": 5}


class NginxLogBridge:
    def __init__(self, log_path: str, output_queue: queue.Queue):
        self.log_path = log_path
        self.out = output_queue
        self._running = False
        self._ip_req_count: Dict[str, int] = defaultdict(int)
        self._ip_req_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def _parse_line(self, line: str) -> Optional[NetworkConnection]:
        try:
            entry = json.loads(line.strip())
        except json.JSONDecodeError:
            return None

        src_ip   = entry.get("remote_addr", "0.0.0.0")
        method   = entry.get("method", "GET")
        uri      = entry.get("uri", "/")
        status   = int(entry.get("status", 200))
        bytes_s  = int(entry.get("bytes_sent", 0))
        req_len  = int(entry.get("request_length", 0))
        req_time = float(entry.get("request_time", 0.001))

        now = time.time()
        self._ip_req_count[src_ip] += 1
        self._ip_req_times[src_ip].append(now)

        uri_lower = uri.lower()
        is_scan   = any(p in uri_lower for p in SCAN_PATHS)
        is_sqli   = any(t in uri_lower for t in SQLI_TOKENS)
        is_xss    = any(t in uri_lower for t in XSS_TOKENS)

        recent = [t for t in self._ip_req_times[src_ip] if t > now - 10]
        req_rate = len(recent) / 10.0
        ddos_score = min(req_rate / 5.0, 1.0)

        ef = {
            "http_method_encoded": HTTP_METHODS.get(method.upper(), 0),
            "http_status":         status,
            "response_body_len":   bytes_s,
            "request_body_len":    req_len,
            "is_scan_path":        is_scan,
            "is_sqli_attempt":     is_sqli,
            "is_xss_attempt":      is_xss,
            "conn_count":          self._ip_req_count[src_ip],
            "ddos_score":          ddos_score,
            "brute_force_score":   1.0 if status == 401 and self._ip_req_count[src_ip] > 5 else 0.0,
            "port_scan_score":     1.0 if is_scan else 0.0,
        }

        features = make_feature_vector(
            src_ip=src_ip, dst_ip=TARGET_IP,
            src_port=0, dst_port=80,
            proto="TCP", duration=req_time,
            src_bytes=req_len, dst_bytes=bytes_s,
            src_pkts=1, dst_pkts=1,
            extra_flags=ef,
        )

        return NetworkConnection(
            src_ip=src_ip,
            dst_ip=TARGET_IP,
            src_port=0,
            dst_port=80,
            protocol="TCP",
            timestamp=now,
            duration=max(req_time, 0.001),
            src_bytes=req_len,
            dst_bytes=bytes_s,
            src_pkts=1,
            dst_pkts=1,
            features=features,
        )

    def start(self):
        self._running = True

        def tail_loop():
            log.info(f"[NginxLog] Waiting for {self.log_path}...")
            while self._running and not os.path.exists(self.log_path):
                time.sleep(2)
            log.info(f"[NginxLog] Tailing {self.log_path}")

            with open(self.log_path, "r") as f:
                f.seek(0, 2)
                while self._running:
                    line = f.readline()
                    if line:
                        conn = self._parse_line(line)
                        if conn:
                            self.out.put(conn)
                    else:
                        time.sleep(0.1)

        threading.Thread(target=tail_loop, daemon=True, name="nginx-tail").start()

    def stop(self):
        self._running = False


# ─────────────────────────────────────────────────────────────
#  Main orchestrator
# ─────────────────────────────────────────────────────────────

class RealTrafficOrchestrator:
    def __init__(self):
        self.conn_queue: queue.Queue = queue.Queue(maxsize=10_000)

        self.pkt_source = PacketCaptureBridge(IFACE, self.conn_queue)
        self.log_source = NginxLogBridge(
            os.path.join(TARGET_LOG_DIR, "access.log"),
            self.conn_queue,
        )

        self.gov = AdaptiveGovernanceSystem(config={
            "window_seconds": 60,
            "max_nodes": 512,
            "gnn_hidden": 64,
            "gnn_embed": 32,
        })

        self._running = False
        self.scanner  = None   # legacy compat
        self.store    = None   # DashStore — wired by entry point

    def start(self):
        log.info("=" * 60)
        log.info("  Real-Traffic Bridge — connecting live data to governance AI")
        log.info("=" * 60)

        self._running = True

        threading.Thread(target=self.pkt_source.start, daemon=True, name="pkt-cap").start()
        self.log_source.start()

        log.info(f"[Orchestrator] Analysis cycle every {ANALYSIS_WINDOW}s")
        self._analysis_loop()

    def _analysis_loop(self):
        while self._running:
            cycle_start = time.time()
            batch: List[NetworkConnection] = []

            while True:
                try:
                    conn = self.conn_queue.get_nowait()
                    batch.append(conn)
                    if len(batch) >= 2000:
                        break
                except queue.Empty:
                    break

            if batch:
                log.info(f"[Orchestrator] Processing {len(batch)} real connections")
                try:
                    self._run_governance(batch)
                except Exception as e:
                    log.error(f"[Orchestrator] Governance error: {e}", exc_info=True)
            else:
                log.debug("[Orchestrator] No connections this window — waiting...")

            elapsed = time.time() - cycle_start
            time.sleep(max(0.0, ANALYSIS_WINDOW - elapsed))

    def _run_governance(self, connections: List[NetworkConnection]):
        gov = self.gov

        for conn in connections:
            gov.graph_builder.ingest_connection(conn)

        node_features, adj_matrix, node_ids = gov.graph_builder.build_graph()
        if node_features.shape[0] < 2:
            log.debug("[Governance] Graph too small, skipping cycle")
            return

        gov.metrics["total_connections"] += len(connections)

        gnn_results = gov.gnn.detect_anomalies(node_features, adj_matrix, node_ids)
        dnn_results = gov.dnn.predict_batch(node_features)

        n_conns = len(connections)
        rps = n_conns / ANALYSIS_WINDOW
        traffic_snapshot = {
            "requests_per_sec": rps,
            "unique_srcs":      len(set(c.src_ip for c in connections)),
            "unique_dsts":      len(set(c.dst_ip for c in connections)),
            # normalise mean_pkt_size: large batches of small packets = flood
            "mean_pkt_size":    min(np.mean([c.src_bytes + c.dst_bytes for c in connections]) / 1500.0, 1.0),
            "syn_ratio":        float(node_features[:, 19].mean()),
            "fin_ratio":        float(node_features[:, 20].mean()),
            "rst_ratio":        float(node_features[:, 21].mean()),
            # connection rate: saturate at 200 conn/s → score 1.0
            "duration_mean":    min(rps / 200.0, 1.0),
        }
        try:
            temporal_score = gov.temporal.ingest(traffic_snapshot)
        except Exception as e:
            log.warning(f"Temporal analyzer failed: {e}")
            temporal_score = 0.1

        fusion_result = gov.fusion.fuse(
            gnn_results.get("max_score", 0),
            float(np.max(dnn_results.get("binary_scores", [0]))),
            temporal_score,
        )

        severity = fusion_result.get("severity", "NORMAL")
        fused    = fusion_result.get("fused_score", 0)

        if severity != "NORMAL":
            gov.metrics["total_threats_detected"] += 1
            log.warning(
                f"[THREAT] severity={severity} fused={fused:.3f} "
                f"anomalous_nodes={gnn_results.get('anomalous_nodes', [])[:3]}"
            )

        # ── Push connections into DashStore (no lock contention) ──
        if self.store:
            self.store.ingest_connections(connections)

        # Find real top attacker IP from connection batch
        # (GNN often returns "unknown" — fall back to most frequent src IP)
        from collections import Counter
        src_counts = Counter(
            c.src_ip for c in connections
            if c.src_ip not in (TARGET_IP, "0.0.0.0", "unknown", "")
            and c.src_ip not in IP_WHITELIST
        )
        top_attacker = src_counts.most_common(1)[0][0] if src_counts else None

        event = gov.monitor.observe(gnn_results, dnn_results, temporal_score, fusion_result)
        if event:
            # Patch source_ip if GNN returned unknown
            if event.source_ip in ("unknown", "", None) and top_attacker:
                event.source_ip = top_attacker

            event = gov.threat_analyst.analyze(event, gov.monitor.get_temporal_context(),
                                                system_logs={})
            actions = gov.responder.execute(event)
            gov.governor.process_actions(event, actions)

            # Push threat event into DashStore
            if self.store:
                self.store.ingest_threat(event, actions)

            # ── AUTO-BLOCK: fire immediately for HIGH / CRITICAL threats ──────
            # Does NOT depend on the agent's action type — if the AI says HIGH
            # or CRITICAL, the attacker IP is blocked automatically regardless.
            # Respects the dashboard toggle (DashboardServer.auto_block_enabled).
            from agentic_governance.realtime.dashboard import DashboardServer as _DS
            # Auto-block fires at fused_score >= 0.45 OR HIGH/CRITICAL level
            AUTO_BLOCK_LEVELS = {"MEDIUM", "HIGH", "CRITICAL"}
            if (_DS.auto_block_enabled
                    and (event.threat_level.name in AUTO_BLOCK_LEVELS
                         or event.fused_score >= 0.45)
                    and top_attacker
                    and top_attacker not in IP_WHITELIST):
                ok = ip_blocker.block(top_attacker, duration_sec=3600)
                if self.store:
                    self.store.mark_blocked(top_attacker)
                    self.store.mark_auto_blocked(top_attacker, event.threat_level.name)
                log.warning(
                    f"[AUTO-BLOCK] {top_attacker} level={event.threat_level.name} "
                    f"score={event.fused_score:.3f} "
                    f"iptables={'applied' if ok else 'log-only'}"
                )

            # ── ACTION-DRIVEN BLOCK: agent-selected firewall actions ──────────
            # These fire at any severity level when the RL agent picks a block action.
            from agentic_governance.agents.multi_agent import ActionType
            for action in actions:
                if action.action_type in (ActionType.BLOCK_IP_RANGE,
                                          ActionType.FIREWALL_UPDATE,
                                          ActionType.QUARANTINE_HOST):
                    block_ip = action.target
                    if block_ip in ("unknown", "", None) and top_attacker:
                        block_ip = top_attacker
                    if block_ip and block_ip not in ("unknown", "", None) and block_ip not in IP_WHITELIST:
                        ok = ip_blocker.block(block_ip, duration_sec=3600)
                        if self.store:
                            self.store.mark_blocked(block_ip)
                        log.warning(
                            f"[BLOCK] {block_ip} action={action.action_type.value} "
                            f"iptables={'applied' if ok else 'log-only'}"
                        )


# ─────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import threading
    from http.server import ThreadingHTTPServer
    from agentic_governance.realtime.dashboard import DashboardServer, DashStore

    # ── Shared data store (no RealTimeNetworkScanner, no lock deadlock) ──
    store = DashStore()
    DashboardServer.store      = store
    DashboardServer.ip_blocker = ip_blocker

    # ── Governance orchestrator → background thread ───────────────
    orch       = RealTrafficOrchestrator()
    orch.store = store                  # wire store into orchestrator
    gov_thread = threading.Thread(target=orch.start, daemon=True, name="gov")
    gov_thread.start()
    log.info("[Bridge] Governance loop started in background thread")

    # ── HTTP server → main thread (never blocked by analysis loop) ─
    log.info(f"[Dashboard] Serving on http://0.0.0.0:{DASHBOARD_PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardServer)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        orch._running = False
        ip_blocker.flush()
        server.shutdown()
