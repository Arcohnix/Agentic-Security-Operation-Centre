"""
Network Graph Builder — FIXED
Transforms raw UNSW-NB15 network traffic records into dynamic graph representations.
Nodes = network entities, Directed edges = annotated communications.
Sliding temporal window maintains current network snapshot.

FIXES:
  - Removed duplicate @dataclass decorator on NetworkConnection
  - Removed stray `label` / `attack_cat` fields from NetworkConnection
    (those only exist in UNSWNBSimulator generated data; real traffic doesn't have them)
  - UNSWNBSimulator.generate_* methods no longer pass unknown kwargs
"""

import numpy as np
import networkx as nx
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
import time


# ── BUG FIX: removed duplicate @dataclass decorator ──────────────
@dataclass
class NetworkConnection:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float
    duration: float
    src_bytes: int
    dst_bytes: int
    src_pkts: int
    dst_pkts: int
    tcp_flags: int = 0
    features: np.ndarray = None

    @property
    def bytes_per_pkt(self) -> float:
        total = self.src_pkts + self.dst_pkts
        return (self.src_bytes + self.dst_bytes) / max(1, total)

    @property
    def flow_rate(self) -> float:
        return (self.src_bytes + self.dst_bytes) / max(1e-6, self.duration)


class NetworkGraphBuilder:
    """
    Converts network traffic streams into dynamic graph representations.

    Graph structure:
      - Nodes: IP addresses with aggregated feature vectors
      - Edges: Connection flows with traffic statistics
      - Window: Sliding temporal window (default 60s) for current snapshot
    """

    NODE_FEATURE_DIM = 49

    def __init__(self, window_seconds: float = 60.0, max_nodes: int = 256):
        self.window_seconds = window_seconds
        self.max_nodes = max_nodes

        self.node_index: Dict[str, int] = {}
        self.index_node: Dict[int, str] = {}
        self._next_idx = 0

        self.connection_buffer: deque = deque()

        self.node_stats: Dict[str, Dict] = defaultdict(lambda: {
            "total_bytes_out": 0.0,
            "total_bytes_in": 0.0,
            "total_pkts_out": 0,
            "total_pkts_in": 0,
            "unique_dsts": set(),
            "unique_srcs": set(),
            "unique_ports": set(),
            "protocols": defaultdict(int),
            "durations": [],
            "tcp_flags_hist": np.zeros(8),
            "connection_count": 0,
            "last_seen": 0.0,
        })

    def _get_or_create_node(self, ip: str) -> int:
        if ip not in self.node_index:
            idx = self._next_idx % self.max_nodes
            if idx in self.index_node:
                old_ip = self.index_node[idx]
                del self.node_index[old_ip]
            self.node_index[ip] = idx
            self.index_node[idx] = ip
            self._next_idx += 1
        return self.node_index[ip]

    def ingest_connection(self, conn: NetworkConnection):
        self.connection_buffer.append(conn)
        self._evict_old(conn.timestamp)
        self._update_node_stats(conn)

    def _evict_old(self, current_time: float):
        cutoff = current_time - self.window_seconds
        while self.connection_buffer and self.connection_buffer[0].timestamp < cutoff:
            self.connection_buffer.popleft()

    def _update_node_stats(self, conn: NetworkConnection):
        src = self.node_stats[conn.src_ip]
        dst = self.node_stats[conn.dst_ip]

        src["total_bytes_out"] += conn.src_bytes
        src["total_pkts_out"] += conn.src_pkts
        src["unique_dsts"].add(conn.dst_ip)
        src["unique_ports"].add(conn.dst_port)
        src["protocols"][conn.protocol] += 1
        src["durations"].append(conn.duration)
        src["connection_count"] += 1
        src["last_seen"] = conn.timestamp

        dst["total_bytes_in"] += conn.src_bytes
        dst["total_pkts_in"] += conn.dst_pkts
        dst["unique_srcs"].add(conn.src_ip)
        dst["connection_count"] += 1
        dst["last_seen"] = conn.timestamp

        for bit in range(8):
            if conn.tcp_flags & (1 << bit):
                src["tcp_flags_hist"][bit] += 1

    def _compute_node_features(self, ip: str) -> np.ndarray:
        s = self.node_stats[ip]
        feats = np.zeros(self.NODE_FEATURE_DIM)

        feats[0] = np.log1p(s["total_bytes_out"])
        feats[1] = np.log1p(s["total_bytes_in"])
        feats[2] = np.log1p(s["total_pkts_out"])
        feats[3] = np.log1p(s["total_pkts_in"])
        feats[4] = len(s["unique_dsts"])
        feats[5] = len(s["unique_srcs"])
        feats[6] = len(s["unique_ports"])
        feats[7] = s["connection_count"]

        if s["connection_count"] > 0:
            feats[8:16] = s["tcp_flags_hist"] / max(1, s["connection_count"])

        total_proto = max(1, sum(s["protocols"].values()))
        feats[16] = s["protocols"].get("tcp", 0) / total_proto
        feats[17] = s["protocols"].get("udp", 0) / total_proto
        feats[18] = s["protocols"].get("icmp", 0) / total_proto
        feats[19] = 1.0 - feats[16] - feats[17] - feats[18]

        if s["durations"]:
            durs = np.array(s["durations"])
            feats[20] = np.mean(durs)
            feats[21] = np.std(durs) if len(durs) > 1 else 0.0
            feats[22] = np.min(durs)
            feats[23] = np.max(durs)
            feats[24] = np.percentile(durs, 75) - np.percentile(durs, 25)

        total_bytes = s["total_bytes_out"] + s["total_bytes_in"] + 1e-9
        feats[25] = s["total_bytes_out"] / total_bytes
        feats[26] = s["total_bytes_in"] / total_bytes

        out_deg = len(s["unique_dsts"])
        in_deg  = len(s["unique_srcs"])
        feats[27] = out_deg / max(1, out_deg + in_deg)

        port_counts = np.ones(len(s["unique_ports"]) + 1)
        port_entropy = -np.sum(
            (port_counts / port_counts.sum()) *
            np.log2(port_counts / port_counts.sum() + 1e-9)
        )
        feats[28] = port_entropy

        return feats

    def build_graph(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        active_ips: set = set()
        for conn in self.connection_buffer:
            active_ips.add(conn.src_ip)
            active_ips.add(conn.dst_ip)

        if not active_ips:
            return np.zeros((1, self.NODE_FEATURE_DIM)), np.zeros((1, 1)), ["0.0.0.0"]

        node_ids = sorted(active_ips)
        ip_to_idx = {ip: i for i, ip in enumerate(node_ids)}
        N = len(node_ids)

        node_features = np.stack([self._compute_node_features(ip) for ip in node_ids])

        adj = np.zeros((N, N))
        for conn in self.connection_buffer:
            if conn.src_ip in ip_to_idx and conn.dst_ip in ip_to_idx:
                i = ip_to_idx[conn.src_ip]
                j = ip_to_idx[conn.dst_ip]
                weight = np.log1p(conn.src_bytes + conn.dst_bytes)
                adj[i, j] += weight

        max_w = adj.max()
        if max_w > 0:
            adj = adj / max_w

        np.fill_diagonal(adj, 1.0)

        feat_min = node_features.min(axis=0, keepdims=True)
        feat_max = node_features.max(axis=0, keepdims=True)
        feat_range = feat_max - feat_min + 1e-9
        node_features = (node_features - feat_min) / feat_range

        return node_features, adj, node_ids

    def get_graph_stats(self) -> Dict:
        return {
            "window_connections": len(self.connection_buffer),
            "active_nodes": len(set(
                [c.src_ip for c in self.connection_buffer] +
                [c.dst_ip for c in self.connection_buffer]
            )),
            "total_nodes_seen": len(self.node_index),
        }


class UNSWNBSimulator:
    """
    Simulates UNSW-NB15 traffic patterns for demo/testing.
    BUG FIX: Removed `label` and `attack_cat` kwargs — NetworkConnection doesn't have them.
    """

    ATTACK_CATEGORIES = [
        "Normal", "Exploits", "DoS", "Backdoor",
        "Fuzzers", "Generic", "Reconnaissance",
        "Shellcode", "Worms", "Analysis"
    ]

    def __init__(self, n_hosts: int = 20, rng_seed: int = 42):
        self.rng = np.random.RandomState(rng_seed)
        self.n_hosts = n_hosts
        self.hosts = [f"10.0.0.{i+1}" for i in range(n_hosts)]
        self.servers = [f"192.168.1.{i+1}" for i in range(5)]
        self.attacker_ips = [f"203.0.113.{i+1}" for i in range(10)]

    def _random_ip(self, pool: List[str]) -> str:
        return pool[self.rng.randint(0, len(pool))]

    def _random_port(self) -> int:
        common = [80, 443, 22, 21, 8080, 3306, 5432]
        if self.rng.random() < 0.3:
            return common[self.rng.randint(0, len(common))]
        return int(self.rng.randint(1024, 65535))

    def generate_normal_traffic(self, n: int = 100, base_time: float = 0.0) -> List[NetworkConnection]:
        conns = []
        for i in range(n):
            conn = NetworkConnection(
                src_ip=self._random_ip(self.hosts),
                dst_ip=self._random_ip(self.servers),
                src_port=int(self.rng.randint(1024, 65535)),
                dst_port=self._random_port(),
                protocol=self.rng.choice(["tcp", "udp"]),
                duration=float(self.rng.exponential(2.0)),
                src_bytes=int(self.rng.lognormal(7, 2)),
                dst_bytes=int(self.rng.lognormal(8, 2)),
                src_pkts=int(self.rng.randint(1, 50)),
                dst_pkts=int(self.rng.randint(1, 50)),
                tcp_flags=int(self.rng.randint(0, 255)),
                timestamp=base_time + i * 0.1,
            )
            conns.append(conn)
        return conns

    def generate_ddos_traffic(self, n: int = 200, base_time: float = 0.0) -> List[NetworkConnection]:
        target = self._random_ip(self.servers)
        conns = []
        for i in range(n):
            conn = NetworkConnection(
                src_ip=self._random_ip(self.attacker_ips),
                dst_ip=target,
                src_port=int(self.rng.randint(1024, 65535)),
                dst_port=80,
                protocol="tcp",
                duration=float(self.rng.exponential(0.05)),
                src_bytes=int(self.rng.randint(64, 1500)),
                dst_bytes=0,
                src_pkts=int(self.rng.randint(1, 5)),
                dst_pkts=0,
                tcp_flags=0b00000010,
                timestamp=base_time + i * 0.005,
            )
            conns.append(conn)
        return conns

    def generate_zeroday_lateral(self, base_time: float = 0.0) -> List[NetworkConnection]:
        conns = []
        path = self.rng.choice(self.hosts, size=min(5, self.n_hosts), replace=False).tolist()
        for step, (src, dst) in enumerate(zip(path[:-1], path[1:])):
            conn = NetworkConnection(
                src_ip=src,
                dst_ip=dst,
                src_port=int(self.rng.randint(1024, 65535)),
                dst_port=int(self.rng.choice([22, 445, 3389, 5985])),
                protocol="tcp",
                duration=float(self.rng.uniform(30, 300)),
                src_bytes=int(self.rng.randint(500, 5000)),
                dst_bytes=int(self.rng.randint(100, 2000)),
                src_pkts=int(self.rng.randint(5, 50)),
                dst_pkts=int(self.rng.randint(2, 30)),
                tcp_flags=0b00011000,
                timestamp=base_time + step * 15.0,
            )
            conns.append(conn)
        return conns
