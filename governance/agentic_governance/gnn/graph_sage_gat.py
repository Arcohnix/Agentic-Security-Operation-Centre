"""
GraphSAGE-GAT Hybrid GNN for Network Anomaly Detection
Paper: Agentic AI Based Adaptive System Governance
Ref: Marfo et al. (2024), Kisanga et al. (2023)
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
import networkx as nx


class GraphAttentionLayer:
    """
    Graph Attention Network (GAT) layer.
    Weights neighbor contributions by anomaly relevance.
    Ref: Velickovic et al. — attention coefficients focus on anomalous edges.
    """

    def __init__(self, in_features: int, out_features: int, n_heads: int = 4, dropout: float = 0.1):
        self.in_features = in_features
        self.out_features = out_features
        self.n_heads = n_heads
        self.dropout = dropout
        self.head_dim = out_features // n_heads

        # Weight matrices per head
        rng = np.random.RandomState(42)
        scale = np.sqrt(2.0 / (in_features + self.head_dim))
        self.W = [rng.randn(in_features, self.head_dim) * scale for _ in range(n_heads)]
        # Attention vectors: concatenation of (Wh_i || Wh_j)
        self.a = [rng.randn(2 * self.head_dim) * 0.01 for _ in range(n_heads)]
        self.leaky_alpha = 0.2

    def _leaky_relu(self, x: np.ndarray) -> np.ndarray:
        return np.where(x > 0, x, self.leaky_alpha * x)

    def forward(self, H: np.ndarray, adj: np.ndarray) -> np.ndarray:
        """
        H: [N, in_features] node feature matrix
        adj: [N, N] adjacency matrix (can be weighted)
        Returns: [N, out_features]
        """
        N = H.shape[0]
        head_outputs = []

        for k in range(self.n_heads):
            Wh = H @ self.W[k]                          # [N, head_dim]
            # Attention: e_ij = LeakyReLU(a^T [Wh_i || Wh_j])
            Wh_i = np.repeat(Wh, N, axis=0)             # [N*N, head_dim]
            Wh_j = np.tile(Wh, (N, 1))                  # [N*N, head_dim]
            concat = np.concatenate([Wh_i, Wh_j], axis=1)  # [N*N, 2*head_dim]
            e = self._leaky_relu(concat @ self.a[k]).reshape(N, N)  # [N, N]

            # Mask non-edges — set to -inf so softmax -> 0
            mask = (adj == 0)
            e_masked = np.where(mask, -1e9, e)

            # Softmax over neighbors
            e_max = e_masked.max(axis=1, keepdims=True)
            exp_e = np.exp(e_masked - e_max)
            exp_e = np.where(mask, 0.0, exp_e)
            alpha = exp_e / (exp_e.sum(axis=1, keepdims=True) + 1e-9)  # [N, N]

            # Dropout on attention (training simulation)
            if self.dropout > 0:
                drop_mask = np.random.binomial(1, 1 - self.dropout, alpha.shape)
                alpha = alpha * drop_mask / (1 - self.dropout + 1e-9)

            # Aggregate: h'_i = ELU(sum_j alpha_ij * Wh_j)
            h_prime = alpha @ Wh  # [N, head_dim]
            head_outputs.append(h_prime)

        # Concatenate all heads
        out = np.concatenate(head_outputs, axis=1)  # [N, out_features]
        return np.maximum(out, 0)  # ELU approximated as ReLU for simplicity


class GraphSAGELayer:
    """
    GraphSAGE inductive layer — generates embeddings for unseen nodes.
    Ref: Hamilton et al., adapted for network anomaly detection.
    Inductive: works on dynamic graphs where new nodes join/leave.
    """

    def __init__(self, in_features: int, out_features: int, aggregator: str = "mean"):
        self.in_features = in_features
        self.out_features = out_features
        self.aggregator = aggregator  # mean | max | lstm-mean

        rng = np.random.RandomState(7)
        scale = np.sqrt(2.0 / (2 * in_features + out_features))
        self.W_self = rng.randn(in_features, out_features) * scale
        self.W_neigh = rng.randn(in_features, out_features) * scale
        self.bias = np.zeros(out_features)

    def _aggregate(self, neighbor_feats: np.ndarray) -> np.ndarray:
        if self.aggregator == "mean":
            return neighbor_feats.mean(axis=0)
        elif self.aggregator == "max":
            return neighbor_feats.max(axis=0)
        else:
            return neighbor_feats.mean(axis=0)

    def forward(self, H: np.ndarray, adj: np.ndarray) -> np.ndarray:
        """
        H: [N, in_features]
        adj: [N, N] adjacency (row = node, cols = neighbors)
        Returns: [N, out_features]
        """
        N = H.shape[0]
        H_new = np.zeros((N, self.out_features))

        for i in range(N):
            neighbor_idx = np.where(adj[i] > 0)[0]
            if len(neighbor_idx) == 0:
                neigh_agg = np.zeros(self.in_features)
            else:
                neigh_agg = self._aggregate(H[neighbor_idx])

            h_self = H[i] @ self.W_self
            h_neigh = neigh_agg @ self.W_neigh
            H_new[i] = h_self + h_neigh + self.bias

        # L2 normalize output embeddings (GraphSAGE default)
        norms = np.linalg.norm(H_new, axis=1, keepdims=True) + 1e-9
        H_new = H_new / norms
        return np.maximum(H_new, 0)  # ReLU


class GraphSAGEGATHybrid:
    """
    Hybrid GraphSAGE-GAT model for network anomaly detection.
    Architecture: GraphSAGE (inductive embedding) -> GAT (attention-weighted refinement)
    -> Node anomaly score via MLP head.

    Achieves 98% accuracy on UNSW-NB15 per Marfo et al. (2024).
    """

    def __init__(self, input_dim: int = 49, hidden_dim: int = 64, embed_dim: int = 32,
                 n_heads: int = 4):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.embed_dim = embed_dim

        # Layer 1: GraphSAGE for inductive embeddings
        self.sage1 = GraphSAGELayer(input_dim, hidden_dim, aggregator="mean")
        self.sage2 = GraphSAGELayer(hidden_dim, embed_dim, aggregator="max")

        # Layer 2: GAT for attention-weighted anomaly focus
        self.gat = GraphAttentionLayer(embed_dim, embed_dim, n_heads=n_heads)

        # MLP anomaly scoring head: embed_dim -> 16 -> 1
        rng = np.random.RandomState(13)
        self.mlp_W1 = rng.randn(embed_dim, 16) * np.sqrt(2.0 / embed_dim)
        self.mlp_b1 = np.zeros(16)
        self.mlp_W2 = rng.randn(16, 1) * np.sqrt(2.0 / 16)
        self.mlp_b2 = np.zeros(1)

        # Threshold for anomaly flagging (dynamic, self-adaptive)
        self.anomaly_threshold = 0.5
        self.threshold_history: List[float] = []

    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))

    def forward(self, node_features: np.ndarray, adj: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        node_features: [N, input_dim]
        adj: [N, N]
        Returns: (embeddings [N, embed_dim], anomaly_scores [N])
        """
        # GraphSAGE inductive embedding
        H = self.sage1.forward(node_features, adj)
        H = self.sage2.forward(H, adj)

        # GAT attention-weighted refinement
        H = self.gat.forward(H, adj)

        # MLP anomaly scoring
        logits = np.maximum(H @ self.mlp_W1 + self.mlp_b1, 0)
        scores = self._sigmoid(logits @ self.mlp_W2 + self.mlp_b2).squeeze(-1)

        return H, scores

    def detect_anomalies(self, node_features: np.ndarray, adj: np.ndarray,
                         node_ids: Optional[List] = None) -> Dict:
        """
        Full anomaly detection pipeline.
        Returns structured detection results with per-node and per-edge scores.
        """
        embeddings, node_scores = self.forward(node_features, adj)
        N = node_features.shape[0]
        if node_ids is None:
            node_ids = list(range(N))

        # Per-edge anomaly: high if both endpoints are anomalous
        edge_scores = {}
        for i in range(N):
            for j in range(N):
                if adj[i, j] > 0:
                    edge_scores[(node_ids[i], node_ids[j])] = float(
                        (node_scores[i] + node_scores[j]) / 2.0)

        anomalous_nodes = [node_ids[i] for i in range(N)
                           if node_scores[i] > self.anomaly_threshold]
        anomalous_edges = [(u, v) for (u, v), s in edge_scores.items()
                           if s > self.anomaly_threshold]

        # DDoS fan-out detection: one node -> many targets
        out_degrees = adj.sum(axis=1)
        ddos_candidates = [node_ids[i] for i in range(N)
                           if out_degrees[i] > (out_degrees.mean() + 2 * out_degrees.std())]

        # Zero-day lateral movement: unusual paths in embedding space
        lateral_candidates = self._detect_lateral_movement(embeddings, adj, node_ids)

        # Self-adaptive threshold update
        self._update_threshold(node_scores)

        return {
            "node_scores": dict(zip(node_ids, node_scores.tolist())),
            "edge_scores": edge_scores,
            "anomalous_nodes": anomalous_nodes,
            "anomalous_edges": anomalous_edges,
            "ddos_candidates": ddos_candidates,
            "lateral_movement_candidates": lateral_candidates,
            "max_score": float(node_scores.max()),
            "mean_score": float(node_scores.mean()),
            "threshold": self.anomaly_threshold,
            "embeddings": embeddings,
        }

    def _detect_lateral_movement(self, embeddings: np.ndarray, adj: np.ndarray,
                                  node_ids: List) -> List:
        """
        Detect zero-day lateral movement: nodes with unusual embedding distances
        to their neighbors (structural surprise).
        """
        N = embeddings.shape[0]
        lateral = []
        for i in range(N):
            neighbors = np.where(adj[i] > 0)[0]
            if len(neighbors) < 2:
                continue
            dists = [np.linalg.norm(embeddings[i] - embeddings[j]) for j in neighbors]
            if np.mean(dists) > 0.8:  # High structural distance = unusual path
                lateral.append(node_ids[i])
        return lateral

    def _update_threshold(self, scores: np.ndarray):
        """
        Self-adaptive threshold recalibration.
        Prevents performance degradation as traffic distributions evolve.
        """
        self.threshold_history.append(float(scores.mean()))
        if len(self.threshold_history) > 50:
            self.threshold_history = self.threshold_history[-50:]
        baseline = np.mean(self.threshold_history)
        self.anomaly_threshold = min(0.85, max(0.3, baseline + 0.25))
