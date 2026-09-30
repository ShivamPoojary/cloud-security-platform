"""Correlation Graph and Connected-Component Clustering.

Implements graph-based temporal and entity correlation for security alerts and
behavioral anomalies across the 60-minute sliding window.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Set, Tuple, Any, Optional
from collections import defaultdict, deque

# Non-correlatable generic IP addresses
IGNORED_GENERIC_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "unknown"}

# Maximum sliding correlation window in seconds (60 minutes)
MAX_CORRELATION_WINDOW_SECONDS = 3600


class CorrelationNode:
    """Represents an individual detection or anomaly node in the correlation graph."""

    def __init__(
        self,
        node_id: str,
        node_type: str,  # 'DETECTION' or 'ML_ANOMALY'
        record_id: uuid.UUID,
        event_id: uuid.UUID,
        timestamp: datetime,
        record: Any,
        normalized_event: Any,
    ):
        self.node_id = node_id
        self.node_type = node_type
        self.record_id = record_id
        self.event_id = event_id
        self.timestamp = timestamp
        self.record = record
        self.normalized_event = normalized_event
        self.entity_keys: Set[Tuple[str, str]] = self._extract_entity_keys(normalized_event)

    @staticmethod
    def _extract_entity_keys(event: Any) -> Set[Tuple[str, str]]:
        """Extracts valid, non-null, normalized correlation keys from a normalized event."""
        keys: Set[Tuple[str, str]] = set()
        if not event:
            return keys

        # 1. Principal Name
        p_name = getattr(event, "principal_name", None)
        if p_name and str(p_name).strip():
            clean_name = str(p_name).strip().lower()
            if clean_name not in ("none", "null", "unknown", ""):
                keys.add(("principal_name", clean_name))

        # 2. Principal ID / Object ID
        p_id = getattr(event, "principal_id", None)
        if p_id and str(p_id).strip():
            clean_id = str(p_id).strip().lower()
            if clean_id not in ("none", "null", "unknown", ""):
                keys.add(("principal_id", clean_id))

        # 3. Caller IP (ignoring local/generic IPs)
        ip = getattr(event, "caller_ip", None)
        if ip and str(ip).strip():
            clean_ip = str(ip).strip().lower()
            if clean_ip not in IGNORED_GENERIC_IPS and clean_ip not in ("none", "null", ""):
                keys.add(("caller_ip", clean_ip))

        # 4. Target Resource ID
        res_id = getattr(event, "target_resource_id", None)
        if res_id and str(res_id).strip():
            clean_res_id = str(res_id).strip().lower()
            if clean_res_id not in ("none", "null", "unknown", ""):
                keys.add(("target_resource_id", clean_res_id))

        # 5. Target Resource Name
        res_name = getattr(event, "target_resource_name", None)
        if res_name and str(res_name).strip():
            clean_res_name = str(res_name).strip().lower()
            if clean_res_name not in ("none", "null", "unknown", ""):
                keys.add(("target_resource_name", clean_res_name))

        return keys

    def shares_entity_with(self, other: "CorrelationNode") -> bool:
        """Determines if two nodes share at least one valid correlation entity.

        Safety guard: A shared caller_ip alone will not connect two events if both have
        explicitly different principals AND different target resources, avoiding false
        clustering from common proxies or shared NAT gateways.
        """
        shared = self.entity_keys.intersection(other.entity_keys)
        if not shared:
            return False

        shared_key_types = {k for k, _ in shared}
        if shared_key_types == {"caller_ip"}:
            self_principals = {v for k, v in self.entity_keys if k in ("principal_name", "principal_id")}
            other_principals = {v for k, v in other.entity_keys if k in ("principal_name", "principal_id")}
            self_resources = {v for k, v in self.entity_keys if k in ("target_resource_id", "target_resource_name")}
            other_resources = {v for k, v in other.entity_keys if k in ("target_resource_id", "target_resource_name")}

            # If both have explicit different principals and no shared resource, IP alone is insufficient
            if (
                self_principals
                and other_principals
                and not self_principals.intersection(other_principals)
                and not self_resources.intersection(other_resources)
            ):
                return False

        return True

    def temporal_distance_seconds(self, other: "CorrelationNode") -> float:
        """Calculates absolute temporal distance in seconds."""
        t1 = self.timestamp.timestamp() if hasattr(self.timestamp, "timestamp") else 0.0
        t2 = other.timestamp.timestamp() if hasattr(other.timestamp, "timestamp") else 0.0
        return abs(t1 - t2)


class CorrelationGraph:
    """Undirected correlation graph performing connected-component clustering."""

    def __init__(self, window_seconds: int = MAX_CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.nodes: Dict[str, CorrelationNode] = {}
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, node: CorrelationNode):
        """Adds a correlation node to the graph."""
        self.nodes[node.node_id] = node
        _ = self.adjacency[node.node_id]

    def build_edges(self):
        """Builds edges between nodes satisfying both entity overlap and temporal constraints."""
        node_list = sorted(self.nodes.values(), key=lambda n: n.timestamp)
        n = len(node_list)

        for i in range(n):
            node_a = node_list[i]
            for j in range(i + 1, n):
                node_b = node_list[j]

                # Stop early if temporal difference exceeds window (nodes are sorted chronologically)
                time_diff = node_b.timestamp.timestamp() - node_a.timestamp.timestamp()
                if time_diff > self.window_seconds:
                    break

                # Check entity key intersection with proxy safety guard
                if node_a.shares_entity_with(node_b):
                    self.adjacency[node_a.node_id].add(node_b.node_id)
                    self.adjacency[node_b.node_id].add(node_a.node_id)

    def get_connected_components(self) -> List[List[CorrelationNode]]:
        """Finds all connected components via Breadth-First Search (BFS).

        Returns components sorted deterministically, with nodes in each component
        ordered chronologically by timestamp.
        """
        self.build_edges()
        visited: Set[str] = set()
        components: List[List[CorrelationNode]] = []

        # Sort node keys for deterministic iteration order
        sorted_node_ids = sorted(
            self.nodes.keys(),
            key=lambda nid: (self.nodes[nid].timestamp, str(self.nodes[nid].record_id)),
        )

        for node_id in sorted_node_ids:
            if node_id in visited:
                continue

            # BFS traversal for current component
            component_nodes: List[CorrelationNode] = []
            queue = deque([node_id])
            visited.add(node_id)

            while queue:
                current_id = queue.popleft()
                component_nodes.append(self.nodes[current_id])

                for neighbor_id in self.adjacency[current_id]:
                    if neighbor_id not in visited:
                        visited.add(neighbor_id)
                        queue.append(neighbor_id)

            # Sort nodes inside component chronologically
            component_nodes.sort(
                key=lambda n: (n.timestamp, str(n.record_id))
            )
            components.append(component_nodes)

        # Sort components by earliest event timestamp
        components.sort(
            key=lambda c: (c[0].timestamp, len(c)),
            reverse=True,
        )
        return components
