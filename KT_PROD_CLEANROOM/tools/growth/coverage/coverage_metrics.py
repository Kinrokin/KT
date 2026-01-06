from __future__ import annotations

"""
Coverage metrics helper.

Computes observed coverage from:
- executed_step_ids: ordered execution truth (e.g., trace events)
- step_tag_index: mapping of step_id -> tags dict
- ontology graph (optional) for graph distance

Fail-closed posture is handled at the caller/validator; this module provides
best-effort metrics and leaves gating to the validator.
"""

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional


@dataclass
class CoverageObserved:
    domains: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    microdomains: Set[str] = field(default_factory=set)
    ventures: Set[str] = field(default_factory=set)
    reasoning_modes: Set[str] = field(default_factory=set)
    modalities: Set[str] = field(default_factory=set)
    tools: Set[str] = field(default_factory=set)

    sequence_domains: List[str] = field(default_factory=list)
    sequence_subdomains: List[str] = field(default_factory=list)

    cross_domain_edges: int = 0
    mean_graph_distance: float = 0.0
    max_graph_distance: int = 0
    paradox_events: int = 0

    top_domain_share: float = 0.0
    top_5_domain_share: float = 0.0
    entropy_domains: float = 0.0


class OntologyGraph:
    """Undirected adjacency for distance between subdomains/microdomains."""

    def __init__(self, adjacency: Dict[str, List[str]]):
        self.adj = adjacency

    def shortest_path_len(self, a: str, b: str, max_depth: int = 50) -> Optional[int]:
        if a == b:
            return 0
        if a not in self.adj or b not in self.adj:
            return None
        q = deque([(a, 0)])
        seen = {a}
        while q:
            node, d = q.popleft()
            if d >= max_depth:
                continue
            for nxt in self.adj.get(node, []):
                if nxt == b:
                    return d + 1
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, d + 1))
        return None


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / total
        ent -= p * math.log(p, 2)
    return ent


def compute_coverage(
    *,
    executed_step_ids: List[str],
    step_tag_index: Dict[str, Dict[str, List[str]]],
    ontology_subdomain_graph: Optional[OntologyGraph] = None,
    paradox_event_count: int = 0,
) -> CoverageObserved:
    obs = CoverageObserved()
    obs.paradox_events = paradox_event_count

    domain_freq = Counter()

    prev_domain = None
    prev_subdomain = None
    dist_sum = 0
    dist_n = 0
    dist_max = 0

    for step_id in executed_step_ids:
        tags = step_tag_index.get(step_id)
        if tags is None:
            continue  # caller/validator should decide if this is fatal

        for d in tags.get("domains", []):
            obs.domains.add(d)
        for s in tags.get("subdomains", []):
            obs.subdomains.add(s)
        for m in tags.get("microdomains", []):
            obs.microdomains.add(m)
        for v in tags.get("ventures", []):
            obs.ventures.add(v)
        for r in tags.get("reasoning_modes", []):
            obs.reasoning_modes.add(r)
        for x in tags.get("modalities", []):
            obs.modalities.add(x)
        for t in tags.get("tools", []):
            obs.tools.add(t)

        dom0 = (tags.get("domains") or [None])[0]
        sub0 = (tags.get("subdomains") or [None])[0]
        if dom0:
            obs.sequence_domains.append(dom0)
            domain_freq[dom0] += 1
        if sub0:
            obs.sequence_subdomains.append(sub0)

        if prev_domain and dom0 and dom0 != prev_domain:
            obs.cross_domain_edges += 1
        prev_domain = dom0 or prev_domain

        if ontology_subdomain_graph and prev_subdomain and sub0:
            dist = ontology_subdomain_graph.shortest_path_len(prev_subdomain, sub0)
            if dist is not None:
                dist_sum += dist
                dist_n += 1
                dist_max = max(dist_max, dist)
        prev_subdomain = sub0 or prev_subdomain

    total_steps = sum(domain_freq.values())
    if total_steps > 0:
        top = domain_freq.most_common(1)[0][1]
        top5 = sum(v for _, v in domain_freq.most_common(5))
        obs.top_domain_share = top / total_steps
        obs.top_5_domain_share = top5 / total_steps
        obs.entropy_domains = shannon_entropy(domain_freq)

    if dist_n > 0:
        obs.mean_graph_distance = dist_sum / dist_n
        obs.max_graph_distance = dist_max

    return obs
