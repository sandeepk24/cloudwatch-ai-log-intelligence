"""Service dependency graph construction and inference.

The graph is built from two sources (in priority order):
1. Explicit edges passed via ``known_dependencies`` in the API request.
2. Inferred edges from signal patterns (e.g., ALB always sits in front of ECS/Lambda).

The graph is used during hypothesis scoring to check whether a service's
errors could propagate to downstream callers — supporting upstream root causes.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from app.core.logging import get_logger
from app.schemas.incidents import (
    RawSignal,
    ServiceDependency,
    ServiceNode,
    SignalKind,
    SignalSeverity,
    SignalSource,
)

logger = get_logger(__name__)

ERROR_SEVERITIES = frozenset({SignalSeverity.HIGH, SignalSeverity.CRITICAL, SignalSeverity.MEDIUM})

# Prefer these sources when multiple source types emit signals for the same service_name.
# Example: an RDS cluster may also have CloudWatch alarm signals; we still want its
# primary identity/source to be RDS so topology rules (ECS/EKS/Lambda → RDS) apply.
_SOURCE_PRIORITY: dict[SignalSource, int] = {
    SignalSource.RDS: 100,
    SignalSource.ECS: 90,
    SignalSource.EKS: 90,
    SignalSource.LAMBDA: 90,
    SignalSource.ALB: 80,
    SignalSource.EC2: 70,
    SignalSource.CLOUDWATCH_ALARM: 10,
    SignalSource.UNKNOWN: 0,
}

# ── Default topology assumptions ──────────────────────────────────────────────
# These represent common AWS patterns; explicit edges override them.
#
# Format: (upstream_source, downstream_source, dependency_type)
_DEFAULT_TOPOLOGY: list[tuple[SignalSource, SignalSource, str]] = [
    (SignalSource.ALB, SignalSource.ECS, "synchronous"),
    (SignalSource.ALB, SignalSource.LAMBDA, "synchronous"),
    (SignalSource.ECS, SignalSource.RDS, "database"),
    (SignalSource.EKS, SignalSource.RDS, "database"),
    (SignalSource.LAMBDA, SignalSource.RDS, "database"),
    (SignalSource.ECS, SignalSource.EKS, "synchronous"),
]


def build_service_graph(
    signals: list[RawSignal],
    known_deps: list[dict[str, str]] | None = None,
) -> tuple[list[ServiceNode], list[ServiceDependency]]:
    """Build ServiceNode list and ServiceDependency edges from signals.

    Returns:
        (nodes, edges) where nodes are all observed services and edges are
        the dependency relationships between them.
    """
    # Collect per-service signal statistics
    service_signals: dict[str, list[RawSignal]] = defaultdict(list)
    service_source_votes: dict[str, Counter[SignalSource]] = defaultdict(Counter)

    for sig in signals:
        service_signals[sig.service_name].append(sig)
        service_source_votes[sig.service_name][sig.source] += 1

    # Decide a single primary source per service_name.
    # Tie-breaker is source priority (e.g., RDS beats CLOUDWATCH_ALARM).
    service_source: dict[str, SignalSource] = {}
    for svc, votes in service_source_votes.items():
        if not votes:
            service_source[svc] = SignalSource.UNKNOWN
            continue
        service_source[svc] = max(
            votes.items(),
            key=lambda kv: (kv[1], _SOURCE_PRIORITY.get(kv[0], 0)),
        )[0]

    nodes: list[ServiceNode] = []
    for svc_name, svc_signals in service_signals.items():
        error_signals = [s for s in svc_signals if s.severity in ERROR_SEVERITIES]
        deploy_signals = [
            s for s in svc_signals if s.kind == SignalKind.ECS_DEPLOYMENT_EVENT
        ]

        node = ServiceNode(
            name=svc_name,
            source=service_source[svc_name],
            signal_count=len(svc_signals),
            error_signal_count=len(error_signals),
        )

        if error_signals:
            node.first_error_at = min(s.timestamp for s in error_signals)
            node.last_error_at = max(s.timestamp for s in error_signals)
            node.error_signal_ids = [s.signal_id for s in error_signals]

        if deploy_signals:
            latest_deploy = max(deploy_signals, key=lambda s: s.timestamp)
            node.deployment_version = latest_deploy.deployment_version
            node.deployment_at = latest_deploy.timestamp

        nodes.append(node)

    # Build dependency edges
    edges = _build_edges(service_source, known_deps or [])

    return nodes, edges


def _build_edges(
    service_source: dict[str, SignalSource],
    known_deps: list[dict[str, str]],
) -> list[ServiceDependency]:
    """Build dependency edges from explicit deps and topology inference."""
    edges: list[ServiceDependency] = []
    seen: set[tuple[str, str]] = set()

    def add_edge(upstream: str, downstream: str, dep_type: str = "synchronous") -> None:
        key = (upstream, downstream)
        if key not in seen:
            seen.add(key)
            edges.append(
                ServiceDependency(
                    upstream=upstream,
                    downstream=downstream,
                    dependency_type=dep_type,
                )
            )

    # 1. Explicit user-provided edges
    for dep in known_deps:
        upstream = dep.get("upstream", dep.get("caller", ""))
        downstream = dep.get("downstream", dep.get("callee", ""))
        dep_type = dep.get("type", dep.get("dependency_type", "synchronous"))
        if upstream and downstream:
            add_edge(upstream, downstream, dep_type)

    # 2. Topology-based inference
    # Group services by source type
    source_to_services: dict[SignalSource, list[str]] = defaultdict(list)
    for svc, src in service_source.items():
        source_to_services[src].append(svc)

    for upstream_src, downstream_src, dep_type in _DEFAULT_TOPOLOGY:
        for up_svc in source_to_services.get(upstream_src, []):
            for dn_svc in source_to_services.get(downstream_src, []):
                if up_svc != dn_svc:
                    add_edge(up_svc, dn_svc, dep_type)

    return edges


def get_upstream_services(
    service: str,
    edges: list[ServiceDependency],
) -> list[str]:
    """Return services that call INTO the given service (i.e., callers)."""
    return [e.upstream for e in edges if e.downstream == service]


def get_downstream_services(
    service: str,
    edges: list[ServiceDependency],
) -> list[str]:
    """Return services that the given service depends on (i.e., callees)."""
    return [e.downstream for e in edges if e.upstream == service]


def can_propagate_to(
    source_service: str,
    target_service: str,
    edges: list[ServiceDependency],
    max_depth: int = 5,
) -> bool:
    """Return True if errors in source_service could propagate to target_service.

    Follows the dependency graph downstream (source is upstream of target).
    """
    if source_service == target_service:
        return True

    visited: set[str] = set()
    # Track depth explicitly; do NOT use visited size as a depth proxy, because
    # fan-out graphs can visit many nodes at shallow depth.
    queue: list[tuple[str, int]] = [(source_service, 0)]

    while queue:
        current, depth = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        if current == target_service:
            return True

        if depth >= max_depth:
            continue

        for nxt in get_downstream_services(current, edges):
            if nxt not in visited:
                queue.append((nxt, depth + 1))

    return False
