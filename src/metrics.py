"""
Graph-Theoretic Security Metrics for O-RAN Attack-Defense Graphs.

All metrics are fundamentally based on graph algorithms that cannot
be replicated with simple tabular analysis:

1. TPRS (Topology-Propagated Risk Score): BFS + distance-decay risk spreading
2. CTI  (Cascading Threat Index): Personalized PageRank on attack graph
3. DEI  (Defense Effectiveness Index): Graph-cut analysis of defense impact
4. SPI  (Security Posture Index): Aggregated score from graph metrics
"""

import math
import networkx as nx
from collections import defaultdict

# Module-level parameter for sensitivity analysis
DEFENSE_COEFF = 0.5


def get_nodes_by_type(G, node_type):
    return [n for n, d in G.nodes(data=True) if d.get("node_type") == node_type]


def _defense_effectiveness(total_strength):
    """Diminishing-returns: 1 - 1/(1 + coeff*strength). Monotonic, absolute scale."""
    return 1 - 1 / (1 + DEFENSE_COEFF * total_strength)


def _threat_residual_risk(G, tid):
    """Residual risk after defenses: severity * likelihood * (1 - eff).

    Uses WG11 support-weighted defense strength instead of raw count.
    """
    data = G.nodes[tid]
    sev = data.get("severity", 0.5)
    lik = data.get("likelihood", 0.5)
    total_strength = sum(G.nodes[src].get("strength", 0.5)
                         for src, _, d in G.in_edges(tid, data=True)
                         if d.get("edge_type") == "mitigates")
    return sev * lik * (1 - _defense_effectiveness(total_strength))


def _build_topology_graph(G):
    """Extract undirected topology subgraph and precompute all-pairs distances."""
    topo = nx.Graph()
    for u, v, d in G.edges(data=True):
        if d.get("edge_type") == "topology":
            topo.add_edge(u, v, interface=d.get("interface", ""))
    # Ensure all assets are present even if isolated
    for n, d in G.nodes(data=True):
        if d.get("node_type") == "asset":
            topo.add_node(n)
    distances = dict(nx.all_pairs_shortest_path_length(topo))
    return topo, distances


def _build_enables_graph(G):
    """Extract directed enables subgraph among attack nodes."""
    sub = nx.DiGraph()
    attacks = get_nodes_by_type(G, "attack")
    for t in attacks:
        sub.add_node(t)
    for u, v, d in G.edges(data=True):
        if d.get("edge_type") == "enables":
            sub.add_edge(u, v)
    return sub


# =============================================================================
# Metric 1: Topology-Propagated Risk Score (TPRS)
# =============================================================================
def compute_tprs(G, decay=0.5):
    """
    Graph algorithm: BFS shortest-path + exponential distance decay.

    For each component c:
      TPRS(c) = sum over ALL threats t of:
          residual_risk(t) * max over targets(t) of: decay^dist(c, target)

    A threat targeting Near-RT RIC contributes full risk to Near-RT RIC,
    half risk to its 1-hop neighbors (SMO, Non-RT RIC, O-CU, O-DU, xApp),
    quarter risk to 2-hop neighbors, etc.

    WHY THIS NEEDS A GRAPH: The decay factor depends on shortest-path
    distance in the O-RAN topology. A spreadsheet cannot compute this
    without encoding the full topology graph.

    Returns: dict {component -> TPRS score}
    """
    assets = get_nodes_by_type(G, "asset")
    attacks = get_nodes_by_type(G, "attack")
    _, distances = _build_topology_graph(G)

    tprs = {a: 0.0 for a in assets}
    for tid in attacks:
        risk = _threat_residual_risk(G, tid)
        direct_targets = [t for _, t, d in G.out_edges(tid, data=True)
                          if d.get("edge_type") == "targets"]
        for comp in assets:
            # Best (closest) propagation from any direct target
            best_decay = 0.0
            for target in direct_targets:
                dist = distances.get(target, {}).get(comp, 99)
                best_decay = max(best_decay, decay ** dist)
            tprs[comp] += risk * best_decay

    return {k: round(v, 4) for k, v in tprs.items()}


# =============================================================================
# Metric 2: Cascading Threat Index (CTI)
# =============================================================================
def compute_cti(G, alpha=0.85):
    """
    Graph algorithm: Personalized PageRank on the attack-enables graph.

    PageRank propagates risk scores through attack chains: a threat that
    is "enabled by" many high-risk threats receives amplified importance.
    Personalization seeds each node with its raw risk score.

    WHY THIS NEEDS A GRAPH: PageRank is defined on graph structure.
    The enables edges create cascading amplification that is invisible
    in a flat threat table.

    Returns: dict {threat_id -> CTI score}
    """
    attacks = get_nodes_by_type(G, "attack")
    enables_graph = _build_enables_graph(G)

    # Personalization: seed with residual risk (defense-aware)
    personalization = {}
    for tid in enables_graph.nodes:
        personalization[tid] = max(_threat_residual_risk(G, tid), 1e-6)

    cti = nx.pagerank(enables_graph, alpha=alpha,
                      personalization=personalization, max_iter=200)

    # Normalize so scores sum to total residual risk (interpretable scale)
    total_residual = sum(personalization.values())
    total_pr = sum(cti.values())
    scale = total_residual / total_pr if total_pr > 0 else 1
    cti = {k: round(v * scale, 6) for k, v in cti.items()}

    return cti


# =============================================================================
# Metric 3: Defense Effectiveness Index (DEI)
# =============================================================================
def compute_dei(G):
    """
    Graph algorithm: Edge-cut analysis + topology reach.

    For each defense d mitigating threats {t1, t2, ...}:
      DEI(d) = sum over mitigated threats ti of:
          CTI(ti) * topology_reach(ti)

    where topology_reach(t) = number of components within 2 hops of
    any target of t, normalized by total components.

    This captures two graph-dependent factors:
    - CTI (PageRank): how important is this threat in attack chains?
    - topology_reach: how much of the network does this threat endanger?

    A defense that mitigates a high-PageRank threat on a central node
    (like Near-RT RIC, betweenness=0.34) scores much higher than one
    mitigating a peripheral threat.

    WHY THIS NEEDS A GRAPH: Both CTI (PageRank) and topology_reach
    (BFS neighborhood) are graph algorithms.

    Returns: dict {defense_id -> DEI score}
    """
    defenses = get_nodes_by_type(G, "defense")
    assets = get_nodes_by_type(G, "asset")
    n_assets = len(assets)
    cti = compute_cti(G)
    _, distances = _build_topology_graph(G)

    # Precompute topology reach for each threat
    def topology_reach(tid):
        targets = [t for _, t, d in G.out_edges(tid, data=True)
                   if d.get("edge_type") == "targets"]
        reachable = set()
        for target in targets:
            for comp, dist in distances.get(target, {}).items():
                if dist <= 2:
                    reachable.add(comp)
        return len(reachable) / n_assets if n_assets > 0 else 0

    dei = {}
    for did in defenses:
        score = 0.0
        for _, tid, d in G.out_edges(did, data=True):
            if d.get("edge_type") == "mitigates":
                score += cti.get(tid, 0) * topology_reach(tid)
        dei[did] = round(score, 6)

    return dei


# =============================================================================
# Metric 4: Security Posture Index (SPI)
# =============================================================================
def compute_spi(G):
    """
    Aggregated security score [0, 100] based on graph metrics.

    SPI = 100 * (1 - avg_normalized_TPRS)

    where normalized_TPRS(c) = TPRS(c) / TPRS_max(c),
    and TPRS_max(c) is the TPRS when there are zero defenses
    (worst case).

    Guarantees:
    - SPI=0 when no defenses exist (TPRS == TPRS_max everywhere)
    - SPI increases monotonically with more defenses
    - SPI approaches 100 with deep defense-in-depth

    Returns: float in [0, 100]
    """
    assets = get_nodes_by_type(G, "asset")
    tprs = compute_tprs(G)

    # Compute worst-case TPRS (no defenses)
    tprs_max = _compute_tprs_no_defense(G)

    weighted_norm = 0.0
    total_weight = 0.0
    for comp in assets:
        crit = G.nodes[comp].get("criticality", 0.5)
        if tprs_max[comp] > 0:
            norm = tprs[comp] / tprs_max[comp]
        else:
            norm = 0.0
        weighted_norm += crit * norm
        total_weight += crit

    avg = weighted_norm / total_weight if total_weight > 0 else 0
    return round(100 * (1 - avg), 2)


def _compute_tprs_no_defense(G, decay=0.5):
    """TPRS when all defenses are removed (worst case baseline)."""
    assets = get_nodes_by_type(G, "asset")
    attacks = get_nodes_by_type(G, "attack")
    _, distances = _build_topology_graph(G)

    tprs = {a: 0.0 for a in assets}
    for tid in attacks:
        data = G.nodes[tid]
        sev = data.get("severity", 0.5)
        lik = data.get("likelihood", 0.5)
        risk = sev * lik  # no defense = full risk

        direct_targets = [t for _, t, d in G.out_edges(tid, data=True)
                          if d.get("edge_type") == "targets"]
        for comp in assets:
            best_decay = 0.0
            for target in direct_targets:
                dist = distances.get(target, {}).get(comp, 99)
                best_decay = max(best_decay, decay ** dist)
            tprs[comp] += risk * best_decay

    return tprs


# =============================================================================
# Critical Path Analysis
# =============================================================================
def compute_critical_paths(G, top_k=20):
    """
    Graph algorithm: Weighted longest-path search on the attack DAG.

    Finds attack chains that:
    1. Cross subsystem boundaries (lateral movement)
    2. Have high cumulative PageRank-weighted risk
    3. Span the most components (high topology impact)

    Scoring: path_risk = mean(CTI) * impact_breadth * sqrt(len)

    Returns: list of (path, score, entry_targets, final_targets, all_targets)
    """
    attacks = get_nodes_by_type(G, "attack")
    assets = get_nodes_by_type(G, "asset")
    n_assets = len(assets)
    cti = compute_cti(G)
    enables_graph = _build_enables_graph(G)

    # Add cross-subsystem edges (via shared component targets + STRIDE escalation)
    _add_cross_subsystem_edges(G, enables_graph)

    # DFS from highest-CTI threats
    entry_threats = sorted(attacks, key=lambda t: cti.get(t, 0), reverse=True)[:60]

    all_paths = []
    for entry in entry_threats:
        stack = [(entry, [entry])]
        while stack:
            current, path = stack.pop()
            if len(path) >= 2:
                all_targets = set()
                for tid in path:
                    for _, t, d in G.out_edges(tid, data=True):
                        if d.get("edge_type") == "targets":
                            all_targets.add(t)
                entry_targets = {t for _, t, d in G.out_edges(path[0], data=True)
                                 if d.get("edge_type") == "targets"}
                final_targets = {t for _, t, d in G.out_edges(path[-1], data=True)
                                 if d.get("edge_type") == "targets"}
                if entry_targets and final_targets:
                    mean_cti = sum(cti.get(t, 0) for t in path) / len(path)
                    breadth = len(all_targets) / n_assets if n_assets > 0 else 0
                    score = mean_cti * breadth * math.sqrt(len(path))
                    all_paths.append((path[:], round(score, 6),
                                     entry_targets, final_targets, all_targets))

            if len(path) < 5:
                for _, nxt in enables_graph.out_edges(current):
                    if nxt not in path:
                        stack.append((nxt, path + [nxt]))

    all_paths.sort(key=lambda x: x[1], reverse=True)
    return all_paths[:top_k]


def _add_cross_subsystem_edges(G, enables_graph):
    """Add lateral-movement edges between threats sharing a target component."""
    import re
    attacks = get_nodes_by_type(G, "attack")
    enables_chain = {
        "Spoofing": {"Elevation of Privilege", "Tampering"},
        "Information Disclosure": {"Spoofing", "Tampering"},
        "Elevation of Privilege": {"Tampering", "Information Disclosure"},
        "Tampering": {"Denial of Service"},
    }

    def prefix(tid):
        m = re.match(r'(T-[A-Za-z]+-?[A-Za-z]*)', tid)
        return m.group(1) if m else tid

    comp_threats = defaultdict(list)
    for tid in attacks:
        if G.nodes[tid].get("risk_score", 0) >= 0.5:
            for _, t, d in G.out_edges(tid, data=True):
                if d.get("edge_type") == "targets":
                    comp_threats[t].append(tid)

    for comp, tids in comp_threats.items():
        for i, t1 in enumerate(tids):
            p1 = prefix(t1)
            cats1 = G.nodes[t1].get("stride_categories", [])
            if isinstance(cats1, str):
                cats1 = cats1.split(",")
            for t2 in tids[i + 1:]:
                if prefix(t2) == p1:
                    continue
                cats2 = G.nodes[t2].get("stride_categories", [])
                if isinstance(cats2, str):
                    cats2 = cats2.split(",")
                for c1 in cats1:
                    if c1 in enables_chain and enables_chain[c1] & set(cats2):
                        if not enables_graph.has_edge(t1, t2):
                            enables_graph.add_edge(t1, t2)
                        break


# =============================================================================
# Bottleneck Analysis (Betweenness Centrality)
# =============================================================================
def compute_bottlenecks(G):
    """
    Graph algorithm: Betweenness centrality on O-RAN topology.

    Components with high betweenness sit on many shortest paths —
    they are natural chokepoints where attacks converge and defenses
    should be concentrated.

    Returns: dict {component -> centrality score}
    """
    topo, _ = _build_topology_graph(G)
    return nx.betweenness_centrality(topo)


# =============================================================================
# What-if Analysis
# =============================================================================
def what_if_disable_defense(G, defense_ids):
    removed = []
    for did in defense_ids:
        for _, target, d in list(G.out_edges(did, data=True)):
            if d.get("edge_type") == "mitigates":
                removed.append((did, target, dict(d)))
                G.remove_edge(did, target)

    result = {
        "spi": compute_spi(G),
        "tprs": compute_tprs(G),
    }

    for u, v, d in removed:
        G.add_edge(u, v, **d)
    return result


def what_if_add_defense(G, threat_ids, new_defense_id="hypothetical-defense"):
    G.add_node(new_defense_id, node_type="defense", control_type="hypothetical")
    for tid in threat_ids:
        if tid in G.nodes:
            G.add_edge(new_defense_id, tid, edge_type="mitigates")

    result = {
        "spi": compute_spi(G),
        "tprs": compute_tprs(G),
    }

    G.remove_node(new_defense_id)
    return result


# =============================================================================
# Run all metrics
# =============================================================================
def run_all_metrics(G):
    print("=" * 70)
    print("Graph-Theoretic Security Posture Assessment")
    print("=" * 70)

    # --- TPRS ---
    tprs = compute_tprs(G)
    print("\n1. Topology-Propagated Risk Score (TPRS)")
    print("   [BFS + distance-decay propagation on O-RAN topology]")
    max_tprs = max(tprs.values()) if tprs else 1
    for comp, score in sorted(tprs.items(), key=lambda x: -x[1]):
        bar = "#" * int(score / max_tprs * 30)
        print(f"   {comp:15s} {score:8.2f} {bar}")

    # --- CTI ---
    cti = compute_cti(G)
    print("\n2. Cascading Threat Index (CTI) — Top 15")
    print("   [Personalized PageRank on attack-enables graph]")
    cti_sorted = sorted(cti.items(), key=lambda x: -x[1])
    for tid, score in cti_sorted[:15]:
        raw = G.nodes[tid].get("risk_score", 0.5)
        amp = score / (_threat_residual_risk(G, tid)) if _threat_residual_risk(G, tid) > 0.001 else 0
        title = G.nodes[tid].get("title", "")[:45]
        print(f"   {tid:25s} CTI={score:.4f} (raw={raw}, amp={amp:.1f}x) {title}")

    # --- Bottlenecks ---
    bottlenecks = compute_bottlenecks(G)
    print("\n3. Topology Bottleneck Analysis")
    print("   [Betweenness centrality on O-RAN network graph]")
    for comp, cent in sorted(bottlenecks.items(), key=lambda x: -x[1]):
        bar = "#" * int(cent / max(bottlenecks.values()) * 20) if max(bottlenecks.values()) > 0 else ""
        print(f"   {comp:15s} centrality={cent:.4f} {bar}")

    # --- Critical Paths ---
    paths = compute_critical_paths(G)
    print(f"\n4. Critical Attack Paths — Top 10")
    print("   [Weighted DFS on enables graph with cross-subsystem lateral movement]")
    for i, (path, score, entry_t, final_t, all_t) in enumerate(paths[:10]):
        entry_str = ",".join(sorted(entry_t)[:2])
        final_str = ",".join(sorted(final_t)[:2])
        n_comps = len(all_t)
        print(f"   [{i+1}] score={score:.4f} | {entry_str} -> {final_str} ({n_comps} components)")
        print(f"       {' -> '.join(path)}")

    # --- DEI ---
    dei = compute_dei(G)
    print(f"\n5. Defense Effectiveness Index (DEI) — Top 10")
    print("   [PageRank importance * topology reach of mitigated threats]")
    for did, score in sorted(dei.items(), key=lambda x: -x[1])[:10]:
        n_mit = sum(1 for _, _, d in G.out_edges(did, data=True)
                    if d.get("edge_type") == "mitigates")
        print(f"   {did:40s} DEI={score:.4f} ({n_mit} threats)")

    print(f"\n   Bottom 10:")
    for did, score in sorted(dei.items(), key=lambda x: x[1])[:10]:
        print(f"   {did:40s} DEI={score:.4f}")

    # --- SPI ---
    spi = compute_spi(G)
    print(f"\n6. Security Posture Index (SPI): {spi:.2f} / 100")
    if spi >= 70:
        print("   Rating: ACCEPTABLE")
    elif spi >= 40:
        print("   Rating: NEEDS IMPROVEMENT")
    else:
        print("   Rating: CRITICAL")

    return {
        "tprs": tprs,
        "cti": cti,
        "bottlenecks": bottlenecks,
        "critical_paths": paths,
        "dei": dei,
        "spi": spi,
    }


if __name__ == "__main__":
    from adg_builder import build_adg
    G = build_adg()
    run_all_metrics(G)
