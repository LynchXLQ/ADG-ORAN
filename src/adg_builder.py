"""
ADG Builder: Constructs Attack-Defense Graphs from extracted WG11 data.

Creates a NetworkX heterogeneous directed graph with:
- Asset nodes: O-RAN components (SMO, Near-RT RIC, etc.)
- Attack nodes: WG11 threats (T-xxx)
- Defense nodes: Security controls (SEC-CTL-xxx)
- Edges: topology, targets, mitigates, enables, requires
"""

import json
import re
import networkx as nx
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).parent.parent / "data"

# O-RAN topology: component -> list of (connected_component, interface)
ORAN_TOPOLOGY = {
    "SMO": [
        ("Non-RT RIC", "O1"),
        ("Near-RT RIC", "O1"),
        ("O-CU-CP", "O1"),
        ("O-CU-UP", "O1"),
        ("O-DU", "O1"),
        ("O-RU", "O1"),
        ("O-Cloud", "O2"),
    ],
    "Non-RT RIC": [
        ("Near-RT RIC", "A1"),
        ("rApp", "R1"),
        ("SMO", "O1"),
    ],
    "Near-RT RIC": [
        ("O-CU-CP", "E2"),
        ("O-CU-UP", "E2"),
        ("O-DU", "E2"),
        ("xApp", "E2-internal"),
        ("Non-RT RIC", "A1"),
    ],
    "O-CU-CP": [
        ("O-CU-UP", "E1"),
        ("O-DU", "F1"),
    ],
    "O-CU-UP": [
        ("O-CU-CP", "E1"),
    ],
    "O-DU": [
        ("O-RU", "Open-FH-CUS"),
        ("O-RU", "Open-FH-M"),
    ],
    "O-Cloud": [
        ("Near-RT RIC", "O2"),
        ("O-CU-CP", "O2"),
        ("O-CU-UP", "O2"),
        ("O-DU", "O2"),
    ],
}

# Map component name variants from specs to canonical names
COMPONENT_ALIASES = {
    "O-RU": "O-RU",
    "ORU": "O-RU",
    "O-DU": "O-DU",
    "ODU": "O-DU",
    "O-CU": "O-CU-CP",  # default to CP
    "O-CU-CP": "O-CU-CP",
    "O-CU-UP": "O-CU-UP",
    "Near-RT RIC": "Near-RT RIC",
    "Near RT RIC": "Near-RT RIC",
    "Near-RT-RIC": "Near-RT RIC",
    "NearRT-RIC": "Near-RT RIC",
    "Non-RT RIC": "Non-RT RIC",
    "Non RT RIC": "Non-RT RIC",
    "Non-RT-RIC": "Non-RT RIC",
    "NonRT-RIC": "Non-RT RIC",
    "SMO": "SMO",
    "O-Cloud": "O-Cloud",
    "O-CLOUD": "O-Cloud",
    "xApp": "xApp",
    "xApps": "xApp",
    "rApp": "rApp",
    "rApps": "rApp",
}

# Map threat ID prefixes to primary affected components
THREAT_PREFIX_TO_COMPONENTS = {
    "T-O-RAN": ["SMO", "Non-RT RIC", "Near-RT RIC", "O-CU-CP", "O-CU-UP", "O-DU", "O-RU", "O-Cloud"],
    "T-FRHAUL": ["O-DU", "O-RU"],
    "T-MPLANE": ["O-DU", "O-RU", "SMO"],
    "T-SPLANE": ["O-DU", "O-RU"],
    "T-CPLANE": ["O-DU", "O-RU"],
    "T-UPLANE": ["O-DU", "O-RU"],
    "T-ORU": ["O-RU"],
    "T-O-RU": ["O-RU"],
    "T-SharedORU": ["O-RU"],
    "T-NEAR-RT": ["Near-RT RIC"],
    "T-NONRTRIC": ["Non-RT RIC"],
    "T-xAPP": ["xApp", "Near-RT RIC"],
    # WG11 7.4.7 Protocol Stack Threats: REST stack of the A1 and R1 interfaces (Fig 7-13)
    "T-ProtocolStack": ["Non-RT RIC", "Near-RT RIC", "rApp"],
    "T-rAPP": ["rApp", "Non-RT RIC"],
    "T-SMO": ["SMO"],
    "T-AppLCM": ["SMO", "O-Cloud"],
    "T-GEN": ["SMO", "Non-RT RIC", "Near-RT RIC", "O-CU-CP", "O-CU-UP", "O-DU", "O-RU", "O-Cloud"],
    "T-VM-C": ["O-Cloud"],
    "T-IMG": ["O-Cloud"],
    "T-VL": ["O-Cloud"],
    "T-O2": ["O-Cloud", "SMO"],
    "T-OCAPI": ["O-Cloud"],
    "T-HW": ["O-Cloud"],
    "T-ADMIN": ["O-Cloud"],
    "T-AAL": ["O-Cloud"],
    "T-O-CLOUD-ID": ["O-Cloud"],
    "T-OPENSRC": ["O-Cloud"],
    "T-PHYS": ["O-RU", "O-DU"],
    "T-RADIO": ["O-RU"],
    "T-PNF": ["O-RU"],
    "T-AIML": ["Near-RT RIC", "Non-RT RIC", "SMO"],
    "T-TS": ["Near-RT RIC", "SMO"],
    "T-A1": ["Near-RT RIC", "Non-RT RIC"],
    "T-E2": ["Near-RT RIC", "O-CU-CP", "O-DU"],
    "T-Y1": ["Non-RT RIC", "SMO"],
    "T-R1": ["Non-RT RIC", "rApp"],
    "T-OAuth-G": ["SMO", "Non-RT RIC", "Near-RT RIC", "O-Cloud"],
}

# Risk score mapping to numeric values
RISK_SCORE_MAP = {"High": 0.9, "Medium": 0.5, "Low": 0.2}
SEVERITY_MAP = {"High": 0.9, "Medium": 0.5, "Low": 0.2}
LIKELIHOOD_MAP = {"High": 0.9, "Medium": 0.5, "Low": 0.2}

# STRIDE category to numeric encoding
STRIDE_MAP = {
    "Spoofing": 0,
    "Tampering": 1,
    "Repudiation": 2,
    "Information Disclosure": 3,
    "Denial of Service": 4,
    "Elevation of Privilege": 5,
}

# WG11 requirement support levels -> defense strength weight
SUPPORT_WEIGHT = {"MS": 1.0, "M": 0.8, "OS": 0.5, "O": 0.3}

# Component criticality (based on architectural role)
COMPONENT_CRITICALITY = {
    "SMO": 0.95,
    "Non-RT RIC": 0.85,
    "Near-RT RIC": 0.9,
    "O-CU-CP": 0.85,
    "O-CU-UP": 0.75,
    "O-DU": 0.8,
    "O-RU": 0.7,
    "O-Cloud": 0.9,
    "xApp": 0.6,
    "rApp": 0.6,
}


def load_json(filename):
    with open(DATA_DIR / filename) as f:
        return json.load(f)


def parse_affected_components(threat_summary_entry):
    """Extract canonical component names from threat summary's affected_components field."""
    text = threat_summary_entry.get("affected_components", "")
    components = set()
    for alias, canonical in COMPONENT_ALIASES.items():
        if alias in text:
            components.add(canonical)
    return components


def get_components_for_threat(threat_id, threat_summary_map):
    """Determine which O-RAN components a threat targets."""
    # First try threat summary table
    if threat_id in threat_summary_map:
        components = parse_affected_components(threat_summary_map[threat_id])
        if components:
            return components

    # Sub-variant fallback: T-GEN-02A is absent from the summary table but its
    # base row T-GEN-02 is present — use the base row, not the broad prefix map.
    if threat_id[-1:].isalpha() and threat_id[:-1] in threat_summary_map:
        components = parse_affected_components(threat_summary_map[threat_id[:-1]])
        if components:
            return components

    # Fallback: use threat ID prefix mapping (case-insensitive: spec mixes T-xApp/T-xAPP)
    tid_l = threat_id.lower()
    for prefix, comps in sorted(THREAT_PREFIX_TO_COMPONENTS.items(), key=lambda x: -len(x[0])):
        if tid_l.startswith(prefix.lower()):
            return set(comps)

    return set()


def parse_stride_categories(threat_type_str):
    """Parse STRIDE categories from threat type string."""
    # case-insensitive match against the 6 canonical names; each appended at most once
    categories = []
    for cat in STRIDE_MAP:
        if cat.lower() in threat_type_str.lower() and cat not in categories:
            categories.append(cat)
    return categories


def expand_requirement_ranges(reqs_text):
    """Expand range notations like REQ-SEC-SLM-SST-1..7 and REQ-SEC-ALM-PKG-1 to REQ-SEC-ALM-PKG-15."""
    text = reqs_text.replace("REC-SEC-", "REQ-SEC-")  # normalize typo

    all_ids = set()

    # Pattern 1: PREFIX-N..M (e.g., REQ-SEC-SLM-SST-1..7, SEC-CTL-NEAR-RT-13..14)
    for m in re.finditer(r'((?:REQ-[A-Z0-9-]*|SEC-CTL-[A-Z0-9-]*|REQ-SBOM-)-)(\d+)\.\.(\d+)', text):
        prefix, start_s, end_s = m.group(1), m.group(2), m.group(3)
        width = len(start_s)
        for i in range(int(start_s), int(end_s) + 1):
            all_ids.add(f"{prefix}{str(i).zfill(width)}")

    # Pattern 2: PREFIX-N to PREFIX-M (e.g., REQ-SEC-ALM-PKG-1 to REQ-SEC-ALM-PKG-15)
    for m in re.finditer(r'((?:REQ|SEC-CTL)-[A-Z0-9-]*-)(\d+)\s+to\s+\1(\d+)', text):
        prefix, start_s, end_s = m.group(1), m.group(2), m.group(3)
        width = len(start_s)
        for i in range(int(start_s), int(end_s) + 1):
            all_ids.add(f"{prefix}{str(i).zfill(width)}")

    # Direct matches (non-range)
    for m in re.finditer(r'(REQ-[A-Z0-9]+-[A-Z0-9-]*\d+)', text):
        all_ids.add(m.group(1))

    # Direct SEC-CTL matches
    for m in re.finditer(r'(SEC-CTL-[A-Z0-9-]*\d+)', text):
        all_ids.add(m.group(1))

    return all_ids


def _parse_support_weight(support_str):
    """Parse WG11 support field to a numeric weight. Handles multi-value entries."""
    if not support_str:
        return 0.5  # default for missing
    # Simple case: direct match
    if support_str in SUPPORT_WEIGHT:
        return SUPPORT_WEIGHT[support_str]
    # Complex multi-line entries: extract all support levels, take max
    best = 0.3
    for level in SUPPORT_WEIGHT:
        if level in support_str:
            best = max(best, SUPPORT_WEIGHT[level])
    return best


def _extract_chain_targets(description):
    """Extract STRIDE categories that a threat's description says it enables.

    Only matches when explicit causal language is present (leads to, enabling,
    results in, allows) followed by a STRIDE-relevant outcome keyword.

    Returns set of STRIDE categories that this threat can lead to.
    """
    desc = description.lower()
    targets = set()

    # Causal connector + outcome keyword patterns (within 60 chars)
    causal_outcome_patterns = [
        (r'(?:leads?\s+to|result(?:s|ing)?\s+in|enabl(?:e|es|ing)|allows?)\s+.{0,60}?(?:escalat|privilege)',
         "Elevation of Privilege"),
        (r'(?:leads?\s+to|result(?:s|ing)?\s+in|enabl(?:e|es|ing)|allows?)\s+.{0,60}?(?:tamper|inject|modif|manipulat)',
         "Tampering"),
        (r'(?:leads?\s+to|result(?:s|ing)?\s+in|enabl(?:e|es|ing)|allows?)\s+.{0,60}?(?:denial.of.service|dos\b|disrupt|unavailab)',
         "Denial of Service"),
        (r'(?:leads?\s+to|result(?:s|ing)?\s+in|enabl(?:e|es|ing)|allows?)\s+.{0,60}?(?:disclos|exfiltrat|leak|intercept|eavesdrop)',
         "Information Disclosure"),
        (r'(?:leads?\s+to|result(?:s|ing)?\s+in|enabl(?:e|es|ing)|allows?)\s+.{0,60}?(?:spoof|impersonat|forge)',
         "Spoofing"),
    ]

    for pattern, cat in causal_outcome_patterns:
        if re.search(pattern, desc):
            targets.add(cat)

    # Lateral movement / pivot explicitly implies enabling Tampering + EoP
    if re.search(r'(?:lateral|pivot)', desc):
        targets.update({"Tampering", "Elevation of Privilege"})

    return targets


def build_adg():
    """Build the Attack-Defense Graph from extracted WG11 data."""
    G = nx.DiGraph()

    # Load all data
    threats = load_json("raw_threats.json")
    assets = load_json("raw_assets.json")
    risk_assessment = load_json("raw_risk_assessment.json")
    coverage_matrix = load_json("raw_coverage_matrix.json")
    threat_summary = load_json("raw_threat_summary.json")
    threat_to_reqs = load_json("raw_threat_to_requirements.json")
    security_reqs = load_json("raw_security_requirements.json")
    security_controls = load_json("raw_security_controls.json")

    # Build lookup maps
    risk_map = {r["threat_id"]: r for r in risk_assessment}
    threat_summary_map = {t["threat_id"]: t for t in threat_summary}
    threat_to_reqs_map = {t["threat_id"]: t for t in threat_to_reqs}
    req_to_controls = {}
    for r in security_reqs:
        ctrl_ids = re.findall(r'SEC-CTL-[A-Za-z0-9-]+', r.get("controls", ""))
        req_to_controls[r["requirement_id"]] = ctrl_ids
    control_map = {c["control_id"]: c for c in security_controls}

    # Void controls (deleted in SRCS) must not become defense nodes.
    # Handles both "SEC-CTL-X: Void" and range form "SEC-CTL-X-1 to 4: Void".
    void_controls = set()
    for c in security_controls:
        ctx = (c.get("context") or "").strip()
        if re.search(r":\s*Void\.?\s*$", ctx, re.I):
            void_controls.add(c["control_id"])
            m = re.match(r"(SEC-CTL-[A-Za-z0-9-]+-)(\d+)\s+to\s+(\d+)\s*:", ctx)
            if m:
                for i in range(int(m.group(2)), int(m.group(3)) + 1):
                    void_controls.add(f"{m.group(1)}{i}")

    # ========== 1. Add Asset Nodes (O-RAN components) ==========
    for comp_name, criticality in COMPONENT_CRITICALITY.items():
        G.add_node(comp_name,
                   node_type="asset",
                   criticality=criticality,
                   component_type=comp_name)

    # ========== 2. Add Topology Edges (asset ↔ asset) ==========
    for src, connections in ORAN_TOPOLOGY.items():
        for dst, interface in connections:
            if src in G.nodes and dst in G.nodes:
                G.add_edge(src, dst, edge_type="topology", interface=interface)
                if not G.has_edge(dst, src):
                    G.add_edge(dst, src, edge_type="topology", interface=interface)

    # ========== 3. Add Attack Nodes (threats) ==========
    seen_threats = set()
    threat_descriptions = {}  # for enables edge Tier 1
    for threat in threats:
        tid = threat["id"].replace(" ", "")   # normalize 'T- NONRTRIC-03' docx artifact
        if not tid.startswith("T-"):
            continue
        if tid in seen_threats:
            continue
        seen_threats.add(tid)
        threat_descriptions[tid] = threat.get("description", "")

        # Get risk data
        risk = risk_map.get(tid, {})
        severity = SEVERITY_MAP.get(risk.get("severity_level", ""), 0.5)
        likelihood = LIKELIHOOD_MAP.get(risk.get("likelihood_level", ""), 0.5)
        risk_score = RISK_SCORE_MAP.get(risk.get("risk_score", ""), 0.5)

        # Parse STRIDE categories
        stride_cats = parse_stride_categories(threat.get("threat_type", ""))

        # Get coverage by security principles
        sps = coverage_matrix.get(tid, [])

        G.add_node(tid,
                   node_type="attack",
                   title=threat.get("title", ""),
                   stride_categories=stride_cats,
                   severity=severity,
                   likelihood=likelihood,
                   risk_score=risk_score,
                   num_security_principles=len(sps),
                   threat_type=threat.get("threat_type", ""))

        # Add edges: attack -> asset (targets)
        target_components = get_components_for_threat(tid, threat_summary_map)
        for comp in target_components:
            if comp in G.nodes:
                G.add_edge(tid, comp, edge_type="targets")

    # ========== 4. Add Defense Nodes (security controls) ==========
    # Build requirement -> support weight map
    req_support = {}
    for r in security_reqs:
        req_support[r["requirement_id"]] = _parse_support_weight(r.get("support", ""))

    # Resolve SRCS threat IDs to threat-catalog node IDs:
    #  - whitespace artifacts ("T- NONRTRIC-03" vs catalog spelling)
    #  - stale base IDs renamed to sub-variants in the catalog (T-GEN-02 -> T-GEN-02A/02B)
    def resolve_tids(tid):
        cands = {tid, tid.replace(" ", "")}
        hits = [c for c in cands if c in seen_threats]
        if hits:
            return hits
        base = tid.replace(" ", "")
        variants = [t for t in seen_threats
                    if t.startswith(base) and len(t) == len(base) + 1 and t[-1].isalpha()]
        return variants

    # Build threat -> controls chain: threat -> requirements -> controls
    threat_to_controls = defaultdict(set)
    for t2r in threat_to_reqs:
        reqs_text = t2r.get("security_requirements", "")
        if reqs_text == "For further study" or not reqs_text:
            continue
        all_ids = expand_requirement_ranges(reqs_text)
        for tid in resolve_tids(t2r["threat_id"]):
            for rid in all_ids:
                if rid.startswith("SEC-CTL-"):
                    # Direct control reference
                    threat_to_controls[tid].add(rid)
                elif rid in req_to_controls:
                    for ctl_id in req_to_controls[rid]:
                        threat_to_controls[tid].add(ctl_id)

    # Compute control -> max support weight from requirements that reference it
    control_strength = defaultdict(lambda: 0.3)
    for r in security_reqs:
        rid = r["requirement_id"]
        weight = _parse_support_weight(r.get("support", ""))
        for ctl_id in req_to_controls.get(rid, []):
            control_strength[ctl_id] = max(control_strength[ctl_id], weight)

    # Add control nodes (excluding controls SRCS marks as Void)
    all_controls_used = set()
    for controls in threat_to_controls.values():
        all_controls_used.update(controls)
    all_controls_used -= void_controls

    for ctl_id in all_controls_used:
        ctl_info = control_map.get(ctl_id, {})
        # Determine control type from ID
        control_type = "general"
        ctl_lower = ctl_id.lower()
        if "tls" in ctl_lower or "tcomm" in ctl_lower:
            control_type = "transport_security"
        elif "auth" in ctl_lower or "oauth" in ctl_lower:
            control_type = "authentication"
        elif "acc" in ctl_lower or "rbac" in ctl_lower:
            control_type = "access_control"
        elif "log" in ctl_lower or "slm" in ctl_lower:
            control_type = "logging"
        elif "crypto" in ctl_lower:
            control_type = "cryptography"
        elif "alm" in ctl_lower or "pkg" in ctl_lower:
            control_type = "lifecycle_management"
        elif "img" in ctl_lower or "boot" in ctl_lower:
            control_type = "secure_boot"

        G.add_node(ctl_id,
                   node_type="defense",
                   control_type=control_type,
                   strength=control_strength[ctl_id],
                   section=ctl_info.get("section", ""),
                   description=ctl_info.get("context", "")[:200])

        # Add edges: defense -> attack (mitigates)
        for tid, controls in threat_to_controls.items():
            if ctl_id in controls and tid in G.nodes:
                G.add_edge(ctl_id, tid, edge_type="mitigates")

    # ========== 5. Add Attack Chains (attack -> attack enables) ==========
    # Two-tier approach:
    #   Tier 1: description-based chains (high confidence)
    #   Tier 2: STRIDE heuristic + shared-target constraint (medium confidence)
    attack_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "attack"]
    enables_chain = {
        "Spoofing": {"Elevation of Privilege", "Tampering"},
        "Information Disclosure": {"Spoofing", "Tampering"},
        "Elevation of Privilege": {"Tampering", "Information Disclosure"},
        "Tampering": {"Denial of Service"},
    }

    def threat_prefix(tid):
        """Extract subsystem prefix: T-FRHAUL, T-SMO, T-xAPP, etc."""
        m = re.match(r'(T-[A-Za-z]+-?[A-Za-z]*)', tid)
        return m.group(1) if m else tid

    # Precompute: threat -> set of target components (for shared-target constraint)
    threat_targets = {}
    for tid in attack_nodes:
        threat_targets[tid] = {t for _, t, d in G.out_edges(tid, data=True)
                               if d.get("edge_type") == "targets"}

    # Precompute: description-based chain targets for Tier 1
    desc_chain_targets = {}
    for tid in attack_nodes:
        desc_chain_targets[tid] = _extract_chain_targets(threat_descriptions.get(tid, ""))

    # Group threats by subsystem prefix
    prefix_groups = defaultdict(list)
    for tid in attack_nodes:
        prefix_groups[threat_prefix(tid)].append(tid)

    # Add enables edges within each subsystem group
    for prefix, tids in prefix_groups.items():
        for i, tid1 in enumerate(tids):
            cats1 = G.nodes[tid1].get("stride_categories", [])
            for tid2 in tids[i + 1:]:
                cats2 = G.nodes[tid2].get("stride_categories", [])

                # Tier 1: description says tid1 enables tid2's STRIDE category
                tier1 = bool(desc_chain_targets[tid1] & set(cats2))

                if tier1:
                    G.add_edge(tid1, tid2, edge_type="enables",
                               via_prefix=prefix, source="description")
                else:
                    # Tier 2: STRIDE heuristic + shared-target constraint
                    shared_targets = threat_targets[tid1] & threat_targets[tid2]
                    if shared_targets:
                        for c1 in cats1:
                            if c1 in enables_chain and enables_chain[c1] & set(cats2):
                                G.add_edge(tid1, tid2, edge_type="enables",
                                           via_prefix=prefix, source="stride_heuristic")
                                break

    return G


def print_graph_stats(G):
    """Print statistics about the ADG."""
    node_types = defaultdict(int)
    edge_types = defaultdict(int)

    for _, data in G.nodes(data=True):
        node_types[data.get("node_type", "unknown")] += 1

    for _, _, data in G.edges(data=True):
        edge_types[data.get("edge_type", "unknown")] += 1

    print("=" * 60)
    print("Attack-Defense Graph Statistics")
    print("=" * 60)
    print(f"Total nodes: {G.number_of_nodes()}")
    for ntype, count in sorted(node_types.items()):
        print(f"  {ntype}: {count}")
    print(f"\nTotal edges: {G.number_of_edges()}")
    for etype, count in sorted(edge_types.items()):
        print(f"  {etype}: {count}")

    # Defense coverage
    attack_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "attack"]
    defended = sum(1 for n in attack_nodes
                   if any(d.get("edge_type") == "mitigates"
                          for _, _, d in G.in_edges(n, data=True)))
    print(f"\nDefense coverage: {defended}/{len(attack_nodes)} threats have mitigations "
          f"({100 * defended / len(attack_nodes):.1f}%)")

    # Undefended threats
    undefended = [n for n in attack_nodes
                  if not any(d.get("edge_type") == "mitigates"
                             for _, _, d in G.in_edges(n, data=True))]
    print(f"Undefended threats: {len(undefended)}")

    # Component exposure
    print("\nComponent exposure (threats targeting each):")
    asset_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset"]
    for comp in sorted(asset_nodes):
        incoming = sum(1 for _, _, d in G.in_edges(comp, data=True)
                       if d.get("edge_type") == "targets")
        print(f"  {comp}: {incoming} threats")


if __name__ == "__main__":
    G = build_adg()
    print_graph_stats(G)

    # Save graph
    output_path = DATA_DIR / "adg_graph.graphml"
    # GraphML doesn't support list attributes, convert to strings
    for n in G.nodes:
        data = G.nodes[n]
        if "stride_categories" in data:
            data["stride_categories"] = ",".join(data["stride_categories"])
    nx.write_graphml(G, output_path)
    print(f"\nGraph saved to {output_path}")
