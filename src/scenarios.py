"""
Evaluation Scenarios for the O-RAN ADG Security Analysis paper.

S1: Baseline - Current WG11 security posture (graph-theoretic analysis)
S2: Fronthaul compromise - What if Open Fronthaul defenses disabled
S3: Cloud infrastructure attack - What if O-Cloud defenses disabled
S4: AI/ML pipeline attack - What if AI/ML related defenses disabled
S5: Optimal defense allocation - Greedy defense addition for max SPI improvement
"""

from pathlib import Path
from collections import defaultdict

from adg_builder import build_adg
from metrics import (
    compute_tprs, compute_cti, compute_dei, compute_spi,
    compute_critical_paths, compute_bottlenecks,
    what_if_disable_defense, what_if_add_defense, get_nodes_by_type,
    run_all_metrics
)

DATA_DIR = Path(__file__).parent.parent / "data"


def scenario_baseline(G):
    """S1: Baseline analysis of current WG11 security posture."""
    print("\n" + "=" * 60)
    print("SCENARIO 1: Baseline Security Posture")
    print("=" * 60)
    return run_all_metrics(G)


def scenario_fronthaul_compromise(G):
    """S2: Disable all Open Fronthaul related defenses."""
    print("\n" + "=" * 60)
    print("SCENARIO 2: Open Fronthaul Compromise")
    print("=" * 60)
    print("Simulating: All Open Fronthaul defenses disabled\n")

    defenses = get_nodes_by_type(G, "defense")
    fh_defenses = [d for d in defenses
                   if any(kw in d.upper() for kw in ["OFH", "MACSEC", "FH", "FRHAUL"])]

    print(f"Disabling {len(fh_defenses)} Fronthaul defenses:")
    for d in fh_defenses:
        print(f"  - {d}")

    base_spi = compute_spi(G)
    base_tprs = compute_tprs(G)
    result = what_if_disable_defense(G, fh_defenses)
    print(f"\nSPI change: {base_spi:.2f} -> {result['spi']:.2f} (delta: {result['spi'] - base_spi:+.2f})")

    print("\nMost affected components (TPRS increase):")
    for comp in sorted(result['tprs'].keys(),
                       key=lambda c: result['tprs'][c] - base_tprs.get(c, 0), reverse=True):
        delta = result['tprs'][comp] - base_tprs.get(comp, 0)
        if delta > 0.01:
            print(f"  {comp:15s}: TPRS +{delta:.4f} (now {result['tprs'][comp]:.2f})")

    return result


def scenario_cloud_attack(G):
    """S3: Disable all O-Cloud related defenses."""
    print("\n" + "=" * 60)
    print("SCENARIO 3: O-Cloud Infrastructure Attack")
    print("=" * 60)
    print("Simulating: All O-Cloud defenses disabled\n")

    defenses = get_nodes_by_type(G, "defense")
    cloud_defenses = [d for d in defenses
                      if any(kw in d.upper() for kw in ["CLOUD", "VM", "IMG", "AAL", "ADMIN", "VL"])]

    print(f"Disabling {len(cloud_defenses)} O-Cloud defenses:")
    for d in cloud_defenses:
        print(f"  - {d}")

    base_spi = compute_spi(G)
    base_tprs = compute_tprs(G)
    result = what_if_disable_defense(G, cloud_defenses)
    print(f"\nSPI change: {base_spi:.2f} -> {result['spi']:.2f} (delta: {result['spi'] - base_spi:+.2f})")

    print("\nMost affected components (TPRS increase):")
    for comp in sorted(result['tprs'].keys(),
                       key=lambda c: result['tprs'][c] - base_tprs.get(c, 0), reverse=True):
        delta = result['tprs'][comp] - base_tprs.get(comp, 0)
        if delta > 0.01:
            print(f"  {comp:15s}: TPRS +{delta:.4f} (now {result['tprs'][comp]:.2f})")

    return result


def scenario_aiml_attack(G):
    """S4: Disable all AI/ML related defenses."""
    print("\n" + "=" * 60)
    print("SCENARIO 4: AI/ML Pipeline Attack")
    print("=" * 60)
    print("Simulating: All AI/ML security defenses disabled\n")

    defenses = get_nodes_by_type(G, "defense")
    aiml_defenses = [d for d in defenses
                     if any(kw in d.upper() for kw in ["AIML", "AI-ML", "ML"])]

    print(f"Disabling {len(aiml_defenses)} AI/ML defenses:")
    for d in aiml_defenses:
        print(f"  - {d}")

    base_spi = compute_spi(G)
    if aiml_defenses:
        result = what_if_disable_defense(G, aiml_defenses)
        print(f"\nSPI change: {base_spi:.2f} -> {result['spi']:.2f} (delta: {result['spi'] - base_spi:+.2f})")
    else:
        print("\nNo AI/ML specific defenses found in current controls.")
        print("This represents a significant defense gap for AI/ML threats.")
        attacks = get_nodes_by_type(G, "attack")
        aiml_threats = [t for t in attacks if "AIML" in t.upper()]
        defended = sum(1 for t in aiml_threats
                       if any(d.get("edge_type") == "mitigates"
                              for _, _, d in G.in_edges(t, data=True)))
        print(f"AI/ML threats: {len(aiml_threats)} total, {defended} defended, "
              f"{len(aiml_threats) - defended} undefended")
        result = {"spi": base_spi, "tprs": compute_tprs(G), "note": "No AI/ML defenses to disable"}

    return result


def scenario_optimal_defense(G):
    """S5: Greedy defense allocation - find best defenses to add."""
    print("\n" + "=" * 60)
    print("SCENARIO 5: Optimal Defense Allocation")
    print("=" * 60)
    print("Finding the most impactful defenses to add for undefended threats\n")

    attacks = get_nodes_by_type(G, "attack")
    cti = compute_cti(G)

    # Find undefended threats
    undefended = []
    for tid in attacks:
        has_defense = any(d.get("edge_type") == "mitigates"
                         for _, _, d in G.in_edges(tid, data=True))
        if not has_defense:
            undefended.append(tid)

    print(f"Undefended threats: {len(undefended)}")

    # Group by prefix for targeted defense
    prefix_groups = defaultdict(list)
    for tid in undefended:
        parts = tid.split("-")
        if len(parts) >= 3:
            prefix = "-".join(parts[:3]) if not parts[2][0].isdigit() else "-".join(parts[:2])
        else:
            prefix = tid
        prefix_groups[prefix].append(tid)

    print("\nUndefended by subsystem (with CTI-weighted risk):")
    for prefix, tids in sorted(prefix_groups.items(),
                                key=lambda x: -sum(cti.get(t, 0) for t in x[1])):
        total_cti = sum(cti.get(t, 0) for t in tids)
        print(f"  {prefix:20s}: {len(tids):3d} threats, total CTI={total_cti:.4f}")

    # Greedy: add hypothetical defense for each group and measure SPI improvement
    base_spi = compute_spi(G)
    improvements = []

    for prefix, tids in prefix_groups.items():
        result = what_if_add_defense(G, tids, f"hyp-defense-{prefix}")
        delta = result["spi"] - base_spi
        total_cti = sum(cti.get(t, 0) for t in tids)
        improvements.append((prefix, len(tids), delta, result["spi"], total_cti))

    improvements.sort(key=lambda x: -x[2])

    print(f"\nDefense prioritization (by SPI improvement):")
    print(f"  Baseline SPI: {base_spi:.2f}")
    print(f"  {'Subsystem':20s} {'Threats':>8s} {'SPI Delta':>10s} {'New SPI':>10s} {'Total CTI':>10s}")
    print(f"  {'-'*60}")
    for prefix, n_threats, delta, new_spi, total_cti in improvements[:15]:
        print(f"  {prefix:20s} {n_threats:8d} {delta:+10.2f} {new_spi:10.2f} {total_cti:10.4f}")

    return improvements


def run_all_scenarios():
    """Run all five evaluation scenarios."""
    G = build_adg()

    results = {}
    results["S1"] = scenario_baseline(G)
    results["S2"] = scenario_fronthaul_compromise(G)
    results["S3"] = scenario_cloud_attack(G)
    results["S4"] = scenario_aiml_attack(G)
    results["S5"] = scenario_optimal_defense(G)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY: Security Posture Across Scenarios")
    print("=" * 60)
    print(f"  S1 Baseline SPI:          {results['S1']['spi']:.2f}")
    s2_spi = results['S2'].get('spi', 'N/A')
    s3_spi = results['S3'].get('spi', 'N/A')
    s4_spi = results['S4'].get('spi', 'N/A')
    print(f"  S2 Fronthaul Compromised: {s2_spi}")
    print(f"  S3 Cloud Compromised:     {s3_spi}")
    print(f"  S4 AI/ML Compromised:     {s4_spi}")
    if results["S5"]:
        best = results["S5"][0]
        print(f"  S5 Best improvement:      {best[0]} (+{best[2]:.2f} SPI)")

    return results


if __name__ == "__main__":
    run_all_scenarios()
