"""
Sensitivity Analysis for O-RAN ADG Security Metrics.

Sweeps key parameters to verify that metric rankings are stable
and not artifacts of specific parameter choices.

Parameters:
  - TPRS decay: controls distance attenuation in topology propagation
  - PageRank alpha: teleport probability in CTI computation
  - Defense coefficient: scaling in diminishing-returns defense formula
"""

from scipy.stats import kendalltau
from adg_builder import build_adg
import metrics
from metrics import (
    compute_tprs, compute_cti, compute_spi,
    what_if_disable_defense, get_nodes_by_type,
)


# Parameter sweep ranges
DECAY_VALUES = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
ALPHA_VALUES = [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
DEFENSE_COEFF_VALUES = [0.3, 0.5, 0.7, 1.0]

BASELINE_DECAY = 0.5
BASELINE_ALPHA = 0.85
BASELINE_DEFENSE_COEFF = 0.5


def _rank_vector(scores_dict, keys):
    """Return rank ordering (0-indexed) for the given keys based on scores."""
    sorted_keys = sorted(keys, key=lambda k: scores_dict.get(k, 0), reverse=True)
    return [sorted_keys.index(k) for k in keys]


def _get_scenario_spis(G):
    """Get S2 (FH disabled) and S3 (Cloud disabled) SPI values."""
    defenses = get_nodes_by_type(G, "defense")
    fh_defs = [d for d in defenses if any(kw in d.upper() for kw in ["OFH", "MACSEC", "FH", "FRHAUL"])]
    cloud_defs = [d for d in defenses if any(kw in d.upper() for kw in ["CLOUD", "VM", "IMG", "AAL", "ADMIN", "VL"])]
    s2 = what_if_disable_defense(G, fh_defs)
    s3 = what_if_disable_defense(G, cloud_defs)
    return s2["spi"], s3["spi"]


def sweep_decay(G):
    """Sweep TPRS decay parameter and measure rank stability."""
    assets = sorted(get_nodes_by_type(G, "asset"))
    baseline_tprs = compute_tprs(G, decay=BASELINE_DECAY)
    baseline_ranks = _rank_vector(baseline_tprs, assets)

    results = []
    for decay in DECAY_VALUES:
        tprs = compute_tprs(G, decay=decay)
        ranks = _rank_vector(tprs, assets)
        tau, p_value = kendalltau(baseline_ranks, ranks)
        results.append({
            "decay": decay,
            "tau": tau,
            "p_value": p_value,
            "top1": max(tprs, key=tprs.get),
            "top2": sorted(tprs, key=tprs.get, reverse=True)[1],
        })
    return results


def sweep_alpha(G):
    """Sweep PageRank alpha and measure CTI rank stability."""
    baseline_cti = compute_cti(G, alpha=BASELINE_ALPHA)
    top20_threats = sorted(baseline_cti, key=baseline_cti.get, reverse=True)[:20]
    baseline_ranks = _rank_vector(baseline_cti, top20_threats)

    results = []
    for alpha in ALPHA_VALUES:
        cti = compute_cti(G, alpha=alpha)
        ranks = _rank_vector(cti, top20_threats)
        tau, p_value = kendalltau(baseline_ranks, ranks)
        results.append({
            "alpha": alpha,
            "tau": tau,
            "p_value": p_value,
            "top1": max(cti, key=cti.get),
        })
    return results


def sweep_defense_coeff(G):
    """Sweep defense coefficient and measure SPI + scenario ordering stability."""
    baseline_spi = compute_spi(G)
    baseline_s2, baseline_s3 = _get_scenario_spis(G)

    results = []
    for coeff in DEFENSE_COEFF_VALUES:
        old_coeff = metrics.DEFENSE_COEFF
        metrics.DEFENSE_COEFF = coeff
        try:
            spi = compute_spi(G)
            s2_spi, s3_spi = _get_scenario_spis(G)
            s2_delta = s2_spi - spi
            s3_delta = s3_spi - spi
            s3_worse = s3_delta < s2_delta  # S3 should be worse (larger negative delta)
        finally:
            metrics.DEFENSE_COEFF = old_coeff
        results.append({
            "coeff": coeff,
            "spi": spi,
            "s2_delta": s2_delta,
            "s3_delta": s3_delta,
            "s3_worse_than_s2": s3_worse,
        })
    return results


def run_sensitivity_analysis():
    """Run full sensitivity analysis and print results."""
    G = build_adg()

    print("=" * 70)
    print("Sensitivity Analysis")
    print("=" * 70)

    # --- Decay sweep ---
    print("\n1. TPRS Decay Parameter Sweep")
    print(f"   Baseline decay = {BASELINE_DECAY}")
    print(f"   {'Decay':>6s}  {'Kendall τ':>10s}  {'p-value':>8s}  {'Top-1':>15s}  {'Top-2':>15s}")
    print(f"   {'-'*60}")
    decay_results = sweep_decay(G)
    for r in decay_results:
        marker = " <-- baseline" if r["decay"] == BASELINE_DECAY else ""
        print(f"   {r['decay']:6.1f}  {r['tau']:10.4f}  {r['p_value']:8.4f}  "
              f"{r['top1']:>15s}  {r['top2']:>15s}{marker}")

    decay_taus = [r["tau"] for r in decay_results]
    print(f"\n   Min τ = {min(decay_taus):.4f}, Mean τ = {sum(decay_taus)/len(decay_taus):.4f}")

    # --- Alpha sweep ---
    print("\n2. PageRank Alpha Parameter Sweep")
    print(f"   Baseline alpha = {BASELINE_ALPHA}")
    print(f"   {'Alpha':>6s}  {'Kendall τ':>10s}  {'p-value':>8s}  {'Top-1 Threat':>25s}")
    print(f"   {'-'*55}")
    alpha_results = sweep_alpha(G)
    for r in alpha_results:
        marker = " <-- baseline" if r["alpha"] == BASELINE_ALPHA else ""
        print(f"   {r['alpha']:6.2f}  {r['tau']:10.4f}  {r['p_value']:8.4f}  "
              f"{r['top1']:>25s}{marker}")

    alpha_taus = [r["tau"] for r in alpha_results]
    print(f"\n   Min τ = {min(alpha_taus):.4f}, Mean τ = {sum(alpha_taus)/len(alpha_taus):.4f}")

    # --- Defense coefficient sweep ---
    print("\n3. Defense Coefficient Parameter Sweep")
    print(f"   Baseline coeff = {BASELINE_DEFENSE_COEFF}")
    print(f"   {'Coeff':>6s}  {'SPI':>6s}  {'S2 Δ':>8s}  {'S3 Δ':>8s}  {'S3>S2?':>6s}")
    print(f"   {'-'*40}")
    coeff_results = sweep_defense_coeff(G)
    for r in coeff_results:
        marker = " <-- baseline" if r["coeff"] == BASELINE_DEFENSE_COEFF else ""
        print(f"   {r['coeff']:6.1f}  {r['spi']:6.2f}  {r['s2_delta']:+8.2f}  "
              f"{r['s3_delta']:+8.2f}  {'Yes' if r['s3_worse_than_s2'] else 'NO':>6s}{marker}")

    # --- Summary ---
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    all_taus = decay_taus + alpha_taus
    print(f"  All Kendall τ values ≥ {min(all_taus):.4f}")
    print(f"  Mean Kendall τ = {sum(all_taus)/len(all_taus):.4f}")
    stable = all(t >= 0.6 for t in all_taus)
    print(f"  All τ ≥ 0.6: {'YES — rankings are stable' if stable else 'NO — some rankings may be sensitive'}")

    # Check that S2 vs S3 ordering is consistent across all coefficient values
    orderings = [r["s3_worse_than_s2"] for r in coeff_results]
    consistent = len(set(orderings)) == 1
    worse_scenario = "S3" if orderings[0] else "S2"
    print(f"  S2 vs S3 ordering consistent: {'YES' if consistent else 'NO'} "
          f"({worse_scenario} always has larger impact)")

    return {
        "decay": decay_results,
        "alpha": alpha_results,
        "defense_coeff": coeff_results,
    }


if __name__ == "__main__":
    run_sensitivity_analysis()
