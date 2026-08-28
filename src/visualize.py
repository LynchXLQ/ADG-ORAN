"""
Paper figures for MILCOM 2026 — IEEE conference style.

Fig 1: Slope chart  — Direct Risk Sum rank → TPRS rank
Fig 2: CTI amplification — r(t) vs cascading threat index
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.lines import Line2D
import numpy as np
from pathlib import Path

from adg_builder import build_adg
from metrics import (
    compute_tprs, compute_cti, get_nodes_by_type,
    _threat_residual_risk,
)

OUTPUT_DIR = Path(__file__).parent.parent / "figures"
OUTPUT_DIR.mkdir(exist_ok=True)

# ── IEEE single-column dimensions ────────────────────────────────────────
COL_W  = 3.487   # inches — one IEEE column
COL_H  = 3.0     # default height; overridden per figure

# ── Unified color palette ─────────────────────────────────────────────────
# Muted academic palette (Tol-inspired, colorblind-safe, grayscale-friendly)
C_UP    = '#4477AA'   # steel blue — rank improved / amplification
C_DOWN  = '#CC6677'   # muted rose — rank worsened
C_FLAT  = '#AAAAAA'   # gray   — unchanged
C_BASE  = '#CCCCCC'   # light gray — residual risk bar fill

# ADG-specific colors
C_ASSET      = '#2D7D46'   # muted forest green
C_ASSET_EDGE = '#1B5E30'   # dark green edge
C_ASSET_TEXT = '#1a3a1a'   # very dark green
C_DEF_THREAT = '#CC6677'   # muted rose — defended threat
C_UNDEF_THREAT = '#882255' # dark wine — undefended threat
C_UNDEF_EDGE = '#661144'   # darker wine edge
C_DEFENSE    = '#4477AA'   # steel blue
C_DEF_TEXT   = '#2B5C8A'   # dark blue text
C_TOPOLOGY   = '#2C2C2C'   # near-black
C_ENABLES    = '#DDCC77'   # muted gold — attack chain
C_TARGETS    = '#CC6677'   # same as defended threat
C_MITIGATES  = '#4477AA'   # same as defense
C_ZOOM       = '#996633'   # muted brown — zoom box & connection lines
C_INSET_BG   = '#F5F3EF'   # light warm gray — inset background
C_IFACE      = '#0E7C6B'   # deep teal — interface labels

# ── Unified rcParams — IEEE Times-like ───────────────────────────────────
IEEE_RC = {
    'pdf.fonttype'      : 42,
    'ps.fonttype'       : 42,
    'font.family'       : 'serif',
    'font.serif'        : ['Times New Roman', 'DejaVu Serif', 'serif'],
    'font.size'         : 8,
    'axes.labelsize'    : 8,
    'axes.titlesize'    : 8,
    'xtick.labelsize'   : 7,
    'ytick.labelsize'   : 7,
    'legend.fontsize'   : 7,
    'axes.linewidth'    : 0.8,
    'grid.linewidth'    : 0.5,
    'lines.linewidth'   : 1.5,
    'lines.markersize'  : 4,
    'xtick.major.width' : 0.8,
    'ytick.major.width' : 0.8,
    'xtick.major.size'  : 3,
    'ytick.major.size'  : 3,
    'axes.spines.top'   : False,
    'axes.spines.right' : False,
}


def _save(fig, name):
    for fmt in ('pdf', 'png'):
        fig.savefig(
            OUTPUT_DIR / f'{name}.{fmt}',
            bbox_inches='tight', pad_inches=0.01, dpi=300,
            facecolor='white', edgecolor='none', format=fmt,
        )
    plt.close(fig)
    print(f'  saved: {name}')


# =========================================================================
# Figure 1  —  Slope chart: Direct Risk Sum rank → TPRS rank
# =========================================================================
def fig1_tprs(G):
    tprs   = compute_tprs(G)
    attacks = get_nodes_by_type(G, 'attack')

    # Direct risk sum per component
    direct = {c: 0.0 for c in tprs}
    for tid in attacks:
        r = _threat_residual_risk(G, tid)
        for _, tgt, d in G.out_edges(tid, data=True):
            if d.get('edge_type') == 'targets' and tgt in direct:
                direct[tgt] += r

    n = len(tprs)
    direct_rank = {c: i + 1 for i, c in
                   enumerate(sorted(tprs, key=lambda c: direct[c], reverse=True))}
    tprs_rank   = {c: i + 1 for i, c in
                   enumerate(sorted(tprs, key=lambda c: tprs[c], reverse=True))}

    with plt.rc_context(IEEE_RC):
        fig, ax = plt.subplots(figsize=(COL_W, 2.6))

        x_l, x_r = 0.0, 1.0

        # Vertical column axes
        ax.plot([x_l, x_l], [-0.5, n - 0.5], color='#333333',
                linewidth=0.8, zorder=1)
        ax.plot([x_r, x_r], [-0.5, n - 0.5], color='#333333',
                linewidth=0.8, zorder=1)

        # Horizontal grid ticks for each rank
        for i in range(n):
            ax.plot([x_l - 0.015, x_l + 0.015], [i, i],
                    color='#333333', linewidth=0.5, zorder=1)
            ax.plot([x_r - 0.015, x_r + 0.015], [i, i],
                    color='#333333', linewidth=0.5, zorder=1)

        for comp in tprs:
            yl = n - direct_rank[comp]
            yr = n - tprs_rank[comp]
            delta = direct_rank[comp] - tprs_rank[comp]

            if delta > 0:
                color = C_UP
            elif delta < 0:
                color = C_DOWN
            else:
                color = C_FLAT

            lw   = 1.8 if abs(delta) >= 2 else 1.2
            fw   = 'normal'

            ax.plot([x_l, x_r], [yl, yr],
                    color=color, linewidth=lw,
                    solid_capstyle='round', zorder=2, alpha=0.85)
            ax.plot(x_l, yl, 'o', color=color, markersize=3.5,
                    markeredgewidth=0.4, markeredgecolor='white', zorder=3)
            ax.plot(x_r, yr, 'o', color=color, markersize=3.5,
                    markeredgewidth=0.4, markeredgecolor='white', zorder=3)

            # Component labels
            ax.text(x_l - 0.04, yl, comp,
                    ha='right', va='center', fontsize=7,
                    fontweight=fw, color=color)
            ax.text(x_r + 0.04, yr, comp,
                    ha='left', va='center', fontsize=7,
                    fontweight=fw, color=color)

        # Column headers
        hdr_kw = dict(ha='center', va='bottom', fontsize=8,
                      fontweight='bold', color='black')
        ax.text(x_l, n - 0.5 + 0.35, 'Direct Risk Sum', **hdr_kw)
        ax.text(x_r, n - 0.5 + 0.35, 'TPRS', **hdr_kw)

        # Legend — same style as fig2, placed below chart
        legend_elements = [
            Line2D([0], [0], color=C_UP,   lw=1.8, label='Rank improved'),
            Line2D([0], [0], color=C_DOWN, lw=1.8, label='Rank worsened'),
            Line2D([0], [0], color=C_FLAT, lw=1.2, label='Unchanged'),
        ]
        ax.legend(handles=legend_elements,
                  loc='upper center', bbox_to_anchor=(0.5, -0.02),
                  ncol=3, fontsize=6.5,
                  frameon=True, edgecolor='#cccccc',
                  fancybox=False, shadow=False,
                  handlelength=1.2, handletextpad=0.5)

        ax.set_xlim(-0.55, 1.55)
        ax.set_ylim(-1.2, n + 0.5)
        ax.axis('off')

        fig.tight_layout(pad=0.4)
        _save(fig, 'fig1_slope')


# =========================================================================
# Figure 2  —  CTI amplification: stacked horizontal bar
# =========================================================================
def fig2_cti(G):
    cti     = compute_cti(G)
    attacks = get_nodes_by_type(G, 'attack')
    res     = {tid: _threat_residual_risk(G, tid) for tid in attacks}

    top  = sorted(cti, key=cti.get, reverse=True)[:5]
    n    = len(top)

    # Short display labels
    def short(tid):
        return tid.replace('T-SharedORU-', 'SharedORU-')\
                  .replace('T-OAuth-G-',   'OAuth-G-')\
                  .replace('T-SMO-',       'SMO-')

    with plt.rc_context(IEEE_RC):
        fig, ax = plt.subplots(figsize=(COL_W, 1.9))

        x  = np.arange(n)
        w  = 0.62

        r_vals   = np.array([res[t] for t in top])
        amp_vals = np.array([cti[t] - res[t] for t in top])
        max_y    = (r_vals + amp_vals).max()

        # Base bar — residual risk
        bars_r = ax.bar(x, r_vals, w,
                        color=C_BASE, edgecolor='#666666',
                        linewidth=0.6, label=r'$r(t)$ (residual risk)',
                        zorder=3)
        # Stacked bar — cascade amplification
        bars_a = ax.bar(x, amp_vals, w, bottom=r_vals,
                        color=C_UP, edgecolor='#1a4f7a',
                        linewidth=0.6, label='Cascade amplification',
                        zorder=3)

        # Amplification ratio labels
        for i, t in enumerate(top):
            ratio = cti[t] / res[t] if res[t] > 0 else 0
            ax.text(i, cti[t] + max_y * 0.02,
                    f'{ratio:.1f}×',
                    va='bottom', ha='center',
                    fontsize=7, fontweight='normal', color=C_UP)

        ax.set_xticks(x)
        ax.set_xticklabels([short(t) for t in top], fontsize=6.5,
                           rotation=20, ha='right')
        ax.set_ylabel('Score', fontsize=8)
        ax.set_ylim(0, max_y * 1.18)

        ax.grid(True, axis='y', alpha=0.3, linestyle='--', linewidth=0.5)
        ax.set_axisbelow(True)

        ax.legend(loc='upper right', fontsize=6.5,
                  frameon=True, edgecolor='#cccccc',
                  fancybox=False, shadow=False,
                  handlelength=1.2, handletextpad=0.5)

        fig.tight_layout(pad=0.4)
        _save(fig, 'fig2_cti')


# =========================================================================
# Figure 3  —  ADG Overview + Zoom Inset (double-column, combined)
# =========================================================================
def _compute_adg_positions(G):
    """Compute node positions for the full ADG visualization."""
    import math

    attacks = get_nodes_by_type(G, 'attack')
    defenses = get_nodes_by_type(G, 'defense')

    asset_pos = {
        'SMO':         (0.0,  0.80),
        'Non-RT RIC':  (-0.60, 0.45),
        'rApp':        (-1.00, 0.15),
        'Near-RT RIC': (0.60,  0.45),
        'xApp':        (1.00,  0.15),
        'O-Cloud':     (0.0,   0.05),
        'O-CU-CP':     (0.45, -0.30),
        'O-CU-UP':     (-0.45, -0.30),
        'O-DU':        (0.0,  -0.58),
        'O-RU':        (0.0,  -0.88),
    }

    np.random.seed(42)
    pos = dict(asset_pos)

    for tid in attacks:
        targets = [t for _, t, d in G.out_edges(tid, data=True)
                   if d.get('edge_type') == 'targets' and t in asset_pos]
        if targets:
            cx = np.mean([asset_pos[t][0] for t in targets])
            cy = np.mean([asset_pos[t][1] for t in targets])
        else:
            cx, cy = 0.0, 0.0
        angle = np.random.uniform(0, 2 * math.pi)
        radius = np.random.uniform(0.04, 0.15)
        pos[tid] = (cx + radius * math.cos(angle),
                    cy + radius * math.sin(angle))

    for did in defenses:
        mitigated = [t for _, t, d in G.out_edges(did, data=True)
                     if d.get('edge_type') == 'mitigates']
        placed = [m for m in mitigated if m in pos]
        if placed:
            cx = np.mean([pos[m][0] for m in placed])
            cy = np.mean([pos[m][1] for m in placed])
        else:
            cx, cy = 0.0, 0.0
        angle = np.random.uniform(0, 2 * math.pi)
        radius = np.random.uniform(0.15, 0.25)
        pos[did] = (cx + radius * math.cos(angle),
                    cy + radius * math.sin(angle))

    return pos, asset_pos


def _draw_overview(ax, G, pos, asset_pos, zoom_box=None):
    """Draw the full ADG overview on the given axes."""
    attacks = get_nodes_by_type(G, 'attack')
    defenses = get_nodes_by_type(G, 'defense')
    assets = get_nodes_by_type(G, 'asset')

    # Edges
    edge_styles = {
        'enables':   dict(color=C_ENABLES + '40', linewidth=0.2, zorder=1),
        'targets':   dict(color=C_TARGETS + '18', linewidth=0.15, zorder=1),
        'mitigates': dict(color=C_MITIGATES + '18', linewidth=0.15, zorder=1),
        'topology':  dict(color=C_TOPOLOGY,        linewidth=1.5,  zorder=2),
    }
    for u, v, d in G.edges(data=True):
        etype = d.get('edge_type', '')
        if etype in edge_styles and u in pos and v in pos:
            ax.plot([pos[u][0], pos[v][0]], [pos[u][1], pos[v][1]],
                    **edge_styles[etype])

    # Interface labels on topology edges — staggered to avoid overlap
    ifc_idx = 0
    for u, v, d in G.edges(data=True):
        if d.get('edge_type') == 'topology' and u < v:
            iface = d.get('interface', '')
            if not iface:
                continue
            ux, uy = pos[u]
            vx, vy = pos[v]
            mx = (ux + vx) / 2
            my = (uy + vy) / 2
            # offset perpendicular to the edge so collinear edges separate
            dex, dey = vx - ux, vy - uy
            L = (dex ** 2 + dey ** 2) ** 0.5 or 1.0
            px, py = -dey / L, dex / L
            off = 0.05 * (1 if ifc_idx % 2 == 0 else -1)
            mx += px * off
            my += py * off
            ax.text(mx, my, iface, fontsize=6.2, ha='center', va='center',
                    color=C_IFACE, fontweight='bold', zorder=5)
            ifc_idx += 1

    # Defense nodes
    dx = [pos[d][0] for d in defenses if d in pos]
    dy = [pos[d][1] for d in defenses if d in pos]
    ax.scatter(dx, dy, s=5, c=C_DEFENSE, alpha=0.45, edgecolors='none',
               zorder=3, marker='s')

    # Attack nodes — color by defended status
    defended_attacks = set()
    for did in defenses:
        for _, t, d in G.out_edges(did, data=True):
            if d.get('edge_type') == 'mitigates':
                defended_attacks.add(t)

    att_def_x = [pos[t][0] for t in attacks if t in defended_attacks and t in pos]
    att_def_y = [pos[t][1] for t in attacks if t in defended_attacks and t in pos]
    att_undef_x = [pos[t][0] for t in attacks if t not in defended_attacks and t in pos]
    att_undef_y = [pos[t][1] for t in attacks if t not in defended_attacks and t in pos]

    ax.scatter(att_def_x, att_def_y, s=7, c=C_DEF_THREAT, alpha=0.5,
               edgecolors='none', zorder=4)
    ax.scatter(att_undef_x, att_undef_y, s=10, c=C_UNDEF_THREAT, alpha=0.75,
               edgecolors=C_UNDEF_EDGE, linewidths=0.3, zorder=4)

    # Asset nodes
    for comp, (x, y) in asset_pos.items():
        crit = G.nodes[comp].get('criticality', 0.5)
        size = 220 + crit * 220
        ax.scatter(x, y, s=size, c=C_ASSET, edgecolors=C_ASSET_EDGE,
                   linewidths=1.2, zorder=10)
        ax.text(x, y, comp, ha='center', va='center',
                fontsize=7.0, fontweight='bold', color='white', zorder=11,
                path_effects=[pe.withStroke(linewidth=2.0,
                                            foreground=C_ASSET_EDGE)])

    # Zoom box highlight
    if zoom_box:
        x0, y0, w, h = zoom_box
        rect = mpatches.FancyBboxPatch(
            (x0, y0), w, h,
            boxstyle='round,pad=0.02',
            linewidth=1.5, edgecolor=C_ZOOM, facecolor='none',
            linestyle='--', zorder=15)
        ax.add_patch(rect)

    return defended_attacks


def _draw_inset(ax, G):
    """Draw the fronthaul subgraph detail with descriptive labels."""
    fh_threats = sorted([n for n in G.nodes
                         if n.startswith('T-FRHAUL-')
                         and G.nodes[n].get('node_type') == 'attack'])

    fh_defenses = set()
    for tid in fh_threats:
        for src, _, d in G.in_edges(tid, data=True):
            if d.get('edge_type') == 'mitigates':
                fh_defenses.add(src)
    fh_defenses = sorted(fh_defenses)

    enables_edges = [(u, v) for u, v, d in G.edges(data=True)
                     if d.get('edge_type') == 'enables'
                     and u in fh_threats and v in fh_threats]

    # Descriptive labels
    threat_labels = {
        'T-FRHAUL-01':  'T-FRHAUL-01: Penetrate\nO-DU via O-RU [T/I]',
        'T-FRHAUL-01A': 'T-FRHAUL-01A: Spoof\nidentity via FH [S]',
        'T-FRHAUL-02':  'T-FRHAUL-02: Unauth.\nL1 eavesdrop [I]',
        'T-FRHAUL-03':  'T-FRHAUL-03: Unauth.\nL1 disruption [D]',
    }
    defense_labels = {
        'SEC-CTL-OFHPLS-2':  '802.1X supplicant',
        'SEC-CTL-OFHPLS-3':  'FH authenticator',
        'SEC-CTL-OFHPLS-4':  'Port-based NAC',
        'SEC-CTL-OFHPLS-5':  'EAP-TLS auth',
        'SEC-CTL-OFHPLS-6':  'O-DU authenticator',
        'SEC-CTL-OFHPLS-7':  'RADIUS interface',
        'SEC-CTL-OFHPLS-8':  'Diameter interface',
        'SEC-CTL-OFHPLS-9':  'Unauthorized port block',
        'SEC-CTL-OFHPLS-10': 'Authorization policy',
        'SEC-CTL-OFHPLS-11': 'O-RU X.509 cert',
        'SEC-CTL-OFHPLS-12': '802.1X procedures',
    }

    # Three-column layout
    pos = {}
    pos['O-DU'] = (-0.85, 0.30)
    pos['O-RU'] = (-0.85, -0.30)

    n_t = len(fh_threats)
    for i, tid in enumerate(fh_threats):
        y = 0.40 - i * (0.80 / max(n_t - 1, 1))
        pos[tid] = (-0.46, y)

    n_d = len(fh_defenses)
    for i, did in enumerate(fh_defenses):
        y = 0.44 - i * (0.88 / max(n_d - 1, 1))
        pos[did] = (0.40, y)

    # ── Edges ──
    for tid in fh_threats:
        for _, tgt, d in G.out_edges(tid, data=True):
            if d.get('edge_type') == 'targets' and tgt in ('O-DU', 'O-RU'):
                ax.annotate('', xy=pos[tgt], xytext=pos[tid],
                            arrowprops=dict(arrowstyle='->', color=C_TARGETS,
                                            linewidth=0.5, alpha=0.30,
                                            shrinkA=3, shrinkB=7))

    for did in fh_defenses:
        for _, tgt, d in G.out_edges(did, data=True):
            if d.get('edge_type') == 'mitigates' and tgt in fh_threats:
                ax.annotate('', xy=pos[tgt], xytext=pos[did],
                            arrowprops=dict(arrowstyle='->', color=C_MITIGATES,
                                            linewidth=0.4, alpha=0.30,
                                            shrinkA=2, shrinkB=3))

    for u, v in enables_edges:
        ax.annotate('', xy=(pos[v][0], pos[v][1] + 0.03),
                    xytext=(pos[u][0], pos[u][1] - 0.03),
                    arrowprops=dict(arrowstyle='->', color=C_ENABLES,
                                    linewidth=0.8, alpha=0.65,
                                    shrinkA=3, shrinkB=3))

    ax.annotate('', xy=pos['O-RU'], xytext=pos['O-DU'],
                arrowprops=dict(arrowstyle='<->', color=C_TOPOLOGY,
                                linewidth=1.2, shrinkA=10, shrinkB=10))
    mid_y = (pos['O-DU'][1] + pos['O-RU'][1]) / 2
    ax.text(pos['O-DU'][0], mid_y, 'Open Fronthaul',
            rotation=90, rotation_mode='anchor',
            ha='center', va='center', fontsize=6.2,
            color=C_IFACE, fontweight='bold', style='italic', zorder=12,
            path_effects=[pe.withStroke(linewidth=2.8, foreground='white')])

    # ── Asset nodes ──
    for comp in ('O-DU', 'O-RU'):
        x, y = pos[comp]
        ax.scatter(x, y, s=560, c=C_ASSET, edgecolors=C_ASSET_EDGE,
                   linewidths=1.2, zorder=10)
        ax.text(x, y, comp, ha='center', va='center',
                fontsize=7.0, fontweight='bold', color='white', zorder=11,
                path_effects=[pe.withStroke(linewidth=2.0,
                                            foreground=C_ASSET_EDGE)])

    # ── Threat nodes with descriptive labels ──
    for tid in fh_threats:
        x, y = pos[tid]
        ax.scatter(x, y, s=70, c=C_DEF_THREAT, edgecolors='white',
                   linewidths=0.8, zorder=10)
        label = threat_labels.get(tid, tid)
        ax.text(x + 0.06, y, label, ha='left', va='center',
                fontsize=6.6, color='#3A2A2E', fontweight='semibold', zorder=12,
                linespacing=1.2)

    # ── Defense nodes with descriptive labels ──
    for did in fh_defenses:
        x, y = pos[did]
        ax.scatter(x, y, s=42, c=C_DEFENSE, edgecolors='white',
                   linewidths=0.6, marker='s', zorder=10)
        label = defense_labels.get(did, did)
        ax.text(x + 0.05, y, label, ha='left', va='center',
                fontsize=6.4, color=C_DEF_TEXT, zorder=11)

    # ── "... and N more" ellipsis to indicate this is a subset ──
    # Count total threats targeting O-DU or O-RU
    all_targets = set()
    for u, v, d in G.edges(data=True):
        if d.get('edge_type') == 'targets' and v in ('O-DU', 'O-RU'):
            all_targets.add(u)
    n_more = len(all_targets) - len(fh_threats)
    # vertical ellipsis of faded threat dots — continues the threat column
    last_y = -0.40
    for k in range(3):
        ax.scatter(-0.46, last_y - 0.07 - k * 0.045,
                   s=16 - k * 4, c=C_DEF_THREAT,
                   alpha=0.45 - k * 0.12, edgecolors='none', zorder=9)
    ax.text(-0.34, last_y - 0.155, f'… +{n_more} more threats\ntargeting O-DU / O-RU',
            ha='left', va='center', fontsize=6.2, color='#6B625A',
            style='italic', linespacing=1.2)

    ax.set_xlim(-1.06, 1.40)
    ax.set_ylim(-0.64, 0.52)
    ax.set_xticks([])
    ax.set_yticks([])


def fig3_adg_combined(G):
    """Full ADG overview with zoom inset on Open Fronthaul subgraph."""
    from matplotlib.patches import ConnectionPatch

    pos, asset_pos = _compute_adg_positions(G)

    attacks = get_nodes_by_type(G, 'attack')
    defenses = get_nodes_by_type(G, 'defense')
    assets = get_nodes_by_type(G, 'asset')

    DOUBLE_COL_W = 7.16
    with plt.rc_context(IEEE_RC):
        fig = plt.figure(figsize=(DOUBLE_COL_W, 3.7))

        # Overview 53%, inset 47% (more room for larger labels)
        ax_main  = fig.add_axes([0.0, 0.0, 0.53, 1.0])
        ax_inset = fig.add_axes([0.55, 0.0, 0.45, 1.0])

        # ── Main overview with zoom box ──
        zoom_box = (-0.32, -1.05, 0.64, 0.60)
        defended_attacks = _draw_overview(ax_main, G, pos, asset_pos,
                                         zoom_box=zoom_box)

        # Legend
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor=C_ASSET,
                   markeredgecolor=C_ASSET_EDGE, markersize=6,
                   label=f'Asset ({len(assets)})'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor=C_DEF_THREAT,
                   markersize=4,
                   label=f'Defended threat ({len(defended_attacks)})'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor=C_UNDEF_THREAT,
                   markeredgecolor=C_UNDEF_EDGE, markersize=4,
                   label=f'Undefended threat ({len(attacks) - len(defended_attacks)})'),
            Line2D([0], [0], marker='s', color='w', markerfacecolor=C_DEFENSE,
                   markersize=4, label=f'Security control ({len(defenses)})'),
            Line2D([0], [0], color=C_TOPOLOGY, lw=1.5, label='Topology'),
            Line2D([0], [0], color=C_ENABLES, lw=1.0, alpha=0.6,
                   label='Attack chain'),
        ]
        ax_main.legend(handles=legend_elements,
                       loc='upper left', fontsize=6,
                       frameon=True, edgecolor='#cccccc',
                       fancybox=False, shadow=False,
                       handlelength=1.0, handletextpad=0.4,
                       labelspacing=0.25, borderpad=0.4)

        ax_main.set_xlim(-1.28, 1.28)
        ax_main.set_ylim(-1.10, 1.00)
        ax_main.axis('off')

        # ── Inset detail ──
        _draw_inset(ax_inset, G)

        # Light background, no hard border
        ax_inset.set_facecolor(C_INSET_BG)
        for spine in ax_inset.spines.values():
            spine.set_visible(False)

        # ── Connection lines: zoom box corners → inset area ──
        from matplotlib.patches import ConnectionPatch
        box_tr = (zoom_box[0] + zoom_box[2], zoom_box[1] + zoom_box[3])
        box_br = (zoom_box[0] + zoom_box[2], zoom_box[1])

        for box_corner, inset_y in [(box_tr, 0.95), (box_br, 0.05)]:
            con = ConnectionPatch(
                xyA=(0.02, inset_y), coordsA=ax_inset.transAxes,
                xyB=box_corner, coordsB=ax_main.transData,
                color=C_ZOOM, linewidth=1.0, linestyle='--', alpha=0.5,
                arrowstyle='-', zorder=20)
            fig.add_artist(con)

        _save(fig, 'fig3_adg_combined')


# =========================================================================
def generate_all_figures():
    G = build_adg()
    print(f'ADG: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges')
    print('Generating:')
    fig1_tprs(G)
    fig2_cti(G)
    fig3_adg_combined(G)
    print(f'Done → {OUTPUT_DIR}/')


if __name__ == '__main__':
    generate_all_figures()