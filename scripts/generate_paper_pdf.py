#!/usr/bin/env python3
"""
USENIX Security Paper PDF Builder & Multi-Plot Figure Generator for EviAssure.
"""

import sys
import shutil
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.run_release_benchmark import main as run_benchmark


def generate_benchmark_figures(docs_dir: Path):
    # matplotlib is an optional extra and is frequently installed into the
    # per-user site-packages directory rather than the interpreter's own.
    # Resolve that directory portably instead of hard-coding a path: a literal
    # /Users/<name>/... path both breaks on every other machine and is an
    # author fingerprint in a double-blind artifact.
    import site
    import sys
    for extra_path in filter(None, [getattr(site, "getusersitepackages", lambda: None)()]):
        if extra_path not in sys.path and Path(extra_path).exists():
            sys.path.insert(0, extra_path)

    import matplotlib.pyplot as plt
    import json

    # Configure publication-grade aesthetics matching 2024-2026 USENIX/IEEE S&P standards
    plt.rcParams.update({
        'font.family': 'sans-serif',
        'font.sans-serif': ['Helvetica', 'DejaVu Sans', 'Arial'],
        'figure.dpi': 600,
        'savefig.dpi': 600,
        'savefig.bbox': 'tight',
        'axes.spines.top': False,
        'axes.spines.right': False,
        'axes.grid': True,
        'axes.grid.which': 'both',
        'grid.color': '#E2E8F0',
        'grid.linestyle': '--',
        'grid.linewidth': 0.6,
        'grid.alpha': 0.7,
        'xtick.direction': 'out',
        'ytick.direction': 'out',
        'xtick.major.size': 3.5,
        'ytick.major.size': 3.5,
    })

    res_dir = docs_dir.parent / "results"
    b_file = res_dir / "benchmark_summary.json"

    if not b_file.exists():
        run_benchmark()

    with open(b_file, 'r', encoding='utf-8') as f:
        data_b = json.load(f)

    fig_dir = docs_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # Figure 2: Merkle Tree Attestation Scaling (N=10 to N=1,000,000)
    # -------------------------------------------------------------
    scaling = data_b["merkle_scaling"]
    traces = [s["trace_count"] for s in scaling]
    pkg_lat = [s["packaging_latency_ms"] for s in scaling]
    merkle_build = [s["merkle_tree_build_ms"] for s in scaling]
    pkg_err = [s.get("packaging_latency_ms_std", 0.0) for s in scaling]
    merkle_err = [s.get("merkle_tree_build_ms_std", 0.0) for s in scaling]

    fig, ax = plt.subplots(figsize=(3.35, 2.5))
    
    # Merkle build curve with error band and prominent markers
    ax.plot(traces, merkle_build, 's-', color='#B91C1C', linewidth=1.8,
            markersize=5.5, markeredgewidth=1.2, markerfacecolor='white',
            label='Merkle Tree Construction', zorder=4)
    ax.fill_between(traces,
                    [max(0.001, m - e) for m, e in zip(merkle_build, merkle_err)],
                    [m + e for m, e in zip(merkle_build, merkle_err)],
                    color='#B91C1C', alpha=0.12, zorder=2)

    # Packaging latency curve with error band and prominent markers
    ax.plot(traces, pkg_lat, 'o-', color='#1D4ED8', linewidth=1.8,
            markersize=5.5, markeredgewidth=1.2, markerfacecolor='white',
            label='Envelope Packaging Latency', zorder=4)
    ax.fill_between(traces,
                    [max(0.001, p - e) for p, e in zip(pkg_lat, pkg_err)],
                    [p + e for p, e in zip(pkg_lat, pkg_err)],
                    color='#1D4ED8', alpha=0.12, zorder=2)

    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.set_ylim(bottom=5e-4, top=3e3)
    ax.tick_params(labelsize=7.5)
    ax.set_xlabel('Trace Count $N$ (log scale)', fontsize=8.5, fontweight='semibold')
    ax.set_ylabel('Execution Time (ms, log scale)', fontsize=8.5, fontweight='semibold')
    
    # Annotated callout at 1M placed cleanly in the open upper-right space above the curves
    # Read the callout from the data. It was hard-coded at 383.5 ms while the
    # benchmark recorded 378.0 -- a figure that silently contradicted the prose
    # macro \merkleBuildOneMMs. Figures drift exactly like numerals do, and the
    # frozen-metrics discipline has to cover them too.
    _n1m = next(r for r in scaling if r['trace_count'] == 1000000)
    _n1m_ms = _n1m['merkle_tree_build_ms']
    # Place the callout in the open band BETWEEN the two curves at the right
    # of the axes (below the Merkle curve, above the packaging curve) and point
    # the arrow up at the 1M marker. The previous fixed position (120k, 900 ms)
    # was chosen when the 1M build took ~380 ms; once the domain-separated
    # tree pushed it past 1.8 s the box sat on top of the line and the marker.
    # Anchoring the box's right edge at 8e5 and its bottom at the geometric
    # midpoint of the two curves' right-hand values keeps it clear of both
    # whatever the measured numbers are.
    _y_top = min(m for t, m in zip(traces, merkle_build) if t >= 1e5)   # Merkle curve near the right
    _y_bot = max(pkg_lat)                                                # packaging curve ceiling
    _y_box = (_y_top * _y_bot) ** 0.5 / 3.0                              # below the log-midpoint
    ax.annotate(f'{_n1m_ms:.1f} ms\n(1M traces)', xy=(1000000, _n1m_ms), xytext=(8e5, _y_box),
                ha='right', va='bottom',
                arrowprops=dict(arrowstyle='->', color='#B91C1C', lw=1.0,
                                shrinkA=2, shrinkB=4),
                fontsize=7.0, fontweight='bold', color='#7F1D1D',
                bbox=dict(boxstyle='round,pad=0.25', facecolor='#FEF2F2', edgecolor='#F87171', lw=0.6),
                zorder=6)

    ax.legend(fontsize=7.2, frameon=True, facecolor='white', edgecolor='#CBD5E1', loc='upper left')
    fig.tight_layout()
    fig.savefig(fig_dir / "merkle_scaling.png", dpi=600)
    plt.close(fig)

    # -------------------------------------------------------------
    # Figure 3: Multi-Process Parallel Verifier Throughput
    # -------------------------------------------------------------
    p_tp = data_b["parallel_throughput"]
    workers = [v["num_workers"] for v in p_tp.values()]
    ops = [v["throughput_ops_sec"] for v in p_tp.values()]
    ops_err = [v.get("throughput_ops_sec_std", 0.0) for v in p_tp.values()]

    fig, ax = plt.subplots(figsize=(3.35, 2.5))
    x_pos = list(range(len(workers)))
    labels = [f'{w}w' for w in workers]
    
    bars = ax.bar(x_pos, ops, yerr=ops_err, capsize=3, width=0.52,
                  color='#059669', edgecolor='#064E3B', linewidth=1.0,
                  hatch='//', zorder=3)

    # Single-worker baseline reference line
    ax.axhline(y=ops[0], color='#64748B', linestyle=':', linewidth=1.0, zorder=2, label='1-Worker Baseline')

    ax.tick_params(labelsize=7.5)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels, fontsize=8.0, fontweight='semibold')
    ax.set_xlabel('Process Pool Size (Workers)', fontsize=8.5, fontweight='semibold')
    ax.set_ylabel('Verifier Throughput (ops/sec)', fontsize=8.5, fontweight='semibold')
    ax.set_ylim(0, max(ops) * 1.25)
    ax.grid(axis='y', ls="--", color='#E2E8F0', alpha=0.7)

    # Bar value labels & peak callout
    for i, (bar, v) in enumerate(zip(bars, ops)):
        if v == max(ops):   # the actual peak, not a hard-coded index
            bar.set_facecolor('#047857')
            bar.set_hatch('\\\\')
            _ratio = v / ops[0]
            ax.text(bar.get_x() + bar.get_width()/2.0, v + 250, f'{int(v):,} /s\n({_ratio:.1f}x Peak)',
                    ha='center', va='bottom', fontweight='bold', fontsize=7.2, color='#065F46')
        else:
            ax.text(bar.get_x() + bar.get_width()/2.0, v + 120, f'{int(v):,}',
                    ha='center', va='bottom', fontweight='semibold', fontsize=7.0, color='#1E293B')

    fig.tight_layout()
    fig.savefig(fig_dir / "parallel_throughput.png", dpi=600)
    plt.close(fig)

    # -------------------------------------------------------------
    # Figure 4: Executed baseline comparison, with Wilson intervals
    #
    # This replaces an earlier chart built from results/comparative_evaluation
    # .json, which plotted 100% for EviAssure against 30.8% for a "composed"
    # baseline and carried a "Sigstore/Cosign" bar. Section 7.7 withdraws that
    # comparison: those baselines were strawmen scored against a vector set
    # derived from our own check list. Plotting withdrawn numbers is worse than
    # stating them, because a reader takes the picture and never reaches the
    # retraction.
    #
    # The replacement reads the EXECUTED baselines from
    # results/security_evaluation.json and draws the 95% Wilson interval on
    # every bar. The intervals overlap, and the figure is supposed to show
    # that: with 17 vectors the evaluation cannot support a strong
    # quantitative separation, which is exactly what the text says.
    # -------------------------------------------------------------
    sec_path = res_dir / "security_evaluation.json"
    if sec_path.exists():
        with open(sec_path, "r", encoding="utf-8") as f:
            sec = json.load(f)
        summ = sec["vectors"]["summary"]

        def _find(sub, default=None):
            for k, v in summ.items():
                if sub.lower() in k.lower():
                    return v
            return default

        rows = [
            ("Status gate",   _find("status gate")),
            ("OPA Rego",      _find("OPA")),
            ("in-toto/DSSE",  _find("DSSE")),
            ("TUF",           _find("TUF")),
            ("Composed",      _find("Composed")),
            ("EviAssure",     summ.get("eviassure")),
        ]
        rows = [(n, m) for n, m in rows if m]

        names = [n for n, _ in rows]
        vals = [m["rate_pct"] for _, m in rows]
        lo = [max(0.0, m["rate_pct"] - m["ci95_low_pct"]) for _, m in rows]
        hi = [max(0.0, m["ci95_high_pct"] - m["rate_pct"]) for _, m in rows]

        fig, ax = plt.subplots(figsize=(3.35, 2.6))
        xs = list(range(len(names)))
        colours = ['#94A3B8'] * (len(names) - 1) + ['#0284C7']
        bars = ax.bar(xs, vals, yerr=[lo, hi], capsize=3, width=0.6,
                      color=colours, edgecolor='#0F172A', linewidth=0.9, zorder=3)
        bars[-1].set_hatch('..')

        ax.set_xticks(xs)
        ax.set_xticklabels(names, rotation=30, ha='right', fontsize=7.2)
        ax.set_ylabel('Vectors blocked (%)', fontsize=8.5, fontweight='semibold')
        ax.set_ylim(0, 112)
        ax.tick_params(labelsize=7.5)
        ax.grid(axis='y', ls='--', color='#E2E8F0', alpha=0.7)

        for x, (n, m) in zip(xs, rows):
            ax.text(x, m["ci95_high_pct"] + 2.5, f'{m["k"]}/{m["n"]}',
                    ha='center', va='bottom', fontsize=6.8,
                    fontweight='bold' if n == 'EviAssure' else 'normal',
                    color='#0C4A6E' if n == 'EviAssure' else '#334155')

        fig.tight_layout()
        fig.savefig(fig_dir / "comparative_block_rate.png", dpi=600)
        plt.close(fig)

        # ---------------------------------------------------------
        # Figure 5: coverage matrix -- WHICH vector each verifier stops.
        #
        # Figure 4 gives the totals with intervals; the prose of Sections
        # 7.5-7.6 used to enumerate, vector by vector, what receipts, chains
        # and the composed pipeline miss. A matrix carries that in one glance
        # and cannot drift from the artifact, because every cell is read from
        # results/security_evaluation.json: panel (a) is the scored tamper
        # suite against the executed baselines, panel (b) the omission suite
        # against the completeness baselines. Two fills only (stopped / not),
        # each with a glyph so the figure survives greyscale printing; the
        # honest control OC1 is drawn in a third, neutral style because there
        # "approved" is the correct outcome.
        # ---------------------------------------------------------
        from matplotlib.patches import Rectangle
        pv = [v for v in sec["vectors"]["per_vector"] if v.get("scored", True)]
        tamper_cols = [v["vector_id"] for v in pv]

        def _col(v, sub):
            for k, val in v.items():
                if isinstance(val, bool) and sub.lower() in k.lower():
                    return val
            return False
        tamper_rows = [
            ("Status gate",  lambda v: _col(v, "status gate")),
            ("OPA Rego",     lambda v: _col(v, "OPA")),
            ("in-toto/DSSE", lambda v: _col(v, "DSSE")),
            ("TUF",          lambda v: _col(v, "TUF")),
            ("Composed",     lambda v: _col(v, "Composed")),
            ("EviAssure",    lambda v: bool(v.get("eviassure_blocked"))),
        ]
        om = sec["omission"]["per_vector"]
        om_cols = [v["vector_id"] for v in om]

        def _om(v, sub):
            for k, val in v["blocked_by"].items():
                if sub.lower() in k.lower():
                    return bool(val)
            return False
        om_rows = [
            ("in-toto/DSSE",      lambda v: _om(v, "DSSE")),
            ("TUF",               lambda v: _om(v, "TUF")),
            ("Hash chain",        lambda v: _om(v, "chain")),
            ("Receipts",          lambda v: _om(v, "receipt")),
            ("EviAssure, no WTC", lambda v: _om(v, "without")),
            ("EviAssure + WTC",   lambda v: _om(v, "+ WTC")),
        ]

        HIT, MISS, CTRL, INK = '#1D4ED8', '#E5E7EB', '#D1FAE5', '#0F172A'
        fig, (ax1, ax2) = plt.subplots(
            2, 1, figsize=(3.35, 2.9),
            gridspec_kw={'height_ratios': [1, 1], 'hspace': 0.55})

        def _draw(ax, cols, rows, control_ids=()):
            for r, (name, fn) in enumerate(rows):
                y = len(rows) - 1 - r
                hits = 0
                for c, cid in enumerate(cols):
                    v = next(x for x in (pv if cols is tamper_cols else om)
                             if x["vector_id"] == cid)
                    stopped = fn(v)
                    is_ctrl = cid in control_ids
                    if is_ctrl:
                        face, glyph, gcol = CTRL, '\u2713', '#065F46'   # approved, as it must be
                    elif stopped:
                        face, glyph, gcol = HIT, '\u2713', 'white'
                        hits += 1
                    else:
                        face, glyph, gcol = MISS, '\u00b7', '#6B7280'
                    ax.add_patch(Rectangle((c, y), 0.92, 0.92, facecolor=face,
                                           edgecolor='white', linewidth=0.6))
                    ax.text(c + 0.46, y + 0.46, glyph, ha='center', va='center',
                            fontsize=6.0, color=gcol, fontweight='bold')
                n = len([c for c in cols if c not in control_ids])
                ax.text(len(cols) + 0.15, y + 0.46, f'{hits}/{n}', ha='left', va='center',
                        fontsize=7.0, color=INK,
                        fontweight='bold' if name.startswith('EviAssure +') or name == 'EviAssure' else 'normal')
            ax.grid(False)
            ax.set_xlim(0, len(tamper_cols) + 1.6)     # same cell size in both panels
            ax.set_ylim(0, len(rows))
            ax.set_xticks([c + 0.46 for c in range(len(cols))])
            ax.set_xticklabels(cols, fontsize=6.2, rotation=90)
            ax.set_yticks([len(rows) - 1 - r + 0.46 for r in range(len(rows))])
            ax.set_yticklabels([n for n, _ in rows], fontsize=7.0)
            ax.tick_params(length=0, pad=1.5)
            for sp in ax.spines.values():
                sp.set_visible(False)
            ax.set_aspect('equal')

        _draw(ax1, tamper_cols, tamper_rows)
        ax1.set_title('(a) Tamper vectors (Table 1): blocked', fontsize=7.5, loc='left', pad=2)
        _draw(ax2, om_cols, om_rows, control_ids=('OC1',))
        ax2.set_title('(b) Omission vectors (Table 2): detected (OC1 must be approved)',
                      fontsize=7.5, loc='left', pad=2)
        fig.savefig(fig_dir / "coverage_matrix.png", dpi=600, bbox_inches='tight')
        plt.close(fig)
    else:
        print("[i] results/security_evaluation.json absent -- comparison figure skipped")

    print(f"[+] High-resolution 600 DPI benchmark figures saved to: {fig_dir}")



def write_frozen_metrics(res_dir, docs_dir):
    """Emit the headline numbers as LaTeX macros the manuscript \\input{}s.

    The benchmark re-runs on every build, so any figure typed into the abstract
    by hand is stale the moment the next build finishes. Three different values
    for the same throughput measurement were in circulation before this existed.
    Defining them here means the number in the paper IS the number in the
    artifact, by construction, and cannot drift.
    """
    import json
    b = json.loads((res_dir / "benchmark_summary.json").read_text())
    tp = b["parallel_throughput"]
    best_k = max(tp, key=lambda k: tp[k]["throughput_ops_sec"])
    best = tp[best_k]
    single = tp["workers_1"]
    n1m = next(r for r in b["merkle_scaling"] if r["trace_count"] == 1000000)
    n100 = next(r for r in b["merkle_scaling"] if r["trace_count"] == 100000)
    n1k = next(r for r in b["merkle_scaling"] if r["trace_count"] == 1000)
    sp = b["sparse_proof"]
    bl = b["blinding_overhead"]
    ui = b["ui_attestation_hashing"]
    peak_ratio = best["throughput_ops_sec"] / single["throughput_ops_sec"]
    # Witness-protocol overhead (Section 4.2) lives in its own results file so
    # that its platform label travels with its numbers; the manuscript quotes
    # both through the macros below.
    wo = json.loads((res_dir / "witness_overhead.json").read_text())
    wo_big = max(wo["rows"], key=lambda r: r["actions"])
    wo_cpu = wo["platform"].get("cpu_model", "unknown")
    wo_cpu_short = (wo_cpu.replace("(R)", "").replace("(TM)", "").replace("Processor", "")
                    .replace("CPU", "").split("@")[0].strip())
    wo_cpu_short = " ".join(wo_cpu_short.split()) or "unknown"
    out = docs_dir / "frozen_metrics.tex"
    out.write_text(
        "% GENERATED by scripts/generate_paper_pdf.py -- do not edit by hand.\n"
        "% Regenerated from results/benchmark_summary.json on every build.\n"
        "% Every benchmark-derived numeral cited in the prose is a macro here,\n"
        "% so a benchmark re-run can never leave a stale number in the text.\n"
        f"\\newcommand{{\\benchRepeats}}{{{b['benchmark_params'].get('repeats', 5)}}}\n"
        # Raw-log sizes were typed into the prose as 222.6 and 220,705.03 while
        # the artifact recorded 221.68 and 220704.11. Small, but it is exactly
        # the drift this file exists to make impossible, and the paper gate
        # caught it. Bind them.
        f"\\newcommand{{\\rawSizeOneKKb}}{{{n1k['bundle_size_kb']:,.2f}}}\n"
        f"\\newcommand{{\\rawSizeOneMKb}}{{{n1m['bundle_size_kb']:,.0f}}}\n"
        f"\\newcommand{{\\peakThroughput}}{{{best['throughput_ops_sec']:,.0f}}}\n"
        f"\\newcommand{{\\peakThroughputStd}}{{{best.get('throughput_ops_sec_std', 0):,.0f}}}\n"
        f"\\newcommand{{\\peakWorkers}}{{{best['num_workers']}}}\n"
        f"\\newcommand{{\\singleWorkerThroughput}}{{{single['throughput_ops_sec']:,.0f}}}\n"
        f"\\newcommand{{\\peakRatio}}{{{peak_ratio:.1f}}}\n"
        f"\\newcommand{{\\merkleBuildMs}}{{{n100['merkle_tree_build_ms']:.1f}}}\n"
        f"\\newcommand{{\\merkleBuildOneMMs}}{{{n1m['merkle_tree_build_ms']:.2f}}}\n"
        f"\\newcommand{{\\merkleBuildOneMStd}}{{{n1m.get('merkle_tree_build_ms_std', 0):.2f}}}\n"
        f"\\newcommand{{\\packagingOverhead}}{{{n100['packaging_overhead_pct']:.4f}}}\n"
        f"\\newcommand{{\\sparseProofNodes}}{{{sp['proof_nodes']}}}\n"
        f"\\newcommand{{\\sparseProofSizeKb}}{{{sp['proof_size_kb']:.2f}}}\n"
        f"\\newcommand{{\\sparseProofGenMs}}{{{sp['gen_latency_ms']:.3f}}}\n"
        f"\\newcommand{{\\sparseProofGenStdMs}}{{{sp.get('gen_latency_ms_std', 0):.3f}}}\n"
        f"\\newcommand{{\\sparseProofVerifyMs}}{{{sp['verify_latency_ms']:.3f}}}\n"
        f"\\newcommand{{\\sparseProofVerifyStdMs}}{{{sp.get('verify_latency_ms_std', 0):.3f}}}\n"
        f"\\newcommand{{\\blindingPerRecordMs}}{{{bl['per_record_ms']:.4f}}}\n"
        f"\\newcommand{{\\blindingTotalMs}}{{{bl['total_ms']:.1f}}}\n"
        f"\\newcommand{{\\blindingTotalStdMs}}{{{bl.get('total_ms_std', 0):.1f}}}\n"
        f"\\newcommand{{\\domHashMs}}{{{ui['dom_hash_ms_per_step']:.4f}}}\n"
        f"\\newcommand{{\\domHashStdMs}}{{{ui.get('dom_hash_ms_per_step_std', 0):.4f}}}\n"
        f"\\newcommand{{\\shotDigestMs}}{{{ui['screenshot_digest_ms_per_step']:.4f}}}\n"
        f"\\newcommand{{\\shotDigestStdMs}}{{{ui.get('screenshot_digest_ms_per_step_std', 0):.4f}}}\n"
        f"\\newcommand{{\\benchTimestamp}}{{{b.get('timestamp', 'unknown')}}}\n"
        f"\\newcommand{{\\witnessActions}}{{{wo_big['actions']:,}}}\n"
        f"\\newcommand{{\\witnessCount}}{{{wo_big['witnesses']}}}\n"
        f"\\newcommand{{\\witnessReceiptBytes}}{{{wo_big['receipt_bytes']}}}\n"
        f"\\newcommand{{\\witnessIssueUs}}{{{wo_big['issue_us_per_receipt']:.0f}}}\n"
        f"\\newcommand{{\\witnessCloseUs}}{{{wo_big['close_us_per_witness']:.0f}}}\n"
        f"\\newcommand{{\\witnessReconcileMs}}{{{wo_big['reconcile_ms']:.0f}}}\n"
        f"\\newcommand{{\\witnessReconcilePerActionUs}}{{{wo_big['reconcile_us_per_action']:.0f}}}\n"
        f"\\newcommand{{\\witnessPlatform}}{{{wo_cpu_short}}}\n"
        f"\\newcommand{{\\witnessRepeats}}{{{wo.get('repeats', 5)}}}\n")
    print(f"[*] Froze headline metrics -> {out.name} "
          f"(throughput={best['throughput_ops_sec']:,.0f}, "
          f"overhead={n100['packaging_overhead_pct']:.3f}%)")
    return out

def compile_latex_pdf(docs_dir: Path) -> Path:
    tex_file = docs_dir / "usenix_paper_manuscript.tex"
    pdflatex_bin = (shutil.which("pdflatex") or (shutil.which("pdflatex") or "/Library/TeX/texbin/pdflatex"))
    bibtex_bin = (shutil.which("bibtex") or "/Library/TeX/texbin/bibtex")

    print(f"[*] Compiling LaTeX manuscript: {tex_file.name} using pdflatex...")

    # First pdflatex pass
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # BibTeX pass
    subprocess.run(
        [bibtex_bin, "usenix_paper_manuscript"],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Second & Third pdflatex passes
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    subprocess.run(
        [pdflatex_bin, "-interaction=nonstopmode", tex_file.name],
        cwd=docs_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    pdf_path = docs_dir / "usenix_paper_manuscript.pdf"
    if pdf_path.exists():
        print(f"[SUCCESS] Compiled USENIX Security paper PDF: {pdf_path}")
        return pdf_path
    else:
        raise RuntimeError("PDF compilation failed to produce output file.")


def main():
    docs_dir = Path(__file__).parent.parent / "docs"
    
    print("=== USENIX Security Paper PDF Builder & Figure Generator ===")
    
    try:
        generate_benchmark_figures(docs_dir)
    except Exception as e:
        print(f"[!] Warning: Figure generation error ({e})")

    write_frozen_metrics(Path(__file__).parent.parent / "results", docs_dir)
    pdf_path = compile_latex_pdf(docs_dir)
    print(f"\n[+] PDF generation complete: {pdf_path}")


if __name__ == "__main__":
    main()
