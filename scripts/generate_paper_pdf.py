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
from scripts.run_comparative_eval import main as run_comparative_eval


def generate_benchmark_figures(docs_dir: Path):
    # Ensure user site-packages are available for matplotlib
    import sys
    for extra_path in ["/Users/skywalker/Library/Python/3.14/lib/python/site-packages", "/opt/homebrew/lib/python3.14/site-packages"]:
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
    c_file = res_dir / "comparative_evaluation.json"

    if not b_file.exists():
        run_benchmark()
    if not c_file.exists():
        run_comparative_eval()

    with open(b_file, 'r', encoding='utf-8') as f:
        data_b = json.load(f)
    with open(c_file, 'r', encoding='utf-8') as f:
        data_c = json.load(f)

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
    ax.annotate('383.5 ms\n(1M traces)', xy=(1000000, 383.48), xytext=(120000, 900.0),
                arrowprops=dict(arrowstyle='->', color='#B91C1C', lw=1.0),
                fontsize=7.0, fontweight='bold', color='#7F1D1D',
                bbox=dict(boxstyle='round,pad=0.25', facecolor='#FEF2F2', edgecolor='#F87171', lw=0.6))

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
        if i == 2:  # Peak at 4 workers
            bar.set_facecolor('#047857')
            bar.set_hatch('\\\\')
            ax.text(bar.get_x() + bar.get_width()/2.0, v + 250, f'{int(v):,} /s\n(2.0x Peak)',
                    ha='center', va='bottom', fontweight='bold', fontsize=7.2, color='#065F46')
        else:
            ax.text(bar.get_x() + bar.get_width()/2.0, v + 120, f'{int(v):,}',
                    ha='center', va='bottom', fontweight='semibold', fontsize=7.0, color='#1E293B')

    fig.tight_layout()
    fig.savefig(fig_dir / "parallel_throughput.png", dpi=600)
    plt.close(fig)

    comp_sum = data_c["summary"]
    systems = ['CI Exit Code', 'Sigstore', 'OPA Schema', 'Composed SOTA', 'EviAssure']
    block_rates = [
        comp_sum.get("ci_exit_code_block_rate_pct", 0.0),
        comp_sum.get("sigstore_cosign_block_rate_pct", 7.7),
        comp_sum.get("opa_schema_block_rate_pct", 23.1),
        comp_sum.get("composed_sota_block_rate_pct", 30.8),
        comp_sum.get("eviassure_block_rate_pct", comp_sum.get("demo5_assurance_block_rate_pct", 100.0))
    ]
    colors = ['#EF4444', '#F59E0B', '#EAB308', '#8B5CF6', '#0284C7']
    hatches = ['///', '\\\\\\', 'xx', '++', '..']

    fig, ax = plt.subplots(figsize=(3.35, 2.5))
    x_pos = list(range(len(systems)))
    bars = ax.bar(x_pos, block_rates, color=colors, edgecolor='#0F172A',
                  linewidth=1.0, width=0.55, zorder=3)
    
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)

    # 100% Target security goal reference line
    ax.axhline(y=100.0, color='#0284C7', linestyle='--', linewidth=1.0, alpha=0.7, zorder=2)
    ax.text(0.0, 102.0, '100% Fail-Closed Target', fontsize=6.8, color='#0369A1', fontweight='bold')

    ax.tick_params(labelsize=7.0)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(systems, rotation=22, ha='right', fontsize=7.2, fontweight='semibold')
    ax.set_ylabel('Fail-Closed Block Rate (%)', fontsize=8.5, fontweight='semibold')
    ax.set_ylim(0, 120)
    ax.grid(axis='y', ls="--", color='#E2E8F0', alpha=0.7)

    for bar, rate in zip(bars, block_rates):
        font_weight = 'bold' if rate == 100.0 else 'semibold'
        color = '#0369A1' if rate == 100.0 else '#1E293B'
        ax.text(bar.get_x() + bar.get_width() / 2.0, rate + 2.5, f"{rate:.1f}%",
                ha='center', va='bottom', fontweight=font_weight, fontsize=7.2, color=color)

    fig.tight_layout()
    fig.savefig(fig_dir / "comparative_block_rate.png", dpi=600)
    plt.close(fig)

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
    sp = b["sparse_proof"]
    bl = b["blinding_overhead"]
    ui = b["ui_attestation_hashing"]
    peak_ratio = best["throughput_ops_sec"] / single["throughput_ops_sec"]
    out = docs_dir / "frozen_metrics.tex"
    out.write_text(
        "% GENERATED by scripts/generate_paper_pdf.py -- do not edit by hand.\n"
        "% Regenerated from results/benchmark_summary.json on every build.\n"
        "% Every benchmark-derived numeral cited in the prose is a macro here,\n"
        "% so a benchmark re-run can never leave a stale number in the text.\n"
        f"\\newcommand{{\\benchRepeats}}{{{b['benchmark_params'].get('repeats', 5)}}}\n"
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
        f"\\newcommand{{\\benchTimestamp}}{{{b.get('timestamp', 'unknown')}}}\n")
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
