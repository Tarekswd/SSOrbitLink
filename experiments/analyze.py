"""Summarise orbitlink-sim raw.csv: mean +/- 95% t-CI half-width across seeds per configuration.
Usage: python experiments/analyze.py <raw.csv> <out_dir>   (stdlib only; plot if matplotlib is present)"""
import csv
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}
COLS = [
    ("delivery_ratio", 3), ("delay_median_s", 0), ("delay_p95_s", 0), ("expired_copies", 0), ("refused_buffer_full", 0),
    ("overhead_tx_per_delivered_payload", 2), ("security_overhead_bytes", 0), ("protect_us_mean", 0),
    ("accept_us_mean", 0), ("sat_buffer_util_mean", 3), ("energy_j_estimate", 1),
]


def ci(xs):
    xs = [x for x in xs if not math.isnan(x)]
    if len(xs) < 2:
        return (xs[0] if xs else float("nan")), None
    return st.fmean(xs), T95.get(len(xs) - 1, 1.96) * st.stdev(xs) / math.sqrt(len(xs))


def main(raw, out):
    rows = list(csv.DictReader(open(raw, newline="")))
    groups = defaultdict(list)
    for r in rows:
        groups[(r["isl"], r["load_per_gs_hour"], r["routing"], r["mode"])].append(r)
    fails = sum(int(r["crypto_failures"]) for r in rows)
    lines = [
        "# OrbitLink results\n",
        f"Source `{Path(raw).name}`: {len(rows)} runs. Network metrics SIMULATED; protect/accept CPU times MEASURED; "
        f"energy ESTIMATED. Crypto failures across all runs: {fails}. Cells: mean +/- 95% CI half-width across seeds.\n",
        "| ISL | load/GS/h | routing | mode | n | " + " | ".join(c for c, _ in COLS) + " |",
        "|" + "---|" * (5 + len(COLS)),
    ]
    summary = {}
    for k in sorted(groups):
        cells = []
        for c, d in COLS:
            m, h = ci([float(r[c]) for r in groups[k]])
            summary.setdefault(k, {})[c] = m
            cells.append(f"{m:.{d}f}" + (f" +/- {h:.{d}f}" if h is not None else ""))
        lines.append(f"| {' | '.join(k)} | {len(groups[k])} | " + " | ".join(cells) + " |")
    out = Path(out)
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print((out / "summary.md").read_text())
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot")
        return
    fig, axes = plt.subplots(1, 2, figsize=(11, 4), sharey=True)
    modes = ["None", "Bib", "BcbPsk", "BcbPq"]
    for ax, isl in zip(axes, ("false", "true")):
        width = 0.2
        for i, mode in enumerate(modes):
            xs, ys = [], []
            for j, (load, routing) in enumerate((l, r) for l in ("20", "120") for r in ("Cgr", "Epidemic", "FirstContact")):
                v = summary.get((isl, load, routing, mode), {}).get("delivery_ratio")
                if v is not None:
                    xs.append(j + (i - 1.5) * width)
                    ys.append(v)
            ax.bar(xs, ys, width, label=mode)
        ax.set_xticks(range(6), [f"{r}\n{l}/h" for l in ("20", "120") for r in ("CGR", "Epid.", "First")], fontsize=8)
        ax.set_title(f"ISL {'on' if isl == 'true' else 'off'}")
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("delivery ratio (simulated)")
    axes[0].legend(fontsize=8)
    fig.suptitle("OrbitLink: delivery by routing, load and bundle security mode")
    fig.tight_layout()
    fig.savefig(out / "delivery.png", dpi=130)
    print(f"wrote {out / 'delivery.png'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
