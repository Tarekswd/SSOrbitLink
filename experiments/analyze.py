"""Summarise orbitlink-sim raw.csv: mean +/- 95% t-CI half-width across seeds per configuration.
Usage: python experiments/analyze.py <raw.csv> <out_dir>   (stdlib only; plot if matplotlib is present)

Security variants: None, BcbPsk, BcbPq (COSE, ML-KEM per bundle), BcbPqSession/r (COSE, one ML-KEM per
(source, destination, hour), ciphertext carried by the first r bundles of the session).
"decrypted_ratio" = bundles delivered AND decrypted before their lifetime ended, over bundles generated."""
import csv
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}
COLS = [
    ("delivery_ratio", 3), ("decrypted_ratio", 3), ("plaintext_delay_median_s", 0), ("security_overhead_bytes", 0),
    ("kem_carrying", 0), ("refused_buffer_full", 0), ("sat_buffer_util_mean", 3),
    ("overhead_tx_per_delivered_payload", 1), ("protect_us_mean", 0), ("accept_us_mean", 0),
    ("ack_bytes_per_bundle", 1), ("acks_delivered", 0),
]


def variant(r):
    if r["mode"] != "BcbPqSession":
        return r["mode"]
    k = r.get("session_refresh_every", "0")
    ts = r.get("session_refresh_s", "0")
    return (f"BcbPqSession/r{r['session_redundancy']}" + (f"k{k}" if k not in ("", "0") else "")
            + (f"t{float(ts):.0f}" if ts not in ("", "0", "0.0", "0.000") and float(ts) > 0 else "")
            + ("u" if r.get("session_refresh_uplink", "0") == "1" else "")
            + ("a" if r.get("session_ack", "0") == "1" else ""))


def ci(xs):
    xs = [x for x in xs if not math.isnan(x)]
    if len(xs) < 2:
        return (xs[0] if xs else float("nan")), None
    return st.fmean(xs), T95.get(len(xs) - 1, 1.96) * st.stdev(xs) / math.sqrt(len(xs))


def main(raw, out):
    rows = list(csv.DictReader(open(raw, newline="")))
    groups = defaultdict(list)
    for r in rows:
        groups[(r["isl"], r["load_per_gs_hour"], r["routing"], variant(r))].append(r)
    fails = sum(int(r["crypto_failures"]) for r in rows)
    lines = [
        "# OrbitLink results\n",
        f"Source `{Path(raw).name}`: {len(rows)} runs. Network metrics SIMULATED; protect/accept CPU times MEASURED. "
        f"Crypto failures across all runs: {fails}. Cells: mean +/- 95% CI half-width across seeds.\n",
        "| ISL | load/GS/h | routing | security | n | " + " | ".join(c for c, _ in COLS) + " |",
        "|" + "---|" * (5 + len(COLS)),
    ]
    summary = {}
    for k in sorted(groups):
        cells = []
        for c, d in COLS:
            m, h = ci([float(r.get(c, "nan")) for r in groups[k]])  # older runs lack newer columns
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
    variants = ["None", "BcbPsk", "BcbPq", "BcbPqSession/r1", "BcbPqSession/r3", "BcbPqSession/r1k4", "BcbPqSession/r1k8",
                "BcbPqSession/r1t300", "BcbPqSession/r1t600", "BcbPqSession/r1t900", "BcbPqSession/r1t1800",
                "BcbPqSession/r1u", "BcbPqSession/r1a"]
    variants = [v for v in variants if any(k[3] == v for k in summary)]  # older runs lack some variants
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8), sharey=True)
    for ax, isl in zip(axes, ("false", "true")):
        width = 0.8 / len(variants)
        cases = [(l, r) for l in ("20", "120") for r in ("Cgr", "Epidemic", "FirstContact")]
        for i, v in enumerate(variants):
            xs = [j + (i - (len(variants) - 1) / 2) * width for j in range(len(cases))]
            ys = [summary.get((isl, l, r, v), {}).get("decrypted_ratio", float("nan")) for l, r in cases]
            ax.bar(xs, ys, width, label=v, color=plt.cm.tab20(i))  # default cycle has 10 colours, 12 variants
        ax.set_xticks(range(len(cases)), [f"{r}\n{l}/h" for l, r in cases], fontsize=8)
        ax.set_title(f"ISL {'on' if isl == 'true' else 'off'}")
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("delivered and decrypted within lifetime (simulated)")
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=6, fontsize=7)  # below the plots: covers no bars
    fig.suptitle("OrbitLink: per-bundle vs session-amortised ML-KEM (COSE) key transport")
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    fig.savefig(out / "decrypted.png", dpi=130)
    print(f"wrote {out / 'decrypted.png'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
