#!/usr/bin/env python3
"""Grafico dello slicing dinamico dai CSV di results/dynamic/timeline.csv (serve matplotlib).

    python3 plot_results.py            # scrive results/dynamic/timeline.png
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(HERE, "results", "dynamic", "timeline.csv")
rows = list(csv.DictReader(open(src)))
t = [float(r["t_s"]) for r in rows]
tcp = [float(r["tcp_mbps"]) for r in rows]
vid = [float(r["video_mbps"]) for r in rows]

fig, ax = plt.subplots(figsize=(7.5, 3.4))
ax.plot(t, tcp, color="#c2410c", lw=2, label="TCP normale (h2 -> h4)")
ax.plot(t, vid, color="#1d5fa8", lw=2, label="video UDP/9999 (h1 -> h3)")
if any(v > 0 for v in vid):
    on = [x for x, v in zip(t, vid) if v > 0]
    ax.axvspan(min(on) - 1, max(on), color="#1d5fa8", alpha=.08)
ax.set_xlabel("tempo (s)")
ax.set_ylabel("Mbit/s")
ax.set_ylim(0, 11)
ax.grid(alpha=.3)
ax.legend(loc="center right", fontsize=8)
ax.set_title("Slicing dinamico: il traffico normale cede la slice alta al video")
fig.tight_layout()
dst = os.path.join(HERE, "results", "dynamic", "timeline.png")
fig.savefig(dst, dpi=160)
print("scritto", dst)
