#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import pandas as pd
import matplotlib.pyplot as plt


def main():
    df = pd.read_csv("telemetry.csv")
    if df.empty:
        print("Errore: telemetry.csv vuoto.")
        sys.exit(1)

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(11, 9.5), sharex=True)
    plt.subplots_adjust(hspace=0.26)

    t = df["timestamp_s"].to_numpy(dtype=float)
    stage = df["max_mitigation_stage"].to_numpy(dtype=float)

    # 1. Service Slicing su bottleneck condiviso s1-eth3 (25 Mbps)
    ax1.plot(t, df["h1_gold_mbps"], label="h1 -> Slice Gold (Porta 5001: 15 Mbps richiesti, Min-Rate Garantito 15 Mbps)",
             color="tab:blue", linewidth=2.4, marker="o", markersize=4)
    ax1.plot(t, df["h2_silver_mbps"], label="h2 -> Slice Silver (Porta 5002: 14 Mbps richiesti, Max-Rate HTB 10 Mbps)",
             color="tab:green", linewidth=2.2, marker="s", markersize=4)
    ax1.axhline(15.0, color="tab:blue", linestyle=":", linewidth=1.2, alpha=0.8, label="SLA Garantito Slice Gold (15.0 Mbps)")
    ax1.set_ylabel("Throughput (Mbps)", fontweight="bold")
    ax1.set_title("1. Verifica QoS e Service Slicing sotto Congestione su Bottleneck Condiviso s1-eth3 (25 Mbps)", fontweight="bold")
    ax1.set_ylim(0, 22)
    ax1.grid(True, linestyle="--", alpha=0.6)
    ax1.legend(loc="upper right", fontsize=9)

    # 2. Traffico attaccante: Iniettato su Edge s2 vs Consegnato su Core s3
    ax2.plot(t, df["attacker_edge_mbps"], label="h3 Traffico Iniettato su Porta Access s2-eth1 (26 Mbps UDP Flood)",
             color="tab:red", linestyle="--", linewidth=2.0, alpha=0.85)
    ax2.plot(t, df["attacker_delivered_mbps"], label="h3 Traffico Consegnato al Server su Core s3 (Dopo Meter 3 Mbps / Drop)",
             color="tab:orange", linewidth=2.6, marker="^", markersize=5)
    ax2.axhline(3.0, color="gray", linestyle=":", linewidth=1.2, label="Soglia Policing Stadio 1 (3.0 Mbps)")
    ax2.set_ylabel("Throughput (Mbps)", fontweight="bold")
    ax2.set_title("2. Mitigazione Attacco DoS: Traffico Iniettato su Edge Switch s2 vs Consegnato su Core Switch s3", fontweight="bold")
    ax2.set_ylim(-1, 45)
    ax2.grid(True, linestyle="--", alpha=0.6)
    ax2.legend(loc="upper right", fontsize=9)

    # 3. Macchina a stati nel controller Ryu
    ax3.step(t, stage, where="post", color="tab:purple", linewidth=2.5)
    ax3.fill_between(t, 0, stage, step="post", color="tab:purple", alpha=0.2)
    ax3.set_yticks([0, 1, 2])
    ax3.set_yticklabels(["0: NORMAL", "1: METER (3 Mbps)", "2: DROP (Quarantena)"])
    ax3.set_ylabel("Stato Difesa", fontweight="bold")
    ax3.set_xlabel("Tempo di Simulazione (secondi)", fontweight="bold")
    ax3.set_title("3. Evoluzione Temporale della Macchina a Stati nel Controller Ryu", fontweight="bold")
    ax3.set_ylim(-0.2, 2.4)
    ax3.grid(True, linestyle="--", alpha=0.6)

    output_img = "risultati_dos_slicing.png"
    plt.savefig(output_img, dpi=300, bbox_inches="tight")
    print(f"Grafico salvato in: {output_img}")


if __name__ == "__main__":
    main()