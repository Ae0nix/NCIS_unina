#!/usr/bin/env python3
"""Generatore UDP a bitrate costante o a raffiche (on/off) per simulare attacchi.

Esempi:
  costante : python3 udp_flood.py --dst 10.0.0.3 --port 9999 --rate 8M --duration 30
  a raffica: python3 udp_flood.py --dst 10.0.0.3 --port 9999 --rate 8M --duration 40 \
             --burst-on 2 --burst-off 3
Stampa una riga al secondo:  epoch,pacchetti_inviati,byte_inviati
"""
import argparse
import socket
import struct
import time


def parse_rate(text):
    text = text.strip().lower()
    mult = {"k": 1e3, "m": 1e6, "g": 1e9}.get(text[-1], 1)
    return float(text[:-1] if text[-1] in "kmg" else text) * mult


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--rate", default="8M", help="bit/s di picco (es. 8M)")
    ap.add_argument("--size", type=int, default=1000, help="byte di payload")
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--burst-on", type=float, default=0, help="secondi di invio (0 = costante)")
    ap.add_argument("--burst-off", type=float, default=0, help="secondi di silenzio")
    args = ap.parse_args()

    rate = parse_rate(args.rate)
    pps = rate / 8.0 / args.size
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload_pad = b"x" * max(0, args.size - 12)
    start = time.time()
    sent_pkts = sent_bytes = 0
    due_sent = 0.0                   # pacchetti "dovuti" nella fase di invio corrente
    phase_start = start
    last_report = start
    rep_pkts = rep_bytes = 0
    seq = 0
    cycle = args.burst_on + args.burst_off
    cur_idx = 0

    while True:
        now = time.time()
        elapsed = now - start
        if elapsed >= args.duration:
            break
        sending = True
        if args.burst_on > 0 and cycle > 0:
            idx = int(elapsed // cycle)
            pos = elapsed - idx * cycle
            sending = pos < args.burst_on
            if idx != cur_idx:                    # inizia un nuovo ciclo on/off
                cur_idx = idx
                phase_start = start + idx * cycle
                due_sent = 0.0
        if sending:
            target = (now - phase_start) * pps
            while due_sent < target:
                sock.sendto(struct.pack("!Id", seq, now) + payload_pad, (args.dst, args.port))
                seq += 1
                due_sent += 1
                sent_pkts += 1
                sent_bytes += args.size
                rep_pkts += 1
                rep_bytes += args.size
        if now - last_report >= 1.0:
            print("%d,%d,%d" % (now, rep_pkts, rep_bytes), flush=True)
            rep_pkts = rep_bytes = 0
            last_report = now
        time.sleep(0.005)
    print("# totale: %d pacchetti, %d byte" % (sent_pkts, sent_bytes), flush=True)


if __name__ == "__main__":
    main()
