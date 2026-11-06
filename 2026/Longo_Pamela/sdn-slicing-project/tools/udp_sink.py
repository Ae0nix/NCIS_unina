#!/usr/bin/env python3
"""Ricevitore UDP: scrive un CSV con il traffico che arriva DAVVERO a destinazione.

Colonne:  epoch_secondo, ip_sorgente, byte_ricevuti, pacchetti_ricevuti
Serve a mostrare quanto traffico d'attacco passa con e senza mitigazione.
"""
import argparse
import signal
import socket
import time
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--duration", type=float, default=0, help="0 = fino a SIGTERM")
    args = ap.parse_args()

    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(0.2)

    bins = defaultdict(lambda: [0, 0])      # (secondo, ip) -> [byte, pacchetti]
    start = time.time()
    with open(args.csv, "w") as out:
        out.write("epoch,src,bytes,packets\n")
        flushed_until = int(start)
        while not stop["flag"]:
            if args.duration and time.time() - start > args.duration:
                break
            try:
                data, (ip, _) = sock.recvfrom(65535)
                b = bins[(int(time.time()), ip)]
                b[0] += len(data)
                b[1] += 1
            except socket.timeout:
                pass
            now_s = int(time.time())
            if now_s > flushed_until:
                for (sec, ip) in sorted(k for k in bins if k[0] < now_s):
                    out.write("%d,%s,%d,%d\n" % (sec, ip, *bins.pop((sec, ip))))
                out.flush()
                flushed_until = now_s
        for (sec, ip), (nb, npk) in sorted(bins.items()):
            out.write("%d,%s,%d,%d\n" % (sec, ip, nb, npk))


if __name__ == "__main__":
    main()
