#!/usr/bin/env python3
"""Esperimenti automatici (richiede sudo, Mininet, OVS, iperf e il controller gia' avviato).

  Terminale 1:  SLICE_MODE=service ryu-manager controller/slice_controller.py
  Terminale 2:  sudo python3 run_experiment.py --mode service

Il --mode deve coincidere con quello del controller. Risultati in results/<mode>/.
  topology : matrice di raggiungibilita', contatori di s2 e s3 e verifica con tcpdump
  service  : video UDP/9999 contro TCP normale, da soli e insieme
  dynamic  : serie temporale; il TCP normale prende la slice alta, la cede al video, la riprende
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "controller"))
import slice_topology as T                                             
import topology                                                       

HERE = os.path.dirname(os.path.abspath(__file__))
UNIT = {"K": 1e-3, "M": 1.0, "G": 1e3}
LINE = re.compile(r"(\d+\.\d+)-\s*(\d+\.\d+)\s+sec\s+.*?([\d.]+)\s+([KMG])bits/sec")


def intervals(text):
    """[(t_fine, Mbit/s)] dalle righe -i 1 di iperf; scarta il riepilogo finale."""
    rows = []
    for m in LINE.finditer(text):
        a, b, v, u = float(m.group(1)), float(m.group(2)), float(m.group(3)), m.group(4)
        if b - a <= 1.5:
            rows.append((b, v * UNIT[u]))
    return rows


def mean(rows):
    return sum(v for _, v in rows) / len(rows) if rows else 0.0


def read(path):
    try:
        return open(path).read()
    except OSError:
        return ""


def rx_packets(iface):
    try:
        return int(open("/sys/class/net/%s/statistics/rx_packets" % iface).read())
    except OSError:
        return -1


def ping_ok(src, dst_ip, count=3):
    out = src.cmd("ping -c %d -W 1 %s" % (count, dst_ip))
    m = re.search(r"(\d+) received", out)
    return bool(m and int(m.group(1)) > 0)


def ping_matrix(net):
    res = {}
    for a in T.HOSTS:
        for b in T.HOSTS:
            if a != b:
                res[(a, b)] = ping_ok(net.get(a), T.HOSTS[b].ip, 2)
    return res


def start_server(host, out, udp_port=None):
    cmd = ["iperf", "-s", "-i", "1"] + (["-u", "-p", str(udp_port)] if udp_port else [])
    return host.popen(cmd, stdout=open(out, "w"), stderr=open(os.devnull, "w"))


def start_client(host, dst, out, secs, udp_port=None, rate="8M"):
    cmd = ["iperf", "-c", T.HOSTS[dst].ip, "-t", str(secs), "-i", "1"]
    if udp_port:
        cmd += ["-u", "-p", str(udp_port), "-b", rate]
    return host.popen(cmd, stdout=open(out, "w"), stderr=open(os.devnull, "w"))


BACKLOG = re.compile(r"backlog\s+(\d+)b")


def queue_backlog(ifaces):
    """Byte ancora accodati (somma di tutte le classi HTB) sulle interfacce date."""
    total = 0
    for ifc in ifaces:
        txt = subprocess.run(["tc", "-s", "class", "show", "dev", ifc],
                             capture_output=True, text=True).stdout
        total += sum(int(x) for x in BACKLOG.findall(txt))
    return total


def wait_queue_drain(log, ifaces=("s1-eth4", "s4-eth4"), timeout=90):
    """Aspetta che la coda della slice bassa si svuoti davvero (invece di un'attesa fissa)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if queue_backlog(ifaces) == 0:
            break
        time.sleep(1)
    waited = time.time() - t0
    log("  coda slice bassa svuotata dopo %.0f s%s" % (waited, "" if waited < timeout else " (TIMEOUT)"))
    time.sleep(2)


def dump_flows(out, tag=""):
    """Salva le regole di ogni switch (serve per spiegarle nella relazione)."""
    for dpid in (1, 2, 3, 4):
        txt = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s%d" % dpid],
                             capture_output=True, text=True).stdout
        open(os.path.join(out, "flows_s%d%s.txt" % (dpid, tag)), "w").write(txt)


def tcpdump_count(host, dst_ip, iface, out, name, count=5):
    """Cattura con tcpdump sull'interfaccia di uno switch MENTRE host pinga dst_ip.
    Ritorna quante richieste ICMP echo sono passate di li'."""
    path = os.path.join(out, "tcpdump_%s.txt" % name)
    with open(path, "w") as f:
        cap = subprocess.Popen(["tcpdump", "-i", iface, "-n", "-l", "icmp"], stdout=f,
                               stderr=subprocess.DEVNULL)
        time.sleep(1)
        host.cmd("ping -c %d -i 0.3 -W 1 %s" % (count, dst_ip))
        time.sleep(1)
        cap.terminate()
        cap.wait()
    return len(re.findall(r"ICMP echo request", read(path)))


def exp_topology(net, out, log):
    m = ping_matrix(net)
    expected = {(a, b): frozenset((a, b)) in T.PAIR_SLICE for (a, b) in m}
    log("Raggiungibilita' (ping):")
    for (a, b), ok in sorted(m.items()):
        log("  %s -> %s : %-9s atteso: %s  %s" % (a, b, "raggiungibile" if ok else "bloccato",
            "ok" if expected[(a, b)] else "vietato", "" if ok == expected[(a, b)] else "<-- DIVERSO"))
    for pair, name in ((("h1", "h3"), "slice ALTA (s2)"), (("h2", "h4"), "slice BASSA (s3)")):
        b2, b3 = rx_packets("s2-eth1"), rx_packets("s3-eth1")
        net.get(pair[0]).cmd("ping -c 8 -i 0.2 -W 1 %s" % T.HOSTS[pair[1]].ip)
        d2, d3 = rx_packets("s2-eth1") - b2, rx_packets("s3-eth1") - b3
        log("Percorso %s-%s: pacchetti entrati in s2=%d, in s3=%d  (atteso %s)" % (pair + (d2, d3, name)))
    log("Verifica con tcpdump (file tcpdump_*.txt):")
    for pair, upper in ((("h1", "h3"), True), (("h2", "h4"), False)):
        n_up = tcpdump_count(net.get(pair[0]), T.HOSTS[pair[1]].ip, "s2-eth1", out, "%s_%s_s2" % pair)
        n_lo = tcpdump_count(net.get(pair[0]), T.HOSTS[pair[1]].ip, "s3-eth1", out, "%s_%s_s3" % pair)
        log("  ping %s->%s: echo request visti su s2-eth1 = %d, su s3-eth1 = %d  (atteso: %s)"
            % (pair + (n_up, n_lo, "solo s2 (slice alta)" if upper else "solo s3 (slice bassa)")))
    dump_flows(out)
    log("Regole di tutti gli switch salvate in flows_s1..s4.txt")
    return all(m[k] == expected[k] for k in m)


def exp_service(net, out, log):
    """Video UDP/9999 contro TCP normale, da soli e insieme.

    Le misure sono prese lato SERVER (cio' che arriva davvero a destinazione), con un server
    nuovo a ogni prova. Tra una prova e l'altra si aspetta (leggendo i contatori `tc`) che la coda
    della slice bassa (1 Mbps) si svuoti davvero: altrimenti i pacchetti rimasti della prova precedente affamano la
    successiva (il lato client di iperf li conta come gia' inviati e da' numeri gonfiati)."""
    h1, h2, h3, h4 = (net.get(n) for n in ("h1", "h2", "h3", "h4"))
    allok = all(ping_matrix(net).values())
    log("Raggiungibilita' totale: %s" % ("ok" if allok else "FALLITA"))
    secs, res = 10, {}
    runs = (("video da solo", "video", True, False), ("TCP normale da solo", "tcp", False, True),
            ("video + TCP insieme", "both", True, True))
    for label, tag, video, tcp in runs:
        sv = start_server(h3, "%s/srv_video_%s.txt" % (out, tag), 9999) if video else None
        st = start_server(h4, "%s/srv_tcp_%s.txt" % (out, tag)) if tcp else None
        time.sleep(1)
        procs = []
        if video:
            procs.append(start_client(h1, "h3", "%s/cli_video_%s.txt" % (out, tag), secs, 9999, "8M"))
        if tcp:
            procs.append(start_client(h2, "h4", "%s/cli_tcp_%s.txt" % (out, tag), secs))
        if video and tcp:
            time.sleep(4)
            dump_flows(out)                     # le regole mentre il traffico e' in corso
        for p in procs:
            p.wait()
        if tcp:
            for srv in (sv, st):                # niente piu' dati nuovi: si svuota solo l'arretrato
                if srv:
                    srv.terminate()
            wait_queue_drain(log)
        else:
            time.sleep(1)
        v = mean(intervals(read("%s/srv_video_%s.txt" % (out, tag)))[:secs]) if video else None
        t = mean(intervals(read("%s/srv_tcp_%s.txt" % (out, tag)))[:secs]) if tcp else None
        for srv in (sv, st):
            if srv:
                srv.terminate()
        res[tag] = (v, t)
        log("%-22s video: %s   TCP: %s" % (label, "%.2f Mbps" % v if video else "-",
                                          "%.2f Mbps" % t if tcp else "-"))
    checks = [
        ("video da solo vicino agli 8 Mbps offerti", res["video"][0] >= 7.0),
        ("TCP da solo limitato dalla slice bassa (0.5-1.3 Mbps)", 0.5 <= res["tcp"][1] <= 1.3),
        ("video con il TCP: nessun calo (>= 7 Mbps)", res["both"][0] >= 7.0),
        ("TCP con il video: resta sulla slice bassa (0.5-1.3 Mbps)", 0.5 <= res["both"][1] <= 1.3),
    ]
    for name, ok in checks:
        log("  %-60s %s" % (name, "ok" if ok else "NO"))
    return allok and all(ok for _, ok in checks)


def exp_dynamic(net, out, log):
    h1, h2, h3, h4 = (net.get(n) for n in ("h1", "h2", "h3", "h4"))
    total, v_start, v_len = 28, 9, 9
    s_video, s_tcp = start_server(h3, out + "/srv_video.txt", 9999), start_server(h4, out + "/srv_tcp.txt")
    time.sleep(1)
    tcp = start_client(h2, "h4", out + "/cli_tcp.txt", total)
    time.sleep(v_start)
    vid = start_client(h1, "h3", out + "/cli_video.txt", v_len, 9999, "8M")
    time.sleep(4)
    dump_flows(out)                             # le regole mentre il video e' in corso
    vid.wait(); tcp.wait(); time.sleep(1)
    # TCP misurato lato SERVER (cio' che arriva davvero): il lato client conta anche i pacchetti
    # ancora accodati sulla slice bassa e da' numeri gonfiati.
    tcp_rows = [r for r in intervals(read(out + "/srv_tcp.txt")) if r[0] <= total + 1]
    vid_rows = intervals(read(out + "/srv_video.txt"))
    with open(out + "/timeline.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_s", "tcp_mbps", "video_mbps"])
        vmap = {int(round(v_start + t)): v for t, v in vid_rows}      # il video parte a v_start
        for i, (t, v) in enumerate(tcp_rows):
            w.writerow([int(round(t)), "%.2f" % v, "%.2f" % vmap.get(int(round(t)), 0)])
    a = mean([r for r in tcp_rows if r[0] <= v_start - 1])
    b = mean([r for r in tcp_rows if v_start + 3 <= r[0] <= v_start + v_len])
    c = mean([r for r in tcp_rows if r[0] >= v_start + v_len + 5])
    log("TCP normale  prima del video : %.2f Mbps  (atteso ~ 9-10: usa la slice alta)" % a)
    log("TCP normale  durante il video: %.2f Mbps  (atteso ~ 1: torna sulla slice bassa)" % b)
    log("TCP normale  dopo il video   : %.2f Mbps  (atteso ~ 9-10: riprende la slice alta)" % c)
    log("Video (UDP 8 Mbps) durante   : %.2f Mbps  (atteso ~ 8)" % mean(vid_rows))
    s_video.terminate(); s_tcp.terminate()
    checks = [("TCP prima del video usa la slice alta (>= 4 Mbps)", a >= 4.0),
              ("TCP durante il video torna sulla slice bassa (<= 2 Mbps)", b <= 2.0),
              ("video vicino agli 8 Mbps offerti (>= 7 Mbps)", mean(vid_rows) >= 7.0)]
    for name, ok in checks:
        log("  %-60s %s" % (name, "ok" if ok else "NO"))
    log("  (il TCP risale con un ritardo di qualche secondo: soglia di silenzio, polling, reinstallazione)")
    return all(ok for _, ok in checks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("topology", "service", "dynamic"), required=True)
    ap.add_argument("--controller", default="127.0.0.1")
    args = ap.parse_args()
    out = os.path.join(HERE, "results", args.mode)
    os.makedirs(out, exist_ok=True)
    lines = []

    def log(s):
        print(s)
        lines.append(s)

    from mininet.log import setLogLevel
    setLogLevel("warning")
    net = topology.build(args.controller)
    net.start()
    topology.apply_qos()
    try:
        time.sleep(3)
        log("== modalita': %s ==" % args.mode)
        ok = {"topology": exp_topology, "service": exp_service, "dynamic": exp_dynamic}[args.mode](net, out, log)
        log("ESITO: %s" % ("ok" if ok else "DA CONTROLLARE"))
    finally:
        topology.clear_qos()
        net.stop()
        open(os.path.join(out, "summary.txt"), "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
