#!/usr/bin/env python3
"""Dimostrazione dell'attacco di MAC spoofing e della difesa (richiede sudo).

  Terminale 1:  SLICE_MODE=service SLICE_SPOOF_MODE=enforce ryu-manager controller/slice_controller.py
  Terminale 2:  sudo python3 spoof_demo.py --label con_difesa
  (ripeti con SLICE_SPOOF_MODE=off e --label senza_difesa per il confronto)

h2 (attaccante) si spaccia per h1 e invia UDP a h3. In service slicing h2 e h3 possono
parlarsi, quindi il solo modo per fermare il pacchetto e' accorgersi che il MAC non
corrisponde alla porta. Due metodi di attacco (--method):
  iplink : h2 cambia il MAC della propria interfaccia (ARP statico per h3, perche'
           anche l'ARP e' controllato)
  scapy  : h2 tiene il proprio MAC ma manda frame contraffatti (tools/spoof_scapy.py;
           serve pip install scap)
  both   : prima uno e poi l'altro, con una pausa per far scadere il drop a tempo
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "controller"))
import slice_topology as T                                             # noqa: E402
import topology                                                        # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def read_sink(path):
    by_src = {}
    for line in open(path).read().splitlines()[1:]:
        _, src, nbytes, _ = line.split(",")
        by_src[src] = by_src.get(src, 0) + int(nbytes)
    return by_src


def phase(net, out, method, port):
    """Una fase: h1 legittimo + h2 che si spaccia per h1 con il metodo indicato."""
    h1, h2, h3 = net.get("h1"), net.get("h2"), net.get("h3")
    victim, mine, target = T.HOSTS["h1"], T.HOSTS["h2"], T.HOSTS["h3"]
    csv = "%s/sink_%s.csv" % (out, method)
    sink = h3.popen(["python3", os.path.join(HERE, "tools", "udp_sink.py"), "--port", str(port),
                     "--csv", csv, "--duration", "14"])
    time.sleep(1)
    # 1) traffico legittimo di h1: deve passare sempre
    h1.cmd("python3 %s/tools/udp_flood.py --dst %s --port %d --rate 1M --duration 3 > /dev/null"
           % (HERE, target.ip, port))
    # 2) h2 si spaccia per h1
    if method == "iplink":
        # cambia il MAC dell'interfaccia; ARP statico perche' anche l'ARP e' controllato
        h2.cmd("arp -s %s %s" % (target.ip, target.mac))
        h2.cmd("ip link set h2-eth0 address %s" % victim.mac)
        h2.cmd("python3 %s/tools/udp_flood.py --dst %s --port %d --rate 1M --duration 5 > /dev/null"
               % (HERE, target.ip, port))
        h2.cmd("ip link set h2-eth0 address %s" % mine.mac)          # ripristina
    else:
        # Scapy: l'interfaccia resta con il suo MAC, e' il frame a dichiarare quello di h1
        h2.cmd("python3 %s/tools/spoof_scapy.py --iface h2-eth0 --src-mac %s --dst-mac %s "
               "--src-ip %s --dst-ip %s --port %d --rate 1M --duration 5 > %s/scapy_%s.txt 2>&1"
               % (HERE, victim.mac, target.mac, mine.ip, target.ip, port, out, method))
    time.sleep(2)
    sink.wait()
    got = read_sink(csv)
    legit, fake = got.get(victim.ip, 0), got.get(mine.ip, 0)
    name = {"iplink": "ip link (cambio MAC dell'interfaccia)", "scapy": "Scapy (frame contraffatti)"}[method]
    return ["Attacco %s" % name,
            "  h1 (legittimo)  byte arrivati a h3: %d" % legit,
            "  h2 (MAC di h1)  byte arrivati a h3: %d" % fake,
            "  ESITO: " + ("attacco BLOCCATO, il legittimo passa" if fake == 0 and legit > 0 else
                           "attacco NON bloccato" if fake > 0 else "controllare: nessun traffico")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="demo")
    ap.add_argument("--method", choices=("iplink", "scapy", "both"), default="both",
                    help="iplink = cambio MAC dell'interfaccia, scapy = frame contraffatti, "
                         "both = prima uno e poi l'altro (con una pausa)")
    ap.add_argument("--pause", type=float, default=32,
                    help="s di attesa tra le due fasi di 'both', per far scadere il drop a tempo")
    args = ap.parse_args()
    out = os.path.join(HERE, "results", "spoof_" + args.label)
    os.makedirs(out, exist_ok=True)

    from mininet.log import setLogLevel
    setLogLevel("warning")
    net = topology.build()
    net.start()
    topology.apply_qos()
    try:
        time.sleep(3)
        methods = ["iplink", "scapy"] if args.method == "both" else [args.method]
        lines = []
        for i, m in enumerate(methods):
            if i:
                time.sleep(args.pause)
            lines += phase(net, out, m, 5001 + i)
        print("\n".join(lines))
        open(out + "/spoof_summary.txt", "w").write("\n".join(lines) + "\n")
    finally:
        topology.clear_qos()
        net.stop()


if __name__ == "__main__":
    main()
