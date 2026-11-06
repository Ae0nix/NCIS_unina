#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Topologia Mininet Cloud/Edge con Congestione Fisica Reale e Mitigazione DoS:
  - Uplink s1-eth3 (condiviso tra h1 Gold e h2 Silver): Bottleneck a 25.0 Mbps
      * Queue 1 (Slice Gold):   min-rate 15 Mbps, max-rate 25 Mbps, priority 1 (Alta)
      * Queue 2 (Slice Silver): min-rate  5 Mbps, max-rate 10 Mbps, priority 2 (Media)
      -> h1 chiede 15 Mbps (porta 5001) e h2 chiede 14 Mbps (porta 5002):
         Totale richiesto 29 Mbps > 25 Mbps disponibili.
         h1 (Gold) ottiene tutti i 15 Mbps garantiti; h2 (Silver) viene limitato a ~10 Mbps.
  - Uplink s2-eth2 e Core s3: Capacita' 50 Mbps con Queue 3 (3.0 Mbps) per Throttling Stadio 1.
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def configure_ovs_qos():
    info("*** Configurazione Bottleneck QoS su s1-eth3 (25 Mbps) e Core/Edge (50 Mbps)...\n")

    # 1. Bottleneck di Congestione sull'uplink condiviso s1-eth3 (Capacita' totale = 25 Mbps)
    cmd_s1 = (
        "ovs-vsctl -- set Port s1-eth3 qos=@s1qos -- "
        "--id=@s1qos create QoS type=linux-htb other-config:max-rate=25000000 "
        "queues:0=@s1q0 queues:1=@s1q1 queues:2=@s1q2 queues:3=@s1q3 -- "
        "--id=@s1q0 create Queue other-config:min-rate=5000000 other-config:max-rate=25000000 -- "
        "--id=@s1q1 create Queue other-config:min-rate=15000000 other-config:max-rate=25000000 other-config:priority=1 -- "
        "--id=@s1q2 create Queue other-config:min-rate=5000000 other-config:max-rate=10000000 other-config:priority=2 -- "
        "--id=@s1q3 create Queue other-config:min-rate=1000000 other-config:max-rate=3000000 other-config:priority=3 >/dev/null 2>&1"
    )
    os.system(cmd_s1)

    # 2. Sulle porte di s2 e del Core Switch s3: Capacita' 50 Mbps e Queue 3 (3.0 Mbps) per lo Stadio 1
    for port in ["s2-eth2", "s3-eth3", "s3-eth4"]:
        cmd = (
            f"ovs-vsctl -- set Port {port} qos=@newqos -- "
            f"--id=@newqos create QoS type=linux-htb other-config:max-rate=50000000 "
            f"queues:0=@q0 queues:1=@q1 queues:2=@q2 queues:3=@q3 -- "
            f"--id=@q0 create Queue other-config:min-rate=5000000 other-config:max-rate=50000000 -- "
            f"--id=@q1 create Queue other-config:min-rate=15000000 other-config:max-rate=50000000 other-config:priority=1 -- "
            f"--id=@q2 create Queue other-config:min-rate=5000000 other-config:max-rate=35000000 other-config:priority=2 -- "
            f"--id=@q3 create Queue other-config:min-rate=1000000 other-config:max-rate=3000000 other-config:priority=3 >/dev/null 2>&1"
        )
        os.system(cmd)


def run_automated_scenario(net):
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h4 = net.get("h4")
    h5 = net.get("h5")

    info("\n======================================================================\n")
    info(" AVVIO SIMULAZIONE CON CONGESTIONE E ATTACCO DoS (Durata: ~56 secondi)\n")
    info("======================================================================\n")

    info("*** [Setup] Attesa convergenza switch OpenFlow 1.3...\n")
    time.sleep(3)

    info("*** [Setup] Avvio Server iperf3 su h4 (Gold 10.0.0.100:5001) e h5 (Silver 10.0.0.200:5002/5003)...\n")
    h4.cmd("iperf3 -s -p 5001 -D")
    h5.cmd("iperf3 -s -p 5002 -D")
    h5.cmd("iperf3 -s -p 5003 -D")
    time.sleep(1)

    info("*** [Setup] Verifica connettivita' iniziale e Auto-Discovery Edge...\n")
    net.pingAll()
    time.sleep(2)

    info("*** [Fase 1: t=0..12s] Congestione sull'Uplink s1-eth3 (29 Mbps richiesti su link da 25 Mbps):\n")
    info("    -> h1 (Slice Gold):   chiede 15 Mbps -> Ottiene i 15 Mbps garantiti (Queue 1, Prio 1)\n")
    info("    -> h2 (Slice Silver): chiede 14 Mbps -> Limitato da HTB a ~10 Mbps (Queue 2, Prio 2)\n")
    h1.cmd("iperf3 -c 10.0.0.100 -p 5001 -u -b 15M -l 1000 -t 52 >/dev/null 2>&1 &")
    h2.cmd("iperf3 -c 10.0.0.200 -p 5002 -u -b 14M -l 1000 -t 52 >/dev/null 2>&1 &")
    time.sleep(12)

    info("*** [Fase 2: t=12..34s] Flusso anomalo ad alto rate da h3 (26 Mbps UDP verso Server Silver h5)!\n")
    info("    -> Stadio 1 (Throttling a 3.0 Mbps per 6s) -> Escalation a Stadio 2 (Hard Drop su Edge s2)!\n")
    h3.cmd("iperf3 -c 10.0.0.200 -p 5003 -u -b 26M -l 1000 -w 16K -t 22 >/dev/null 2>&1 &")
    time.sleep(24)

    info("*** [Fase 3: t=36..52s] Fine del flusso anomalo e Auto-Healing post-quarantena...\n")
    time.sleep(16)

    info("*** Simulazione completata! Il file 'telemetry.csv' e' pronto.\n")


def build_network(autotest=False):
    net = Mininet(controller=RemoteController, switch=OVSSwitch, autoSetMacs=True)

    info("*** Aggiunta del Controller Remoto Ryu (127.0.0.1:6633)...\n")
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

    info("*** Creazione Switch OpenFlow 1.3 (s1, s2 Edge - s3 Core)...\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")

    info("*** Creazione Host Client e Cloud Server...\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.100/24", mac="00:00:00:00:01:00")
    h5 = net.addHost("h5", ip="10.0.0.200/24", mac="00:00:00:00:02:00")

    info("*** Creazione Link Topologici...\n")
    net.addLink(h1, s1, port1=1, port2=1)
    net.addLink(h2, s1, port1=1, port2=2)
    net.addLink(h3, s2, port1=1, port2=1)
    net.addLink(s1, s3, port1=3, port2=1)
    net.addLink(s2, s3, port1=2, port2=2)
    net.addLink(s3, h4, port1=3, port2=1)
    net.addLink(s3, h5, port1=4, port2=1)

    info("*** Avvio della rete Mininet...\n")
    net.start()
    configure_ovs_qos()

    if autotest:
        run_automated_scenario(net)
    else:
        info("\n*** Rete pronta! Usa la CLI Mininet oppure avvia con '--autotest'\n")
        CLI(net)

    info("*** Arresto della rete e pulizia code QoS...\n")
    os.system("ovs-vsctl --all destroy QoS -- --all destroy Queue >/dev/null 2>&1")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    auto = "--autotest" in sys.argv
    build_network(autotest=auto)