#!/usr/bin/env python3
"""Rete a rombo per Mininet + Open vSwitch (richiede sudo).

    sudo python3 topology.py            # topologia + CLI di Mininet

Porte fissate con addLink(port1=, port2=): coincidono con quelle di controller/slice_topology.py.
Le velocita' dei link di core NON si impostano con tc (TCLink bw=) ma con le code di OVS
(linux-htb): le due cose si sovrascrivono a vicenda, e le code servono comunque per la QoS.
"""
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] + "/controller")
import slice_topology as T                                              # noqa: E402


def build(controller_ip="127.0.0.1", controller_port=6653):
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController

    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink,
                  autoSetMacs=False, autoStaticArp=False)
    net.addController("c0", controller=RemoteController, ip=controller_ip, port=controller_port)
    sw = {}
    for dpid in (1, 2, 3, 4):
        # failMode=secure: se cade il controller lo switch NON diventa un L2 normale
        # (nel rombo ci sarebbe un loop di broadcast)
        sw[dpid] = net.addSwitch("s%d" % dpid, protocols="OpenFlow13",
                                 dpid="%016x" % dpid, failMode="secure")
    for h in T.HOSTS.values():
        host = net.addHost(h.name, ip=h.ip + "/24", mac=h.mac)
        net.addLink(host, sw[h.dpid], port1=0, port2=h.port, bw=100)
    for a, b in T.SWITCH_LINKS:
        net.addLink(sw[a], sw[b], port1=T.CORE_PORT[(a, b)], port2=T.CORE_PORT[(b, a)])
    return net


def _vsctl(*args):
    subprocess.run(["ovs-vsctl", *args], check=True, capture_output=True, text=True)


def clear_qos():
    for dpid, port, _ in T.core_egress_ports():
        subprocess.run(["ovs-vsctl", "clear", "port", "s%d-eth%d" % (dpid, port), "qos"],
                       capture_output=True)
    subprocess.run(["ovs-vsctl", "--all", "destroy", "qos"], capture_output=True)
    subprocess.run(["ovs-vsctl", "--all", "destroy", "queue"], capture_output=True)


def apply_qos():
    """HTB su ogni porta in uscita verso il core: max-rate = capacita' del link,
    coda 1 (premium) e coda 2 (standard) con banda minima garantita."""
    clear_qos()
    for dpid, port, sl in T.core_egress_ports():
        rate = int(T.LINK_MBPS[sl] * 1_000_000)
        mins = T.QUEUE_MIN_MBPS[sl]
        _vsctl("--", "set", "port", "s%d-eth%d" % (dpid, port), "qos=@q",
               "--", "--id=@q", "create", "qos", "type=linux-htb",
               "other-config:max-rate=%d" % rate,
               "queues:%d=@q1" % T.QUEUE_PREMIUM, "queues:%d=@q2" % T.QUEUE_STANDARD,
               "--", "--id=@q1", "create", "queue",
               "other-config:min-rate=%d" % int(mins[T.QUEUE_PREMIUM] * 1e6),
               "other-config:max-rate=%d" % rate,
               "--", "--id=@q2", "create", "queue",
               "other-config:min-rate=%d" % int(mins[T.QUEUE_STANDARD] * 1e6),
               "other-config:max-rate=%d" % rate)


if __name__ == "__main__":
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("info")
    network = build()
    network.start()
    apply_qos()
    CLI(network)
    clear_qos()
    network.stop()
