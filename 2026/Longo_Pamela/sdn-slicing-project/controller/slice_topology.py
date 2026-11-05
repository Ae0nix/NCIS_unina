r"""Descrizione STATICA della rete a rombo (dati condivisi da controller e topologia).

  slice ALTA  : s1 - s2 - s4, link da 10 Mbps  (video / traffico critico)
  slice BASSA : s1 - s3 - s4, link da  1 Mbps  (traffico best-effort)

I numeri di porta sono fissati qui e passati a Mininet con addLink(port1=, port2=),
cosi' il controller non deve scoprirli: la topologia e' nota a priori.
"""
from collections import namedtuple

Host = namedtuple("Host", "name mac ip dpid port")

HOSTS = {
    "h1": Host("h1", "00:00:00:00:00:01", "10.0.0.1", 1, 1),
    "h2": Host("h2", "00:00:00:00:00:02", "10.0.0.2", 1, 2),
    "h3": Host("h3", "00:00:00:00:00:03", "10.0.0.3", 4, 1),
    "h4": Host("h4", "00:00:00:00:00:04", "10.0.0.4", 4, 2),
}
BY_MAC = {h.mac: h for h in HOSTS.values()}
BY_IP = {h.ip: h for h in HOSTS.values()}

UPPER, LOWER = "upper", "lower"
MIDDLE = {UPPER: 2, LOWER: 3}                 # switch intermedio di ogni slice
EDGES = (1, 4)

# (switch, vicino) -> numero di porta sullo switch
CORE_PORT = {
    (1, 2): 3, (1, 3): 4,
    (4, 2): 3, (4, 3): 4,
    (2, 1): 1, (2, 4): 2,
    (3, 1): 1, (3, 4): 2,
}

# capacita' dei link (Mbps) e regole delle code
LINK_MBPS = {UPPER: 10, LOWER: 1}
QUEUE_PREMIUM, QUEUE_STANDARD = 1, 2
QUEUE_MIN_MBPS = {UPPER: {QUEUE_PREMIUM: 8, QUEUE_STANDARD: 1},
                  LOWER: {QUEUE_PREMIUM: 0.5, QUEUE_STANDARD: 0.5}}

# coppie ammesse nel topology slicing e relativa slice
PAIR_SLICE = {frozenset(("h1", "h3")): UPPER, frozenset(("h2", "h4")): LOWER}

SWITCH_LINKS = [(1, 2), (2, 4), (1, 3), (3, 4)]        # per Mininet / disegni


def slice_of_link(a, b):
    """Slice a cui appartiene il link a-b (a o b e' lo switch intermedio)."""
    for name, mid in MIDDLE.items():
        if mid in (a, b):
            return name
    return None


def core_egress_ports():
    """(dpid, porta, slice) di tutte le porte in uscita verso il core: li' ci vanno le code."""
    out = []
    for (dpid, nb), port in sorted(CORE_PORT.items()):
        out.append((dpid, port, slice_of_link(dpid, nb)))
    return out


def link_label(dpid, port):
    for (d, nb), p in CORE_PORT.items():
        if d == dpid and p == port:
            return "s%d->s%d" % (d, nb)
    return "s%d:%d" % (dpid, port)
