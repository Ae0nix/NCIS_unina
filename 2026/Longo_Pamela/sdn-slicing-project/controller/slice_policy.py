"""Logica di slicing SENZA OpenFlow: decide, ma non parla con gli switch.

Tenerla separata dal controller permette di cambiare le regole senza toccare 
il codice che installa i flussi.

Contiene:
  * SlicePolicy  : ACL delle coppie, classificazione L4, scelta di slice e coda
  * path()       : lista di salti (switch, porta_in, porta_out) per una coppia di host
  * PortGuard    : anti-spoofing, legame porta di accesso <-> MAC/IP
  * DynamicState : "la slice video e' in uso?" (serve allo slicing dinamico)
"""
from collections import namedtuple

import slice_topology as T

UDP, TCP, ICMP = 17, 6, 1

# il cookie OpenFlow di ogni flusso dice a quale classe appartiene: cosi' il controller
# puo' cancellare "tutti i flussi normali che usano la slice alta" con un solo messaggio
COOKIE_VIDEO, COOKIE_NORMAL, COOKIE_BORROW, COOKIE_STATIC = 1, 2, 3, 4
COOKIE_NAMES = {COOKIE_VIDEO: "video", COOKIE_NORMAL: "normale",
                COOKIE_BORROW: "normale-in-prestito", COOKIE_STATIC: "statica"}
QUEUE_NAMES = {T.QUEUE_PREMIUM: "PREMIUM", T.QUEUE_STANDARD: "STANDARD"}

Decision = namedtuple("Decision", "allowed slice queue cookie reason")
Hop = namedtuple("Hop", "dpid in_port out_port core")


class SlicePolicy:
    def __init__(self, cfg, state=None):
        self.cfg = cfg
        self.mode = cfg.MODE
        self.state = state or DynamicState(cfg.VIDEO_IDLE_S)
        if self.mode not in ("topology", "service", "dynamic"):
            raise ValueError("MODE non valido: %r" % self.mode)

    @property
    def uses_queues(self):
        return self.mode != "topology"

    def allowed(self, src, dst):
        if src == dst or src not in T.HOSTS or dst not in T.HOSTS:
            return False
        if self.mode == "topology":
            return frozenset((src, dst)) in T.PAIR_SLICE
        return True

    def is_video(self, proto, dport):
        return proto == UDP and dport == self.cfg.VIDEO_PORT

    def decide(self, src, dst, proto, dport):
        if not self.allowed(src, dst):
            return Decision(False, None, None, 0, "coppia non autorizzata")
        video = self.mode != "topology" and self.is_video(proto, dport)

        if self.mode == "topology":
            sl = T.PAIR_SLICE[frozenset((src, dst))]
        elif video:
            sl = T.UPPER
        elif self.mode == "dynamic" and not self.state.video_active:
            sl = T.UPPER                       # la slice video e' libera: la presto
        else:
            sl = T.LOWER

        if video:
            cookie = COOKIE_VIDEO
        elif sl == T.UPPER and self.mode == "dynamic":
            cookie = COOKIE_BORROW
        else:
            cookie = COOKIE_NORMAL
        queue = None
        if self.uses_queues:
            queue = T.QUEUE_PREMIUM if video else T.QUEUE_STANDARD
        return Decision(True, sl, queue, cookie, "")


def path(src, dst, slice_name):
    """Salti da `src` a `dst` (nomi host). Il traffico entra dalla slice indicata."""
    a, b = T.HOSTS[src], T.HOSTS[dst]
    if a.dpid == b.dpid:                                       # stesso switch
        return [Hop(a.dpid, a.port, b.port, False)]
    mid = T.MIDDLE[slice_name]
    return [
        Hop(a.dpid, a.port, T.CORE_PORT[(a.dpid, mid)], True),
        Hop(mid, T.CORE_PORT[(mid, a.dpid)], T.CORE_PORT[(mid, b.dpid)], True),
        Hop(b.dpid, T.CORE_PORT[(b.dpid, mid)], b.port, False),
    ]


class PortGuard:
    """Anti-spoofing: ogni porta di accesso e' legata a UN solo MAC (e IP).

    La rete e' piccola e nota, quindi i legami sono statici (come un "port security"
    con indirizzi configurati a mano). Le porte verso il core non hanno legami.
    """

    def __init__(self, hosts=None):
        hosts = hosts or T.HOSTS
        self.bindings = {(h.dpid, h.port): (h.mac, h.ip) for h in hosts.values()}

    def is_access_port(self, dpid, port):
        return (dpid, port) in self.bindings

    def check(self, dpid, port, mac, ip=None):
        """None se va bene, altrimenti la ragione della violazione."""
        bound = self.bindings.get((dpid, port))
        if bound is None:
            return None
        if mac != bound[0]:
            return "MAC %s sulla porta %d di s%d, legata a %s" % (mac, port, dpid, bound[0])
        if ip and ip != "0.0.0.0" and ip != bound[1]:
            return "IP %s sulla porta %d di s%d, legata a %s" % (ip, port, dpid, bound[1])
        return None


class DynamicState:
    """Dice se la slice video e' in uso, guardando i byte dei flussi video.

    observe() riceve i byte video nuovi dall'ultimo giro: se > 0 il video e' attivo,
    se per `idle_s` secondi non ne arrivano, la slice e' libera.
    Ritorna True quando lo stato cambia (il controller deve allora riorganizzare).
    """

    def __init__(self, idle_s=3.0):
        self.idle_s = idle_s
        self.video_active = False
        self.last_video = None

    def note_video(self, now):
        self.last_video = now
        return self._refresh(now)

    def observe(self, now, new_video_bytes):
        if new_video_bytes > 0:
            self.last_video = now
        return self._refresh(now)

    def _refresh(self, now):
        active = self.last_video is not None and (now - self.last_video) < self.idle_s
        changed = active != self.video_active
        self.video_active = active
        return changed
