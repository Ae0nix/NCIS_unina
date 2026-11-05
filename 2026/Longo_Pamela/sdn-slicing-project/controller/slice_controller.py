"""Controller Ryu per topology slicing, service slicing, slicing dinamico e anti-spoofing.

Avvio:   SLICE_MODE=dynamic ryu-manager controller/slice_controller.py

Come lavora (approccio ibrido):
  * REATTIVO  : il primo pacchetto di ogni flusso arriva al controller (Packet-In), che
                decide una volta sola e installa le regole su tutti gli switch del percorso
  * PROATTIVO : alla connessione di ogni switch si installano table-miss e regole statiche
  * ARP       : la rete e' un rombo, cioe' ha un ciclo, quindi il flooding andrebbe
                in loop. Il controller risponde lui alle richieste ARP (proxy ARP):
                niente broadcast nella rete.
  * SICUREZZA : prima di ogni altra cosa si controlla che MAC/IP del pacchetto
                corrispondano a quelli legati alla porta di accesso (anti-spoofing)
"""
import json
import os
import time
from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

import slice_config
import slice_policy as P
import slice_topology as T

ALL_COOKIE_BITS = 0xFFFFFFFFFFFFFFFF


class SliceController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = slice_config.load()
        self.policy = P.SlicePolicy(self.cfg)
        self.guard = P.PortGuard()
        self.dps = {}                       # dpid -> datapath
        self.spoof_rules = {}               # (dpid, porta, mac) -> scadenza
        self.spoof_logged = {}              # (dpid, porta, mac) -> ultimo log
        self.counters = {"spoof_packets": 0, "acl_drops": 0, "flows_installed": 0,
                         "arp_replies": 0, "reroutes": 0,
                         "classified_video": 0, "classified_normal": 0}
        self.event_log = deque(maxlen=40)
        self.history = deque(maxlen=self.cfg.HISTORY_LEN)
        self.video_total = {}               # dpid -> byte video visti nell'ultima risposta
        self.video_delta = 0                # byte video nuovi dall'ultimo giro
        self.port_last = {}                 # (dpid, porta) -> (tx_bytes, t)
        self.port_rate = {}                 # (dpid, porta) -> bit/s
        self.flow_last = {}                 # chiave di flusso -> (byte, t)
        self.flow_rows = {}                 # dpid -> righe della tabella dei flussi
        self.last_tick = time.time()
        self.logger.info("slicing mode=%s spoof=%s video_port=%d", self.cfg.MODE,
                         self.cfg.SPOOF_MODE, self.cfg.VIDEO_PORT)
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ------------------------------------------------------------------ switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # table-miss: tutto cio' che non ha una regola va al controller
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._flow_mod(dp, 0, parser.OFPMatch(), actions)
        self._install_static(dp)

    def _install_static(self, dp):
        """Regole PROATTIVE installate alla connessione dello switch (priorita' bassa).

        * switch di core (s2, s3): "dumb forwarding", cio' che entra da una porta esce
          dall'altra. Non servono Packet-In sul core: se un flusso perde la sua regola
          a meta' strada il pacchetto prosegue comunque lungo la slice in cui e' entrato.
        * switch di bordo (s1, s4): cio' che arriva dal core ed e' destinato a un host
          locale esce sulla porta di quell'host.
        * ping (solo service/dynamic): regole sempre presenti sullo switch di bordo, cosi'
          la connettivita' di base non dipende dal controller. Sono legate a porta, MAC e IP
          dell'host vero, quindi non aggirano l'anti-spoofing; e non esistono in
          topology slicing, dove il ping tra coppie vietate DEVE fallire.
        """
        ofp, parser = dp.ofproto, dp.ofproto_parser
        out = parser.OFPActionOutput
        if dp.id not in T.EDGES:
            for a, b in ((1, 2), (2, 1)):
                self._flow_mod(dp, self.cfg.STATIC_PRIORITY, parser.OFPMatch(in_port=a),
                               [out(b)], cookie=P.COOKIE_STATIC)
            return
        local = [h for h in T.HOSTS.values() if h.dpid == dp.id]
        core_ports = [T.CORE_PORT[(dp.id, mid)] for mid in T.MIDDLE.values()]
        for h in local:
            for cp in core_ports:
                self._flow_mod(dp, self.cfg.STATIC_PRIORITY,
                               parser.OFPMatch(in_port=cp, eth_dst=h.mac),
                               [out(h.port)], cookie=P.COOKIE_STATIC)
        if self.policy.mode == "topology":
            return
        for src in local:
            for dst in T.HOSTS.values():
                if dst.name == src.name:
                    continue
                if dst.dpid == dp.id:
                    actions = [out(dst.port)]
                else:                                   # i ping viaggiano sulla slice bassa
                    actions = [parser.OFPActionSetQueue(T.QUEUE_STANDARD),
                               out(T.CORE_PORT[(dp.id, T.MIDDLE[T.LOWER])])]
                match = parser.OFPMatch(in_port=src.port, eth_type=ether_types.ETH_TYPE_IP,
                                        eth_src=src.mac, eth_dst=dst.mac, ip_proto=P.ICMP,
                                        ipv4_src=src.ip)
                self._flow_mod(dp, self.cfg.ICMP_PRIORITY, match, actions,
                               cookie=P.COOKIE_STATIC)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.dps.pop(dp.id, None)

    # ------------------------------------------------------------- helper OF
    def _flow_mod(self, dp, priority, match, actions, cookie=0, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=cookie, priority=priority,
                                      match=match, instructions=inst,
                                      idle_timeout=idle, hard_timeout=hard))

    def _delete_by_cookie(self, cookie):
        for dp in self.dps.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, cookie=cookie, cookie_mask=ALL_COOKIE_BITS,
                table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch()))

    def _packet_out(self, dp, in_port, out_port, data, queue=None):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = []
        if queue is not None:
            actions.append(parser.OFPActionSetQueue(queue))
        actions.append(parser.OFPActionOutput(out_port))
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=data))

    def _event(self, kind, detail):
        self.event_log.appendleft({"t": round(time.time(), 1), "kind": kind, "detail": detail})
        self.logger.info("[%s] %s", kind, detail)

    # ---------------------------------------------------------------- packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return                                     # rumore: si ignora

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        claimed_ip = arp_pkt.src_ip if arp_pkt else (ip_pkt.src if ip_pkt else None)

        # 1) anti-spoofing: prima di qualsiasi altra cosa
        if self.cfg.SPOOF_MODE != "off":
            reason = self.guard.check(dp.id, in_port, eth.src, claimed_ip)
            if reason is not None:
                self._on_spoof(dp, in_port, eth.src, reason)
                if self.cfg.SPOOF_MODE == "enforce":
                    return

        # 2) ARP e IP
        if arp_pkt is not None:
            self._handle_arp(dp, in_port, eth, arp_pkt)
        elif ip_pkt is not None:
            self._handle_ip(dp, in_port, msg.data, eth, pkt, ip_pkt)

    # ------------------------------------------------------------------ ARP
    def _handle_arp(self, dp, in_port, eth, a):
        if a.opcode != arp.ARP_REQUEST:
            return
        src, dst = T.BY_IP.get(a.src_ip), T.BY_IP.get(a.dst_ip)
        if src is None or dst is None or not self.policy.allowed(src.name, dst.name):
            self.counters["acl_drops"] += 1
            return                                     # coppia vietata: nessuna risposta
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                             dst=eth.src, src=dst.mac))
        reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst.mac, src_ip=dst.ip,
                                   dst_mac=eth.src, dst_ip=a.src_ip))
        reply.serialize()
        self._packet_out(dp, dp.ofproto.OFPP_CONTROLLER, in_port, reply.data)
        self.counters["arp_replies"] += 1

    # ------------------------------------------------------------------- IP
    def _handle_ip(self, dp, in_port, data, eth, pkt, ip_pkt):
        src, dst = T.BY_MAC.get(eth.src), T.BY_MAC.get(eth.dst)
        if src is None or dst is None:
            return                                     # host sconosciuto: si scarta
        proto, dport = ip_pkt.proto, 0
        t = pkt.get_protocol(udp.udp) if proto == P.UDP else \
            pkt.get_protocol(tcp.tcp) if proto == P.TCP else None
        if t is not None:
            dport = t.dst_port

        dec = self.policy.decide(src.name, dst.name, proto, dport)
        if not dec.allowed:
            self._drop_pair(dp, in_port, eth)
            return

        if dec.cookie == P.COOKIE_VIDEO and self.policy.mode == "dynamic":
            if self.policy.state.note_video(time.time()):
                self._on_video_state(True)
                dec = self.policy.decide(src.name, dst.name, proto, dport)

        self._log_classification(src, dst, proto, dport, dec)
        hops = P.path(src.name, dst.name, dec.slice)
        for hop in hops:
            self._install_hop(hop, eth, proto, dport, dec)
        self.counters["flows_installed"] += 1

        mine = next((h for h in hops if h.dpid == dp.id), None)
        if mine is not None:                           # inoltra anche il primo pacchetto
            self._packet_out(dp, in_port, mine.out_port, data,
                             dec.queue if mine.core else None)

    def _log_classification(self, src, dst, proto, dport, dec):
        """Una riga per ogni flusso classificato, ad esempio:
        [*] Traffic Identified: [VIDEO] -> [PREMIUM]  h1 -> h3  UDP/9999  slice alta"""
        video = dec.cookie == P.COOKIE_VIDEO
        self.counters["classified_video" if video else "classified_normal"] += 1
        proto_name = {P.UDP: "UDP", P.TCP: "TCP", P.ICMP: "ICMP"}.get(proto, str(proto))
        self.logger.info("[*] Traffic Identified: [%s] -> [%s]  %s -> %s  %s%s  slice %s",
                         "VIDEO" if video else "DATA",
                         P.QUEUE_NAMES.get(dec.queue, "nessuna coda"), src.name, dst.name,
                         proto_name, "/%d" % dport if dport else "",
                         "alta" if dec.slice == T.UPPER else "bassa")

    def _install_hop(self, hop, eth, proto, dport, dec):
        dp = self.dps.get(hop.dpid)
        if dp is None:
            return
        parser = dp.ofproto_parser
        fields = dict(in_port=hop.in_port, eth_type=ether_types.ETH_TYPE_IP,
                      eth_src=eth.src, eth_dst=eth.dst, ip_proto=proto)
        if dport and proto == P.UDP:
            fields["udp_dst"] = dport
        elif dport and proto == P.TCP:
            fields["tcp_dst"] = dport
        actions = []
        if dec.queue is not None and hop.core:
            actions.append(parser.OFPActionSetQueue(dec.queue))
        actions.append(parser.OFPActionOutput(hop.out_port))
        self._flow_mod(dp, self.cfg.FLOW_PRIORITY, parser.OFPMatch(**fields), actions,
                       cookie=dec.cookie, idle=self.cfg.FLOW_IDLE_TIMEOUT)

    def _drop_pair(self, dp, in_port, eth):
        """Coppia non autorizzata: regola di drop a tempo, cosi' il controller non
        viene sommerso di Packet-In dello stesso flusso."""
        parser = dp.ofproto_parser
        self.counters["acl_drops"] += 1
        match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
        self._flow_mod(dp, self.cfg.ACL_PRIORITY, match, [], idle=0,
                       hard=self.cfg.ACL_BLOCK_S)
        self._event("acl", "s%d porta %d: %s -> %s non autorizzato"
                    % (dp.id, in_port, eth.src, eth.dst))

    # ----------------------------------------------------------- anti-spoofing
    def _on_spoof(self, dp, in_port, mac, reason):
        now = time.time()
        key = (dp.id, in_port, mac)
        self.counters["spoof_packets"] += 1
        if now - self.spoof_logged.get(key, 0) >= self.cfg.SPOOF_LOG_S:
            self.spoof_logged[key] = now
            self._event("spoof", reason + (" -> scartato" if self.cfg.SPOOF_MODE == "enforce"
                                           else " (solo segnalato)"))
        if self.cfg.SPOOF_MODE != "enforce" or self.spoof_rules.get(key, 0) > now:
            return
        self.spoof_rules[key] = now + self.cfg.SPOOF_BLOCK_S
        parser = dp.ofproto_parser
        # il drop colpisce solo "questa porta che dice di essere quel MAC": l'host
        # legittimo (che sta su un'altra porta) non viene toccato
        self._flow_mod(dp, self.cfg.SPOOF_PRIORITY,
                       parser.OFPMatch(in_port=in_port, eth_src=mac), [],
                       hard=self.cfg.SPOOF_BLOCK_S)

    # -------------------------------------------------------- slicing dinamico
    def _on_video_state(self, active):
        """Il video e' partito o si e' fermato: i flussi normali vanno riassegnati."""
        self.counters["reroutes"] += 1
        if active:
            self._delete_by_cookie(P.COOKIE_BORROW)    # chi stava in prestito torna in basso
            self._event("dinamico", "video attivo: il traffico normale lascia la slice alta")
        else:
            self._delete_by_cookie(P.COOKIE_NORMAL)    # puo' salire sulla slice alta libera
            self._event("dinamico", "video fermo: il traffico normale puo' usare la slice alta")

    # -------------------------------------------------------------- monitor
    def _monitor_loop(self):
        while True:
            hub.sleep(self.cfg.STATS_INTERVAL)
            try:
                self._tick()
            except Exception:                          # il monitor non deve mai morire
                self.logger.exception("errore nel monitor")

    def _tick(self):
        now = time.time()
        if self.policy.mode == "dynamic":
            delta, self.video_delta = self.video_delta, 0
            if self.policy.state.observe(now, delta):
                self._on_video_state(self.policy.state.video_active)
        self._write_state(now)
        for dp in list(self.dps.values()):
            ofp, parser = dp.ofproto, dp.ofproto_parser
            dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))
            # tutti i flussi: servono sia al video (cookie 1) sia alla tabella della dashboard
            dp.send_msg(parser.OFPFlowStatsRequest(
                dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, 0, parser.OFPMatch()))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        # 1) byte dei flussi video: servono allo slicing dinamico
        total = sum(s.byte_count for s in ev.msg.body if s.cookie == P.COOKIE_VIDEO)
        last = self.video_total.get(dpid, 0)
        # se il totale scende, i flussi sono scaduti e ne e' nato uno nuovo: si riparte da 0
        self.video_delta += total - last if total >= last else total
        self.video_total[dpid] = total
        # 2) tabella dei flussi per la dashboard: solo le regole di INGRESSO (porta di
        #    accesso), cosi' ogni flusso compare una volta sola e non una per ogni switch
        rows, seen = [], set()
        for s in ev.msg.body:
            m = s.match
            in_port = m.get("in_port")
            if s.priority != self.cfg.FLOW_PRIORITY or not self.guard.is_access_port(dpid, in_port):
                continue
            key = (dpid, in_port, m.get("eth_src"), m.get("eth_dst"), m.get("ip_proto"),
                   m.get("udp_dst") or m.get("tcp_dst") or 0)
            seen.add(key)
            prev = self.flow_last.get(key)
            bps = 0.0
            if prev is not None and now > prev[1] and s.byte_count >= prev[0]:
                bps = (s.byte_count - prev[0]) * 8 / (now - prev[1])
            self.flow_last[key] = (s.byte_count, now)
            rows.append(self._flow_row(dpid, s, key, bps))
        for key in [k for k in self.flow_last if k[0] == dpid and k not in seen]:
            del self.flow_last[key]
        self.flow_rows[dpid] = rows

    def _flow_row(self, dpid, s, key, bps):
        out_port, queue = None, None
        for inst in getattr(s, "instructions", []):
            for act in getattr(inst, "actions", []):
                if hasattr(act, "queue_id"):
                    queue = act.queue_id
                elif hasattr(act, "port"):
                    out_port = act.port
        sl = "locale"
        for (d, nb), port in T.CORE_PORT.items():
            if d == dpid and port == out_port:
                sl = "alta" if T.slice_of_link(d, nb) == T.UPPER else "bassa"
        src, dst = T.BY_MAC.get(key[2]), T.BY_MAC.get(key[3])
        return {"src": src.name if src else key[2], "dst": dst.name if dst else key[3],
                "proto": {P.UDP: "UDP", P.TCP: "TCP", P.ICMP: "ICMP"}.get(key[4], str(key[4])),
                "dport": key[5], "class": P.COOKIE_NAMES.get(s.cookie, str(s.cookie)),
                "slice": sl, "queue": P.QUEUE_NAMES.get(queue, "-"),
                "packets": s.packet_count, "bytes": s.byte_count,
                "duration": s.duration_sec, "bps": round(bps)}

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        for s in ev.msg.body:
            key = (dpid, s.port_no)
            last = self.port_last.get(key)
            if last is not None and now > last[1]:
                self.port_rate[key] = max(0, (s.tx_bytes - last[0]) * 8 / (now - last[1]))
            self.port_last[key] = (s.tx_bytes, now)

    def _write_state(self, now):
        """Fotografia per la dashboard: file JSON scritto in modo atomico."""
        links = {}
        for dpid, port, sl in T.core_egress_ports():
            links[T.link_label(dpid, port)] = {
                "slice": sl, "bps": round(self.port_rate.get((dpid, port), 0)),
                "capacity_bps": T.LINK_MBPS[sl] * 1_000_000}
               # ogni flusso attraversa due link del core (es. s1->s2 e s2->s4): si divide per 2
   # per non contarlo due volte
        up = sum(v["bps"] for v in links.values() if v["slice"] == T.UPPER) / 2  # DUE link orientati per percorso
        low = sum(v["bps"] for v in links.values() if v["slice"] == T.LOWER) / 2  # DUE link orientati per percorso
        self.history.append({"t": round(now, 1), "upper": up, "lower": low})
        state = {"time": round(now, 1), "mode": self.policy.mode,
                 "video_active": self.policy.state.video_active,
                 "spoof_mode": self.cfg.SPOOF_MODE, "switches": sorted(self.dps),
                 "links": links, "counters": self.counters,
                 "events": list(self.event_log), "history": list(self.history),
                 "flows": sorted((r for rows in self.flow_rows.values() for r in rows),
                                 key=lambda r: -r["bps"])[:30]}
        path = self.cfg.STATE_FILE
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + ".tmp", "w") as f:
                json.dump(state, f)
            os.replace(path + ".tmp", path)
        except OSError:
            self.logger.exception("scrittura dello stato fallita")
