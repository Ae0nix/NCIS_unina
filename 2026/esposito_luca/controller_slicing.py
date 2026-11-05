import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from ryu.lib import stplib
from ryu.lib import hub

class FinalSTPController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(FinalSTPController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']

        # Parametri DoS (Finestra temporale ridotta a 1.0s per massima reattività)
        self.packet_counts = {}
        self.offense_counts = {}
        self.ban_until = {}
        self.RATE_LIMIT = 5
        self.TIME_WINDOW = 1.0
        self.BASE_BAN_TIME = 15

        # Network Slicing (Isolamento)
        self.slice_a_ips = ['10.0.0.1', '10.0.0.3']
        self.slice_b_ips = ['10.0.0.2', '10.0.0.4']

        # Strutture per il Polling Statistiche
        self.datapaths = {}
        self.flow_stats = {}
        self.monitor_thread = hub.spawn(self._monitor)

    # ====================================================
    # MONITORAGGIO ATTIVO (Polling Statistiche)
    # ====================================================
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            hub.sleep(self.TIME_WINDOW)
            for dp in self.datapaths.values():
                self._request_stats(dp)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        
        for stat in body:
            if stat.priority not in [10, 20, 50]:
                continue
            
            if 'eth_src' in stat.match:
                src = stat.match['eth_src']
                key = (datapath.id, src, stat.match.get('eth_dst'))
                curr_packets = stat.packet_count
                
                if key in self.flow_stats:
                    rate = curr_packets - self.flow_stats[key]
                    if rate > self.RATE_LIMIT:
                        self._trigger_ban(datapath, src, trigger_type="STATISTICHE")
                
                self.flow_stats[key] = curr_packets

    # ====================================================
    # LOGICA DI BAN CENTRALIZZATA
    # ====================================================
    def _trigger_ban(self, datapath, src, trigger_type="PACKET_IN"):
        now = time.time()
        if src in self.ban_until and now < self.ban_until[src]:
            return # È già bannato, ignoriamo

        self.offense_counts[src] = self.offense_counts.get(src, 0) + 1
        offenses = self.offense_counts[src]
        ban_duration = self.BASE_BAN_TIME * (2 ** (offenses - 1))
        self.ban_until[src] = now + ban_duration

        self.logger.warning(f"\n>>> [DOS DA {trigger_type}] Host {src} bloccato per {ban_duration}s! (Infrazione #{offenses}) <<<\n")
        
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src)
        self.add_flow(datapath, priority=100, match=match, actions=[], hard_timeout=ban_duration)

    # ====================================================
    # FUNZIONI BASE OPENFLOW
    # ====================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
                                priority=priority, match=match, instructions=inst,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    # ====================================================
    # ANALISI PACCHETTI (QoS, Slicing, DoS Iniziale)
    # ====================================================
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype in [35020, 34525]:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        now = time.time()

        # 1. CONTROLLO DOS (Sui nuovi pacchetti)
        if src in self.ban_until and now < self.ban_until[src]:
            return
        elif src in self.ban_until:
            del self.ban_until[src]

        if src not in self.packet_counts:
            self.packet_counts[src] = {'count': 0, 'start_time': now}

        if now - self.packet_counts[src]['start_time'] < self.TIME_WINDOW:
            self.packet_counts[src]['count'] += 1
        else:
            self.packet_counts[src] = {'count': 1, 'start_time': now}

        if self.packet_counts[src]['count'] > self.RATE_LIMIT:
            self._trigger_ban(datapath, src, trigger_type="PACKET_IN")
            return

        # 2. NETWORK SLICING (Isolamento Tenant)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        
        src_ip = ipv4_pkt.src if ipv4_pkt else (arp_pkt.src_ip if arp_pkt else None)
        dst_ip = ipv4_pkt.dst if ipv4_pkt else (arp_pkt.dst_ip if arp_pkt else None)

        if src_ip and dst_ip:
            if (src_ip in self.slice_a_ips and dst_ip in self.slice_b_ips) or \
               (src_ip in self.slice_b_ips and dst_ip in self.slice_a_ips):
                self.logger.info(f"[SLICING] Traffico bloccato tra tenant: {src_ip} -> {dst_ip}")
                match = parser.OFPMatch(eth_type=eth.ethertype, ipv4_src=src_ip, ipv4_dst=dst_ip) if ipv4_pkt else \
                        parser.OFPMatch(eth_type=eth.ethertype, arp_spa=src_ip, arp_tpa=dst_ip)
                self.add_flow(datapath, priority=80, match=match, actions=[])
                return

        # 3. SERVICE SLICING & QoS
        flow_priority = 10
        if ipv4_pkt:
            if pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp):
                flow_priority = 50
            elif pkt.get_protocol(icmp.icmp):
                flow_priority = 20

        # 4. LEARNING SWITCH
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, flow_priority, match, actions, msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ====================================================
    # GESTORI EVENTI STP
    # ====================================================
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        self.logger.warning("\n[STP] Cambio topologia rilevato! Ricalcolo i percorsi...\n")
        self.mac_to_port.clear()

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        port_state = "FORWARDING (Attiva)" if ev.port_state == stplib.PORT_STATE_FORWARD else "BLOCKING (Bloccata)"
        self.logger.info(f"[STP] Switch {ev.dp.id}, Porta {ev.port_no} -> {port_state}")