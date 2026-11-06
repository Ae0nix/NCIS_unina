from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp


class SliceEnforcingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Porte verso backbone
    PORT_S2 = 3  # Porta verso S2
    PORT_S3 = 4  # Porta verso S3

    # Host collegati a S1 e S4
    HOST_PORTS = {
        1: [1,2],   # S1: h1, h2
        4: [1,2],   # S4: h3, h4
    }

    PRIORITY_DEFAULT = 10
    PRIORITY_VIDEO   = 20

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath   # lo switch
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Proactive match per traffico video
        match_video_dst = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ip_proto=17,       # UDP
            udp_dst=9999
        )

        match_video_src = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=17,
            udp_src=9999
        )

        actions_video = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                ofp.OFPCML_NO_BUFFER)]

        self.add_flow(dp, 15, match_video_dst, actions_video)
        self.add_flow(dp, 15, match_video_src, actions_video)

        # Regola di default
        match_default = parser.OFPMatch()
        actions_default = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                  ofp.OFPCML_NO_BUFFER)]

        self.add_flow(dp, 0, match_default, actions_default)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)  # estrae il pacchetto
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:  # ignora traffico non Ethernet
            return

        src = eth.src
        dst = eth.dst

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Flag se pacchetto è video (UDP porta 9999)
        is_video = bool(ip_pkt and udp_pkt and
                        (udp_pkt.dst_port == 9999 or udp_pkt.src_port == 9999))

        if dpid in (1, 4):  # Access switches
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]

                # Se l'output port è sbagliata la cambia
                if is_video and out_port == self.PORT_S3:
                    out_port = self.PORT_S2
                elif not is_video and out_port == self.PORT_S2:
                    out_port = self.PORT_S3

                actions = [parser.OFPActionOutput(out_port)]

                if is_video:
                    if udp_pkt and udp_pkt.dst_port == 9999:
                        match = parser.OFPMatch(
                            in_port=in_port,
                            eth_src=src,
                            eth_dst=dst,
                            eth_type=0x0800,
                            ip_proto=17,
                            udp_dst=9999
                        )
                        self.add_flow(dp, self.PRIORITY_VIDEO, match, actions)

                    if udp_pkt.src_port == 9999:
                        match = parser.OFPMatch(
                            in_port=in_port,
                            eth_src=src,
                            eth_dst=dst,
                            eth_type=0x0800,
                            ip_proto=17,
                            udp_src=9999
                        )
                        self.add_flow(dp, self.PRIORITY_VIDEO, match, actions)
                else:
                    match_default = parser.OFPMatch(
                        in_port=in_port,
                        eth_src=src,
                        eth_dst=dst
                    )
                    self.add_flow(dp, self.PRIORITY_DEFAULT, match_default, actions)

            else:
                # Flood verso host locali + uno tra S2/S3
                flood_ports = list(self.HOST_PORTS[dpid])
                flood_ports.append(self.PORT_S2 if is_video else self.PORT_S3)
                actions = [parser.OFPActionOutput(p) for p in flood_ports]

        else:  # Backbone switches (s2, s3)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst
                )

                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self.add_flow(dp, self.PRIORITY_DEFAULT, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(dp, self.PRIORITY_DEFAULT, match, actions)
            else:
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions,
            data=data
        )
        dp.send_msg(out)
