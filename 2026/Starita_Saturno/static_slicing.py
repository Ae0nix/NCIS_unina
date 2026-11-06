from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import ether_types

S1_DPID = 1
S2_DPID = 2   # upper
S3_DPID = 3   # lower
S4_DPID = 4

class StrictSliceDPID(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.H1 = '00:00:00:00:00:01'
        self.H2 = '00:00:00:00:00:02'
        self.H3 = '00:00:00:00:00:03'
        self.H4 = '00:00:00:00:00:04'
        self.allowed = {
            (self.H1, self.H3), (self.H3, self.H1),
            (self.H2, self.H4), (self.H4, self.H2)
        }

    def add_flow(self, dp, prio, match, actions, buffer_id=None):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id,
                                    priority=prio, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=dp, priority=prio,
                                    match=match, instructions=inst)
        dp.send_msg(mod)

    def pkt_out(self, dp, in_port, actions, data=None, buffer_id=None):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(datapath=dp, buffer_id=buffer_id,
                                      in_port=in_port, actions=actions)
        else:
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    def violates_slice(self, src_mac, dpid):
        if src_mac in (self.H1, self.H3) and dpid == S3_DPID:
            return True
        if src_mac in (self.H2, self.H4) and dpid == S2_DPID:
            return True
        return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        self.logger.info("Switch connected: DPID=%s", dp.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dpid, in_port = dp.id, msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src, dst, etype = eth.src, eth.dst, eth.ethertype
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        
        if etype == ether_types.ETH_TYPE_ARP:
            if self.violates_slice(src, dpid):
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_type=etype)
                self.add_flow(dp, 100, match, [])
                return
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            self.pkt_out(dp, in_port, actions, data=msg.data, buffer_id=msg.buffer_id)
            return

        if self.violates_slice(src, dpid):
            match = parser.OFPMatch(in_port=in_port, eth_src=src)
            self.add_flow(dp, 100, match, [])
            return

        if (src, dst) not in self.allowed:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(dp, 100, match, [])
            return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(dp, 10, match, actions, buffer_id=msg.buffer_id)
        else:
            self.add_flow(dp, 10, match, actions)
            self.pkt_out(dp, in_port, actions, data=msg.data)
