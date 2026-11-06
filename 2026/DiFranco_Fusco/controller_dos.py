#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import time
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, tcp, ether_types
from ryu.lib import hub


class AdaptiveSlicingDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MONITOR_PERIOD = 2.0
    STATS_REPLY_WAIT = 0.3
    STAGE1_MBPS_THRESHOLD = 21.0
    STAGE1_SATURATION_MBPS = 2.2
    STAGE2_PPS_THRESHOLD = 4500.0
    STAGE1_MAX_PERSISTENCE = 3
    METER_RATE_KBPS = 3000
    QUARANTINE_TIMEOUT_S = 18

    GOLD_SERVER_IP = "10.0.0.100"
    SILVER_SERVER_IP = "10.0.0.200"
    GOLD_L4_PORT = 5001
    CORE_SWITCH_DPID = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # Discovery porte Access vs Trunk
        self.port_macs = defaultdict(set)
        self.trunk_ports = set()
        self.host_edge_switch = {}
        self.mitigated_target = {}

        # Stato contatori per calcolo bitrate incrementale
        self.prev_flow_stats = {}
        self.prev_port_stats = {}
        self.switch_host_rates = defaultdict(lambda: (0.0, 0.0))
        self.edge_port_rx_rates = defaultdict(lambda: (0.0, 0.0))

        # Stato difesa per host (0: Normal, 1: Meter 3 Mbps, 2: Drop)
        self.host_state = defaultdict(int)
        self.stage1_persistence = defaultdict(int)
        self.quarantine_until = defaultdict(float)
        self.meters_installed = set()

        self.start_time = time.time()
        self.csv_file = "telemetry.csv"
        with open(self.csv_file, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_s",
                "h1_gold_mbps",
                "h2_silver_mbps",
                "attacker_edge_mbps",
                "attacker_delivered_mbps",
                "max_mitigation_stage"
            ])
            f.flush()

        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.logger.info("Controller SDN avviato correttamente.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("[SWITCH CONNESSO] Registrato switch s%d", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        if actions:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def ensure_meter_installed(self, datapath, meter_id):
        key = (datapath.id, meter_id)
        if key in self.meters_installed:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = [parser.OFPMeterBandDrop(rate=self.METER_RATE_KBPS, burst_size=300)]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)
        self.meters_installed.add(key)
        self.logger.info("[OPENFLOW METER] Installato Meter ID=%d su Switch s%d (Cap: %.1f Mbps)",
                         meter_id, datapath.id, self.METER_RATE_KBPS / 1000.0)

    def _update_topology_discovery(self, dpid, in_port, src_mac, src_ip=None):
        port_key = (dpid, in_port)
        self.port_macs[port_key].add(src_mac)

        if len(self.port_macs[port_key]) > 1:
            self.trunk_ports.add(port_key)
            for ip, (e_dpid, e_port) in list(self.host_edge_switch.items()):
                if (e_dpid, e_port) == port_key:
                    del self.host_edge_switch[ip]
            return

        if src_ip and port_key not in self.trunk_ports and dpid != self.CORE_SWITCH_DPID:
            if src_ip not in self.host_edge_switch:
                self.host_edge_switch[src_ip] = (dpid, in_port)
                self.logger.info("[EDGE DISCOVERY] Host %s localizzato su Edge Switch s%d (porta access %d)",
                                 src_ip, dpid, in_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dst_mac = eth.dst
        src_mac = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        self._update_topology_discovery(dpid, in_port, src_mac)

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_dst=dst_mac)
                self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=60)
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto

            self._update_topology_discovery(dpid, in_port, src_mac, src_ip=src_ip)

            if self.host_state[src_ip] == 2 and time.time() < self.quarantine_until[src_ip]:
                return

            edge_info = self.host_edge_switch.get(src_ip)
            if out_port != ofproto.OFPP_FLOOD and edge_info and edge_info[0] == dpid:
                if dst_ip in (self.GOLD_SERVER_IP, self.SILVER_SERVER_IP):
                    self.mitigated_target[src_ip] = (dst_ip, out_port)

            if proto == 1:
                actions = [parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=1,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip
                    )
                    self.add_flow(datapath, priority=15, match=match, actions=actions, idle_timeout=60)
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
                return

            l4_dst_port = None
            l4_src_port = None
            if proto == 17:
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    l4_dst_port = udp_pkt.dst_port
                    l4_src_port = udp_pkt.src_port
            elif proto == 6:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    l4_dst_port = tcp_pkt.dst_port
                    l4_src_port = tcp_pkt.src_port

            is_gold_service = (
                l4_dst_port == self.GOLD_L4_PORT
                or l4_src_port == self.GOLD_L4_PORT
                or dst_ip == self.GOLD_SERVER_IP
                or src_ip == self.GOLD_SERVER_IP
            )
            queue_id = 1 if is_gold_service else 2

            actions = [
                parser.OFPActionSetQueue(queue_id),
                parser.OFPActionOutput(out_port)
            ]

            if out_port != ofproto.OFPP_FLOOD:
                match_kwargs = {
                    "eth_type": ether_types.ETH_TYPE_IP,
                    "ip_proto": proto,
                    "ipv4_src": src_ip,
                    "ipv4_dst": dst_ip
                }
                if proto == 17 and l4_dst_port is not None:
                    match_kwargs["udp_dst"] = l4_dst_port
                elif proto == 6 and l4_dst_port is not None:
                    match_kwargs["tcp_dst"] = l4_dst_port

                match = parser.OFPMatch(**match_kwargs)
                self.add_flow(datapath, priority=20, match=match, actions=actions, idle_timeout=60)

            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)

    def _monitor_loop(self):
        while True:
            try:
                hub.sleep(self.MONITOR_PERIOD - self.STATS_REPLY_WAIT)
                for dp in list(self.datapaths.values()):
                    parser = dp.ofproto_parser
                    ofproto = dp.ofproto
                    dp.send_msg(parser.OFPFlowStatsRequest(dp))
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY))
                hub.sleep(self.STATS_REPLY_WAIT)
                self._evaluate_and_log()
            except Exception as e:
                self.logger.error("Errore nel loop di monitoraggio: %s", str(e))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            if stat.port_no > 1000:
                continue
            key = (dpid, stat.port_no)
            if key not in self.prev_port_stats:
                self.prev_port_stats[key] = (stat.rx_bytes, stat.rx_packets, now)
                continue

            prev_rx_b, prev_rx_p, prev_t = self.prev_port_stats[key]
            dt = max(1.0, now - prev_t)
            d_rx_b = max(0, stat.rx_bytes - prev_rx_b)
            d_rx_p = max(0, stat.rx_packets - prev_rx_p)
            self.prev_port_stats[key] = (stat.rx_bytes, stat.rx_packets, now)

            rx_mbps = (d_rx_b * 8.0) / (dt * 1_000_000.0)
            rx_pps = d_rx_p / dt
            self.edge_port_rx_rates[(dpid, stat.port_no)] = (rx_mbps, rx_pps)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        best_prio_per_host = defaultdict(int)
        host_mbps = defaultdict(float)
        host_pps = defaultdict(float)
        seen_hosts = set()

        for stat in ev.msg.body:
            if stat.priority < 20:
                continue
            if "ipv4_src" not in stat.match or "ipv4_dst" not in stat.match:
                continue

            src_ip = stat.match["ipv4_src"]
            dst_ip = stat.match["ipv4_dst"]
            if dst_ip not in (self.GOLD_SERVER_IP, self.SILVER_SERVER_IP):
                continue

            proto = stat.match.get("ip_proto", 0)
            l4_port = stat.match.get("udp_dst", stat.match.get("tcp_dst", 0))
            key = (dpid, stat.priority, src_ip, dst_ip, proto, l4_port)

            if key not in self.prev_flow_stats:
                d_bytes = stat.byte_count
                d_pkts = stat.packet_count
                dt = self.MONITOR_PERIOD
            else:
                prev_bytes, prev_pkts, prev_t = self.prev_flow_stats[key]
                dt = max(1.0, now - prev_t)
                d_bytes = max(0, stat.byte_count - prev_bytes)
                d_pkts = max(0, stat.packet_count - prev_pkts)

            self.prev_flow_stats[key] = (stat.byte_count, stat.packet_count, now)
            seen_hosts.add(src_ip)

            mbps = (d_bytes * 8.0) / (dt * 1_000_000.0)
            pps = d_pkts / dt

            if stat.priority > best_prio_per_host[src_ip]:
                best_prio_per_host[src_ip] = stat.priority
                host_mbps[src_ip] = mbps
                host_pps[src_ip] = pps
            elif stat.priority == best_prio_per_host[src_ip]:
                host_mbps[src_ip] += mbps
                host_pps[src_ip] += pps

        all_hosts = seen_hosts.union(self.host_edge_switch.keys())
        for src_ip in all_hosts:
            self.switch_host_rates[(dpid, src_ip)] = (host_mbps[src_ip], host_pps[src_ip])

    def _apply_stage1_meter(self, edge_dp, src_ip, dst_ip, edge_out_port):
        meter_id = int(src_ip.split(".")[-1])
        self.ensure_meter_installed(edge_dp, meter_id)

        parser = edge_dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        actions = [
            parser.OFPActionSetQueue(3),
            parser.OFPActionOutput(edge_out_port)
        ]
        self.prev_flow_stats.pop((edge_dp.id, 50, src_ip, dst_ip, 0, 0), None)
        self.add_flow(edge_dp, priority=50, match=match, actions=actions, idle_timeout=30, meter_id=meter_id)

    def _apply_stage2_drop(self, edge_dp, src_ip, dst_ip):
        parser = edge_dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        self.prev_flow_stats.pop((edge_dp.id, 100, src_ip, dst_ip, 0, 0), None)
        self.add_flow(
            edge_dp,
            priority=100,
            match=match,
            actions=[],
            hard_timeout=self.QUARANTINE_TIMEOUT_S
        )

    def _remove_mitigation_flows(self, edge_dp, src_ip, dst_ip):
        ofproto = edge_dp.ofproto
        parser = edge_dp.ofproto_parser
        for prio in (50, 100):
            self.prev_flow_stats.pop((edge_dp.id, prio, src_ip, dst_ip, 0, 0), None)
            mod = parser.OFPFlowMod(
                datapath=edge_dp,
                command=ofproto.OFPFC_DELETE_STRICT,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPP_ANY,
                priority=prio,
                match=parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
            )
            edge_dp.send_msg(mod)

    def _evaluate_and_log(self):
        if len(self.datapaths) < 3:
            return

        now = time.time()
        elapsed = round(now - self.start_time, 1)

        for src_ip, (edge_dpid, access_port) in list(self.host_edge_switch.items()):
            edge_dp = self.datapaths.get(edge_dpid)
            if edge_dp is None or src_ip not in self.mitigated_target:
                continue

            dst_ip, out_port = self.mitigated_target[src_ip]
            edge_mbps, edge_pps = self.edge_port_rx_rates[(edge_dpid, access_port)]
            core_mbps, _ = self.switch_host_rates[(self.CORE_SWITCH_DPID, src_ip)]
            state = self.host_state[src_ip]

            if state == 0:
                if edge_pps > self.STAGE2_PPS_THRESHOLD:
                    self.host_state[src_ip] = 2
                    self.quarantine_until[src_ip] = now + self.QUARANTINE_TIMEOUT_S
                    self._apply_stage2_drop(edge_dp, src_ip, dst_ip)
                    self.logger.warning(
                        "[ALLARME DoS - STADIO 2] Host %s su Edge s%d (%.1f Mbps, %.0f pps) -> DROP (%ds)",
                        src_ip, edge_dpid, edge_mbps, edge_pps, self.QUARANTINE_TIMEOUT_S
                    )
                elif edge_mbps > self.STAGE1_MBPS_THRESHOLD:
                    self.host_state[src_ip] = 1
                    self.stage1_persistence[src_ip] = 1
                    self._apply_stage1_meter(edge_dp, src_ip, dst_ip, out_port)
                    self.logger.warning(
                        "[ANOMALIA - STADIO 1] Host %s su Edge s%d (%.1f Mbps > %.1f Mbps) -> Throttling 3.0 Mbps",
                        src_ip, edge_dpid, edge_mbps, self.STAGE1_MBPS_THRESHOLD
                    )

            elif state == 1:
                if edge_mbps >= self.STAGE1_SATURATION_MBPS or core_mbps >= self.STAGE1_SATURATION_MBPS or edge_pps > self.STAGE2_PPS_THRESHOLD:
                    self.stage1_persistence[src_ip] += 1
                    if self.stage1_persistence[src_ip] > self.STAGE1_MAX_PERSISTENCE or edge_pps > self.STAGE2_PPS_THRESHOLD:
                        self.host_state[src_ip] = 2
                        self.quarantine_until[src_ip] = now + self.QUARANTINE_TIMEOUT_S
                        self._apply_stage2_drop(edge_dp, src_ip, dst_ip)
                        self.logger.error(
                            "[ESCALATION DoS - STADIO 2] Host %s satura lo Stadio 1 su Edge s%d (%ds) -> DROP (%ds)",
                            src_ip, edge_dpid,
                            (self.stage1_persistence[src_ip] - 1) * int(self.MONITOR_PERIOD),
                            self.QUARANTINE_TIMEOUT_S
                        )
                elif edge_mbps < 1.0 and core_mbps < 1.0:
                    self.host_state[src_ip] = 0
                    self.stage1_persistence[src_ip] = 0
                    self._remove_mitigation_flows(edge_dp, src_ip, dst_ip)
                    self.logger.info("[RIPRISTINO] Host %s su s%d tornato normale -> Stato 0", src_ip, edge_dpid)

            elif state == 2:
                if now >= self.quarantine_until[src_ip]:
                    self.host_state[src_ip] = 0
                    self.stage1_persistence[src_ip] = 0
                    self._remove_mitigation_flows(edge_dp, src_ip, dst_ip)
                    self.logger.info(
                        "[AUTO-HEALING] Fine quarantena per Host %s su Edge s%d -> Stato NORMAL (0)",
                        src_ip, edge_dpid
                    )

        h1_gold_mbps, _ = self.switch_host_rates[(self.CORE_SWITCH_DPID, "10.0.0.1")]
        h2_silver_mbps, _ = self.switch_host_rates[(self.CORE_SWITCH_DPID, "10.0.0.2")]
        h3_delivered_mbps, _ = self.switch_host_rates[(self.CORE_SWITCH_DPID, "10.0.0.3")]

        h3_edge_dpid, h3_access_port = self.host_edge_switch.get("10.0.0.3", (2, 1))
        h3_edge_mbps, _ = self.edge_port_rx_rates[(h3_edge_dpid, h3_access_port)]

        max_stage = max(self.host_state.values()) if self.host_state else 0

        with open(self.csv_file, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"{elapsed:.1f}",
                f"{h1_gold_mbps:.2f}",
                f"{h2_silver_mbps:.2f}",
                f"{h3_edge_mbps:.2f}",
                f"{h3_delivered_mbps:.2f}",
                int(max_stage)
            ])
            f.flush()