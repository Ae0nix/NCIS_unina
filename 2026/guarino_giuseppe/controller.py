from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types, tcp, udp
from ryu.lib import hub 
import math
import time
import csv

class DoSController(app_manager.RyuApp):
    OFP_VERSIONS =  [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(DoSController, self).__init__(*_args, **_kwargs)
        self.mac_to_port = {} #dizionario per il MAC learning
        
        self.datapaths = {} #traccia gli switch connessi
        self.flow_stats_history = {} #storico dei contatori per calcolare il delta
        self.entropy_history = {} #storia delle entropie calcolate
        
        self.trunk_ports = {2: 1, 3: 1, 4: 1} #mappa delle porte trunk (porte che collegano edge a core)
        
        self.WINDOW_SIZE = 5 #costante per la finestra temporale
        self.DEFAULT_ENTROPY_THRESHOLD = 0.5 #soglia entropia base
        self.MIN_PKT = 50 #minimo di pacchetti in entrata per rilevare attacco DoS
        self.MIN_BASELINE = 5 #minimo di misurazioni sane per attivare il rilevamento 

        #avvio del thread in background per le letture
        self.monitor_thread = hub.spawn(self._monitor)

        #inizializzazione file di log con timestamp
        self.csv_file = f"metriche_ddos_{int(time.time())}.csv"
        with open(self.csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Timestamp', 'Switch_DPID', 'Pacchetti_In_Trunk', 'Entropia', 'Soglia', 'Attacco'])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Gestione della connessione e disconnessione degli switch"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Switch {datapath.id} connesso. Inizio monitoraggio hardware.")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Regola base: inviare pacchetti sconosciuti al controller"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Funzione per l'installazione delle regole negli switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, 
                                instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _monitor(self):
        """Thread asincrono che richiede le statistiche agli switch ogni 5 secondi"""
        while True:
            hub.sleep(self.WINDOW_SIZE)
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

    def calc_entropy(self, current_tot, current_num_ip):
        """Funzione per calcolare l'entropia di Shannon in base agli ip di destinazione raccolti per uno specifico switch"""
        entropy = 0.0
        if current_tot == 0: 
            #se non ci sono pacchetti ritorna zero 
            return entropy
        for count in current_num_ip.values():
            P = count / current_tot
            entropy -= P * math.log2(P)
        return entropy

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Gestione delle risposte alle richieste di statistiche"""
        msg = ev.msg
        dpid = msg.datapath.id
        
        self.flow_stats_history.setdefault(dpid, {})
        self.entropy_history.setdefault(dpid, [])

        #esclude il core switch (s1) dal calcolo
        trunk_port = self.trunk_ports.get(dpid, None)
        if trunk_port is None:
            return
            
        current_tot = 0
        current_num_ip = {}
        current_vectors = {}
        new_history = {} 

        for stat in msg.body:
            if stat.priority != 1: 
                continue
            
            match = stat.match
            if 'ipv4_dst' in match and 'in_port' in match:

                #ignora le risposte della vittima, conta solo le richieste in entrata dalla trunk port
                if match['in_port'] != trunk_port:
                    continue
                
                flow_key = str(match)
                prev = self.flow_stats_history[dpid].get(flow_key) 

                #se il flusso è nuovo o scaduto riparte da zero, altrimenti fa la differenza
                if prev is None or stat.packet_count < prev[0] or stat.duration_sec < prev[1]:    
                    delta = stat.packet_count #flusso nuovo o scaduto
                else:    
                    delta = stat.packet_count - prev[0] #aggiornamento incrementale
                    
                new_history[flow_key] = (stat.packet_count, stat.duration_sec)
                
                if delta > 0:
                    ip_dst = match['ipv4_dst']
                    in_port = match['in_port']
                    proto = match.get('ip_proto')
                    dst_port = match.get('tcp_dst') or match.get('udp_dst')

                    #aggiorna contatori e dizionario dei vettori
                    current_tot += delta
                    current_num_ip[ip_dst] = current_num_ip.get(ip_dst, 0) + delta
                    
                    current_vectors.setdefault(ip_dst, {})
                    vector_tuple = (in_port, proto, dst_port)
                    current_vectors[ip_dst][vector_tuple] = current_vectors[ip_dst].get(vector_tuple, 0) + delta

        self.flow_stats_history[dpid].update(new_history)
        
        if current_tot == 0:
            return

        act_time = time.time()
        entropy = self.calc_entropy(current_tot, current_num_ip)

        self.logger.info("--- Monitoraggio (Solo Traffico Trunk) ---")
        self.logger.info(f"Switch {dpid} | Pacchetti Entranti: {current_tot} | Entropia: {entropy:.4f}")

        ha_baseline_sufficiente = len(self.entropy_history[dpid]) >= self.MIN_BASELINE

        #se ci sono almeno 5 misurazioni si calcola la media
        if ha_baseline_sufficiente:
            media_act = sum(self.entropy_history[dpid]) / len(self.entropy_history[dpid])
            din_threshold = media_act * 0.70 #la soglia è il 30% in meno della media
            soglia_log = round(din_threshold, 4)
            tipo_soglia = "Dinamica"
        else:
            din_threshold = self.DEFAULT_ENTROPY_THRESHOLD
            soglia_log = "Apprendimento"
            tipo_soglia = "Statica (In apprendimento)"

        self.logger.info(f"Soglia in uso ({tipo_soglia}): {soglia_log}")
        
        attacco_in_corso = False
        
        if entropy < din_threshold and current_tot > self.MIN_PKT and ha_baseline_sufficiente:
            ip_vittima = max(current_num_ip, key=current_num_ip.get)
            attacco_in_corso = True
            self.logger.warning(f"!!! ATTACCO DOS RILEVATO SU SWITCH {dpid} VERSO {ip_vittima} !!!")
            self.mitigate_attack(msg.datapath, ip_vittima, current_vectors)

        #aggiunge l'entropia allo storico solo se è sana (sopra 0.5)    
        elif current_tot > self.MIN_PKT and entropy >= self.DEFAULT_ENTROPY_THRESHOLD:
            self.entropy_history[dpid].append(entropy)
            if len(self.entropy_history[dpid]) > 10:
                #mantiene solo le ultime 10 misurazioni
                self.entropy_history[dpid].pop(0)

        #salvataggio record
        orario_formattato = time.strftime('%H:%M:%S', time.localtime(act_time))
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([orario_formattato, dpid, current_tot, round(entropy, 4), soglia_log, attacco_in_corso])


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Gestione dei pacchetti in ingresso"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return #ignora i pacchetti di sistema LLDP

        dst = eth.dst
        src = eth.src
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            #se è ipv4 crea una regola specifica per contare i flussi
            if ip_pkt:
                match_args = {
                    'in_port': in_port, 'eth_dst': dst, 'eth_src': src,
                    'eth_type': 0x0800, 'ipv4_dst': ip_pkt.dst, 'ip_proto': ip_pkt.proto
                }
                if ip_pkt.proto == 6:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt: match_args['tcp_dst'] = tcp_pkt.dst_port
                elif ip_pkt.proto == 17:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt: match_args['udp_dst'] = udp_pkt.dst_port
                    
                match = parser.OFPMatch(**match_args)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype)

            #idle timeout permette al traffico di scorrere veloce in hardware
            self.add_flow(datapath, 1, match, actions, idle_timeout=20)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    def mitigate_attack(self, datapath, ip_dst, attack_vectors_dpid):
        """Funzione per l'installazione della regola di drop"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst_drop = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        
        if ip_dst in attack_vectors_dpid and attack_vectors_dpid[ip_dst]:
            #estraiamo la porta fisica di ingresso al posto dell'IP sorgente
            (attack_in_port, attack_proto, attack_port), max_count = max(attack_vectors_dpid[ip_dst].items(), key=lambda x: x[1])
            
            if attack_port is not None:
                proto_name = "TCP" if attack_proto == 6 else "UDP"
                self.logger.warning(f"Mitigazione L4: blocco {proto_name}/{attack_port} ingresso TRUNK {attack_in_port} verso {ip_dst}")
                if attack_proto == 6:
                    match = parser.OFPMatch(in_port=attack_in_port, eth_type=0x0800, ipv4_dst=ip_dst, ip_proto=6, tcp_dst=attack_port)
                else:
                    match = parser.OFPMatch(in_port=attack_in_port, eth_type=0x0800, ipv4_dst=ip_dst, ip_proto=17, udp_dst=attack_port)
            else:
                self.logger.warning(f"Mitigazione L3: blocco Protocollo {attack_proto} ingresso TRUNK {attack_in_port} verso {ip_dst}")
                match = parser.OFPMatch(in_port=attack_in_port, eth_type=0x0800, ipv4_dst=ip_dst, ip_proto=attack_proto)
                
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst_drop, hard_timeout=30)
            datapath.send_msg(mod)
        else:
            match_drop = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_dst)
            mod_drop = parser.OFPFlowMod(datapath=datapath, priority=100, match=match_drop, instructions=inst_drop, hard_timeout=30)
            datapath.send_msg(mod_drop)