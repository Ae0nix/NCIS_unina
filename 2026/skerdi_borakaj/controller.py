from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub

class SimpleMonitorController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitorController, self).__init__(*args, **kwargs)
        # Tabella per memorizzare l'associazione MAC -> Porta dello Switch (Learning Switch)
        self.mac_to_port = {}
        # Lista degli switch connessi per inviare le richieste di statistiche
        self.datapaths = {}
        # Avvia un thread in background per il monitoraggio periodico ogni 10 secondi
        self.monitor_thread = hub.spawn(self._monitor)
        print(">>> CONTROLLER RYU AVVIATO CORRETTAMENTE <<<")

    # 1. GESTIONE CONNESSIONE SWITCH
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Salviamo lo switch per poterlo interrogare nelle statistiche
        self.datapaths[datapath.id] = datapath

        # Regola di default (table-miss, priorità 0): se non c'è match, invia al controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Funzione helper per aggiungere regole (flussi) nello switch
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    # 2. PUNTO 1: L2 LEARNING SWITCH (APPRENDIMENTO DEI MAC ADDRESS)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Estrae le informazioni Ethernet dal pacchetto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # APPRENDIMENTO: lo switch impara che il MAC sorgente si trova su 'in_port'
        self.mac_to_port[dpid][src] = in_port

        # Se conosciamo la porta del destinatario inoltriamo direttamente, altrimenti FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Se la porta è nota, INSTALLA LA REGOLA sullo switch con priorità 1.
        # I prossimi pacchetti per questo destinatario non passeranno più dal controller!
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        # Invia il primo pacchetto allo switch per l'inoltro
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    # 3. PUNTO 2: MONITORAGGIO PERIODICO (STATISTICHE FLUSSI OGNI 10 SECONDI)
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        # Richiede allo switch il riepilogo dei flussi attivi
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Riceve la risposta dallo switch con le statistiche
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        print("\n================ [MONITORAGGIO STATISTICHE FLUSSI] ================")
        active_flows = 0
        for stat in body:
            # Mostriamo solo i flussi appresi (priorità 1), escludendo la table-miss (priorità 0)
            if stat.priority == 1:
                active_flows += 1
                dst_mac = stat.match.get('eth_dst', 'N/D')
                in_p = stat.match.get('in_port', 'N/D')
                print(f"-> Regola: In-Port={in_p} Verso MAC={dst_mac} | Pacchetti={stat.packet_count} | Byte={stat.byte_count}")
        
        if active_flows == 0:
            print("Nessun flusso specifico attivo al momento (solo table-miss).")
        print("===================================================================\n")
