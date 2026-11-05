from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import sys
import time

#stessi valori del controller: il warm up dura 8 finestre per completare la baseline
WINDOW_SIZE = 5
MIN_BASELINE = 5
WARMUP = WINDOW_SIZE * (MIN_BASELINE + 3)

class MyTopo(Topo):
    def build(self):
        #add switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13') #switch core
        s2 = self.addSwitch('s2', protocols='OpenFlow13') #switch edge (vittima e utente)
        s3 = self.addSwitch('s3', protocols='OpenFlow13') #switch edge (attaccante A)
        s4 = self.addSwitch('s4', protocols='OpenFlow13') #switch edge (attaccante B, attaccante C, utente)

        #add host
        h1 = self.addHost('h1', ip = '10.0.0.1/24') #vittima
        h2 = self.addHost('h2', ip = '10.0.0.2/24') #utente locale
        h3 = self.addHost('h3', ip = '10.0.0.3/24') #attaccante A (TCP)
        h4 = self.addHost('h4', ip = '10.0.0.4/24') #attaccante B (UDP)
        h5 = self.addHost('h5', ip = '10.0.0.5/24') #attaccante C (ICMP)
        h6 = self.addHost('h6', ip = '10.0.0.6/24') #utente remoto

        #add link core-edge
        self.addLink(s2, s1)
        self.addLink(s3, s1)
        self.addLink(s4, s1)

        #add link edge-host
        self.addLink(h1, s2)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)
        self.addLink(h5, s4)
        self.addLink(h6, s4)

def run_test(net, tipi_attacco, abilita_spoofing = False):
    """Funzione per eseguire la sequenza automatizzata di attacchi scelti"""
    h1, h2, h3, h4, h5, h6 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6')
    s2 = net.get('s2')

    #popola le tabelle ARP degli host e il MAC learning degli switch prima del test
    info("Popolamento tabelle ARP/MAC...\n")
    net.pingAll()

    #configura la vittima per ridurre il traffico di risposta (echo reply e RST)
    info("Configurazione vittima (h1) per ignorare ICMP echo e droppare TCP RST in uscita...\n")
    h1.cmd('sysctl -w net.ipv4.icmp_echo_ignore_all=1')
    h1.cmd('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

    attacchi_str = ", ".join(tipi_attacco).upper()
    modalita_str = "CON SPOOFING (IP Casuali)" if abilita_spoofing else "NORMALE (IP Reali)"
    info(f"\n--- AVVIO TEST AUTOMATICO: {attacchi_str} | MODALITA': {modalita_str} ---\n")

    info("1. Fase di riscaldamento (Traffico UDP Legittimo remoto da h6 verso h1 e h2)\n")
    info(f"   Il controller sta calcolando la baseline entropica sul trunk... attendere {WARMUP}s\n")

    #traffico legittimo UDP per popolare lo storico (porta 5001 per evitare collisioni col test ICMP)
    #il traffico verso h1 e h2 entra in s2 dalla trunk con entropia ~1.0 (> 0.5)
    #lo stdin da /dev/null evita che il processo in background venga sospeso dalla shell dell'host
    h6.cmd('hping3 --udp -p 5001 -i u50000 10.0.0.1 < /dev/null > /dev/null 2>&1 &')
    h6.cmd('hping3 --udp -p 5001 -i u50000 10.0.0.2 < /dev/null > /dev/null 2>&1 &')
    time.sleep(10)

    #controllo che il warm-up sia attivo e che i flussi sulla trunk di s2 contino i pacchetti
    info("   Controllo warm-up (processi attivi su h6):\n")
    info(h6.cmd('ps -o pid,stat,cmd -C hping3') + "\n")
    info("   Controllo warm-up (flussi sulla trunk di s2):\n")
    info(s2.cmd('ovs-ofctl -O OpenFlow13 dump-flows s2 | grep 5001') + "\n")
    time.sleep(WARMUP - 10)

    #costruzione del parametro per lo spoofing
    spoof_flag = "--rand-source " if abilita_spoofing else ""
    testo_spoof = " con SPOOFING" if abilita_spoofing else ""

    #esegue gli attacchi richiesti
    for indice, attacco in enumerate(tipi_attacco):
        if attacco == 'tcp':
            info(f"\n-> ESECUZIONE: Attacco TCP SYN Flood{testo_spoof} (Porta 80 da h3)\n")
            h3.cmd(f'hping3 -S -p 80 -i u1000 -c 10000 {spoof_flag}10.0.0.1 < /dev/null > /dev/null 2>&1 &')
            time.sleep(12)

        elif attacco == 'udp':
            info(f"\n-> ESECUZIONE: Attacco UDP Flood{testo_spoof} (Porta 53 da h4)\n")
            h4.cmd(f'hping3 --udp -p 53 -i u1000 -c 10000 {spoof_flag}10.0.0.1 < /dev/null > /dev/null 2>&1 &')
            time.sleep(12)

        elif attacco == 'icmp':
            info(f"\n-> ESECUZIONE: Attacco ICMP Flood{testo_spoof} (Senza porte da h5)\n")
            h5.cmd(f'hping3 -1 -i u1000 -c 10000 {spoof_flag}10.0.0.1 < /dev/null > /dev/null 2>&1 &')
            time.sleep(12)

        #attesa per far scadere il drop se non è l'ultimo attacco della lista
        if indice < len(tipi_attacco) - 1:
            info("   Attesa 32s per far scadere la mitigazione OpenFlow prima del prossimo attacco...\n")
            time.sleep(32)

    info("\n--- TEST AUTOMATICO COMPLETATO ---\n")
    CLI(net)

    #pulizia processi di traffico legittimo alla chiusura della console
    h6.cmd("pkill -f 'hping3.*5001'")

def run():
    topo = MyTopo()

    #configurazione controller ryu locale sulla porta standard 6653
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=c0, autoSetMacs=True)
    net.start()

    #attesa che gli switch si connettano al controller
    info("*** Attesa connessione switch al controller...\n")
    net.waitConnected()

    #controllo se l'utente ha richiesto lo spoofing
    usa_spoofing = '--spoofing' in sys.argv

    #gestione degli argomenti da riga di comando per avviare i test
    if '--test' in sys.argv:
        idx = sys.argv.index('--test')
        argomenti_inseriti = sys.argv[idx + 1:]

        #filtra solo i nomi validi
        tipi_validi = ['tcp', 'udp', 'icmp', 'all']
        attacchi_selezionati = [arg.lower() for arg in argomenti_inseriti if arg.lower() in tipi_validi]

        #se viene scritto "all" o nessun argomento, esegue tutti gli attacchi
        if 'all' in attacchi_selezionati or len(attacchi_selezionati) == 0:
            sequenza_finale = ['tcp', 'udp', 'icmp']
        else:
            #rimuove doppioni preservando l'ordine di inserimento
            sequenza_finale = list(dict.fromkeys(attacchi_selezionati))

        run_test(net, sequenza_finale, usa_spoofing)
    else:
        info("\n*** Modalita' Normale. Rete pronta (Nessun attacco). ***\n")
        CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()