# -*- coding: utf-8 -*-
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def create_my_network():
    # Avvia Mininet pulendo eventuali residui precedenti
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    info('*** Aggiunta del Controller SDN (Ryu)\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Creazione degli Switch OpenFlow\n')
    s1 = net.addSwitch('s1')

    info('*** Creazione degli Host (H1, H2, H3)\n')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')

    info('*** Connessione degli Host allo Switch\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info('*** Avvio della Rete Virtuale\n')
    net.start()

    # Apre la riga di comando interattiva di Mininet
    CLI(net)

    info('*** Chiusura della Rete\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_my_network()