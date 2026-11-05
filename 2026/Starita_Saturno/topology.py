import threading
import random
import time
from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host, RemoteController
from mininet.link import TCLink

class Environment(object):
    def __init__(self):
        
        self.net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

        # Controller remoto
        self.c1 = self.net.addController('c1', controller=RemoteController)

        info("*** CREAZIONE HOST E SWITCH\n")
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')

        self.s1 = self.net.addSwitch('s1', protocols='OpenFlow13')
        self.s2 = self.net.addSwitch('s2', protocols='OpenFlow13')
        self.s3 = self.net.addSwitch('s3', protocols='OpenFlow13')
        self.s4 = self.net.addSwitch('s4', protocols='OpenFlow13')

        info("*** CREAZIONE COLLEGAMENTI\n")
        self.net.addLink(self.h1, self.s1, bw=10, delay='0.0025ms')
        self.net.addLink(self.h2, self.s1, bw=10, delay='0.0025ms')
        self.net.addLink(self.h3, self.s4, bw=10, delay='0.0025ms')
        self.net.addLink(self.h4, self.s4, bw=10, delay='0.0025ms')

        self.net.addLink(self.s1, self.s2, bw=10, delay='25ms')
        self.net.addLink(self.s2, self.s4, bw=10, delay='25ms')
        self.net.addLink(self.s1, self.s3, bw=1, delay='25ms')
        self.net.addLink(self.s3, self.s4, bw=1, delay='25ms')

        info("*** AVVIO RETE\n")
        self.net.build()
        self.net.start()

if __name__ == '__main__':
    setLogLevel('info')
    info('INIZIALIZZO AMBIENTE\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)

