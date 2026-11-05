import threading
import random
import time
from functools import partial
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController #Controller

class Environment(object):
    def __init__(self):
        ovs_of13 = partial(OVSKernelSwitch, protocols='OpenFlow13')
        
        self.net = Mininet(controller=RemoteController, link=TCLink, switch=ovs_of13)
        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6633)
        c1.start()
        
        info("*** Adding switch\n")
        self.switch = self.net.addSwitch('s1', cls=ovs_of13)
        
        info("*** Adding hosts\n")
        hosts = []
        for i in range(1, 6):
            h = self.net.addHost(f'h{i}', mac=f'00:00:00:00:00:0{i}', ip=f'10.0.0.{i}/24')
            hosts.append(h)
        
        info("*** Adding links\n")  
        for h in hosts:
            self.net.addLink(h, self.switch, bw=10, delay='1ms')
        
        info("*** Starting network\n")
        self.net.build()
        self.net.start()

if __name__ == '__main__':
    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)
    env.net.stop()