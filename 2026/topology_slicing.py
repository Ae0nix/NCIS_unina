from mininet.topo import Topo

class CustomDoSAndSlicingTopo(Topo):
    def build(self):
        # Aggiunta di 3 switch OpenFlow
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Aggiunta di 4 host distribuiti sui vari switch
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        # Connessioni tra gli switch (con link ridondante per testare l'STP e il Failover)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s1, s3) 

        # Connessione degli host agli switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s3)

topos = { 'slicingtopo': (lambda: CustomDoSAndSlicingTopo()) }