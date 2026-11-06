FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Installa Mininet, Open vSwitch, strumenti di rete e pip
RUN apt-get update && apt-get install -y \
    mininet \
    openvswitch-switch \
    python3-pip \
    net-tools \
    iputils-ping \
    iperf \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Installa Ryu e la versione compatibile di eventlet
RUN pip3 install ryu eventlet==0.30.2 mininet

WORKDIR /workspace

# Copia lo script di avvio e impostalo come punto d'ingresso
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]