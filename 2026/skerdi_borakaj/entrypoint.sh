#!/bin/bash

# Inizializza e avvia Open vSwitch in modalità user-space se non è attivo
mkdir -p /var/run/openvswitch
mkdir -p /etc/openvswitch

if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Avvia i demoni di OVS
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --detach
ovs-vswitchd --pidfile --detach

# Mantiene il container aperto eseguendo bash (o il comando passato)
exec "$@"