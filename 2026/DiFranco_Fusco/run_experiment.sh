#!/usr/bin/env bash
set -e

cd ~/progetto_ncis

echo "=== [1/4] Pulizia preliminare di Mininet e Open vSwitch ==="
sudo mn -c >/dev/null 2>&1

echo "=== [2/4] Avvio del Controller Ryu in background ==="
source ~/progetto_ncis/ryu-venv/bin/activate
ryu-manager controller_dos.py > ryu.log 2>&1 &
RYU_PID=$!

# Mostra in diretta i log importanti del controller mentre gira
tail -f ryu.log | grep --line-buffered -E "SWITCH CONNESSO|EDGE DISCOVERY|OPENFLOW METER|ANOMALIA|ESCALATION|AUTO-HEALING|RIPRISTINO" &
TAIL_PID=$!

sleep 3

echo "=== [3/4] Avvio Topologia Mininet e Simulazione Automatica ==="
sudo python3 topology.py --autotest

echo "=== [4/4] Arresto Controller e Generazione Grafici ==="
kill $TAIL_PID 2>/dev/null || true
kill $RYU_PID 2>/dev/null || true
wait $RYU_PID 2>/dev/null || true

python3 plot_results.py
echo "=== ESPERIMENTO COMPLETATO CON SUCCESSO! ==="
