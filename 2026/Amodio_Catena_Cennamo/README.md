# SDN Traffic Monitoring & Mitigation con Quarantena (Ryu + Mininet)

Amodio Martina - DE9000018  
Catena Maria - DE9000020  
Cennamo Antonio - DE9000019  


Progetto che implementa, su una rete SDN emulata con **Mininet** e controllata da **Ryu** (OpenFlow 1.3), un sistema di **monitoraggio per corsie (TCP / non-TCP)** e di **mitigazione automatica** del traffico anomalo. Quando un host supera le soglie di banda per un numero di intervalli consecutivi, il controller installa una regola di mitigazione che deve **dirottarlo in quarantena** su un host di ispezione (`h6`), dove viene catturato con `tcpdump` per l'analisi forense.

Il blocco ha una durata limitata (timeout di sblocco) e, dopo lo sblocco, gli host recidivi vengono ribloccati rapidamente.

---

## Indice


1. [Prerequisiti e istruzioni di esecuzione](#2-prerequisiti-e-istruzioni-di-esecuzione)
2. [Configurazione del controller](#3-configurazione-del-controller)
3. [Output e risultati](#4-output-e-risultati)
4. [Verifica delle regole installate](#5-verifica-delle-regole-installate)
5. [Troubleshooting](#6-troubleshooting)

---



## 1. Prerequisiti e istruzioni di esecuzione

### 1.1 Ambiente di esecuzione (Macchina Virtuale)

| Componente | Versione / Valore |
|---|---|
| Sistema operativo | Ubuntu 22.04 LTS |
| Mininet | 2.3.0 |
| Python | 3.10.12 |
| RAM | 4 GB |
| CPU | 3 core |
| Rete della VM | NAT |

### 1.2 Dipendenze software

```bash
sudo apt install vim
sudo apt install git
sudo apt install python3-pip
sudo pip install ryu
```

Per eseguire i test servono inoltre `mininet`, `iperf` e `tcpdump` (normalmente inclusi nell'installazione di Mininet).

### 1.3 Struttura del repository

```
.
├── topologia.py                  # Script Mininet: crea host, switch e link    
├── controller_fase78.py      # Applicazione Ryu: monitoraggio e mitigazione SDN
├── fase9_analisi_confronto.py    # Analisi dei risultati e generazione grafici
├── genera_grafico_html.py        # Generazione del grafico interattivo
├── confronto_fase9_interattivo.html                  # Grafico HTML generato
├── grafico_fase9_confronto.png
├── grafico_fase9_loss.png
├── monitor_mitigation.csv
├── tabella_fase9_confronto.csv
├── Relazione.pdf
├── README.md
├── Topologia.pdf
├── Topologia.png
└── results/                      # Risultati: log iperf host e server, CSV, pcap
```

### 1.4 Istruzioni di esecuzione (Quickstart)

**1. Avviare il controller** (terminale 1):

```bash
ryu-manager controller_fase78.py
```

**2. Avviare la topologia Mininet** (terminale 2):

```bash
sudo python3 topologia.py
```

**3. Aprire i terminali Xterm** degli host necessari dalla CLI Mininet (ad esempio `xterm h1 h2 h6`).

```bash
mininet> xterm h1 h2 h4 h5 h6 h3 h3 h3 h3
```

**4. Avviare il monitoraggio forense su h6** (CLI Mininet):

```bash
mininet> h6 tcpdump -i h6-eth0 -w results/h6_quarantena.pcap &
```

**5. Eseguire il test: avvio server** (CLI Mininet):

```bash
mininet> h3 stdbuf -oL iperf -s -u -p 5001 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h3_udp_server1.txt
```
```bash
mininet> h3 stdbuf -oL iperf -s -p 5002 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h3_tcp_server1.txt
```
```bash
mininet> h3 stdbuf -oL iperf -s -p 5003 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h3_tcp_server2.txt
```
```bash
mininet> h3 stdbuf -oL iperf -s -u -p 5004 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h3_udp_server2.txt
```

**6. Eseguire il test: avvio client** (CLI Mininet):

```bash
mininet> h2 stdbuf -oL iperf -c 10.0.0.3 -p 5002 -b 1M -t 80 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h2.txt
```
```bash
mininet> h4 stdbuf -oL iperf -c 10.0.0.3 -p 5003 -b 1M -t 80 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h4.txt
```
```bash
mininet> h5 stdbuf -oL iperf -c 10.0.0.3 -p 5004 -u -b 2M -t 75 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h5.txt
```
```bash
mininet> h1 stdbuf -oL iperf -c 10.0.0.3 -p 5001 -b 5M -t 36 -i 1 | ts '%.s' | tee results/Fase5_8/fase_8_h1.txt
```


**7. Analizzare i risultati** al termine del test:

```bash
python3 fase9_analisi_confronto.py
```
```bash
python3 genera_grafico_html.py
```

---

## 2. Configurazione del controller

I parametri principali si trovano in cima a `controller_mitigation.py`.

| Parametro | Default | Descrizione |
|---|---|---|
| `THRESHOLD_TCP` / `CONSECUTIVE_TCP` | `625000` / `10` | Soglia (B/s) e intervalli consecutivi per la corsia TCP |
| `THRESHOLD_NON_TCP` / `CONSECUTIVE_NON_TCP` | `200000` / `3` | Soglia (B/s) e intervalli consecutivi per la corsia NON-TCP |
| `BLOCK_HARD_TIMEOUT` | `15` | Durata del blocco/quarantena (s) |
| `FAST_REBLOCK` | `True` | Riblocco rapido dei recidivi dopo lo sblocco |
| `ENABLE_QUARANTINE` | `True` | `True`: dirotta su h6; `False`: drop puro |
| `QUARANTINE_DPID` / `QUARANTINE_PORT` | `1` / `4` | Switch e porta a cui è collegato h6 |
| `WHITELIST` | `{h3, h5, h6}` | Host esenti dalla mitigazione |

### Modalità di mitigazione

**Quarantena** (`ENABLE_QUARANTINE = True`, host su s1): il flusso viene riscritto (`eth_dst` e `ipv4_dst` di h6) e inviato sulla porta di h6.


### Limitazioni note

- La mitigazione della corsia NON-TCP fa match solo su **UDP** (`ip_proto=17`): traffico ICMP o ARP, pur contato nella corsia, non viene bloccato.
- La quarantena è attiva solo per gli host collegati allo switch `QUARANTINE_DPID`.

---

## 3. Output e risultati

- **Console del controller**: tabella per switch con porta, host, corsia, rate, contatore, stato e nota, aggiornata a ogni intervallo; log di allarme, installazione regola e sblocco.
- **`monitor_mitigation.csv`**: serie temporale con le colonne `t_s, dpid, port, host, lane, rx_Bps, rx_Mbps, counter, state, nota`. Stati possibili: `NORMALE`, `ALLARME`, `BLOCCATO`.
- **`results/`**: log `iperf`, CSV e cattura `h6_quarantena.pcap`.
- **`confronto_fase9_interattivo.html`**: grafico generato da `genera_grafico_html.py`.

---

## 4. Verifica delle regole installate

Durante l'esecuzione, per ispezionare le tabelle di flusso di uno switch (ad esempio s1):

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Per vedere solo la Tabella 0:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 table=0
```

Le regole di mitigazione si riconoscono dalla priorità `200` e dal cookie `0x99`.

---

## 5. Troubleshooting

- **Pulizia di Mininet** in caso di errori o interruzioni: `sudo mn -c`
- **Il controller non vede gli switch**: avviare sempre Ryu *prima* di Mininet e verificare che la topologia usi un controller remoto sulla porta `6653`.
- **Errori all'avvio di Ryu su Python 3.10** (ad esempio legati a `eventlet`): in alcuni ambienti serve una versione compatibile di `eventlet` (es. `pip install eventlet==0.30.2`).
- **Permessi sul file pcap**: assicurarsi che la cartella `results/` esista prima di lanciare `tcpdump`.
