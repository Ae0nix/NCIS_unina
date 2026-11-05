# Rilevamento e mitigazione di attacchi flooding in SDN

Progetto per l'esame di **Network and Cloud Infrastructures** — Prof. Giorgio Ventre,
Università degli Studi di Napoli Federico II, A.A. 2025/2026.

Autore: *Giuseppe Guarino* — matricola DE900002

---

## Cosa fa

`controller.py` è un controller Ryu per OpenFlow 1.3 che estende un learning switch con
un monitor delle statistiche di flusso, un rilevatore basato sull'**entropia di Shannon**
degli IP di destinazione e una mitigazione automatica.

In una rete core-edge emulata con Mininet (4 switch, 6 host), il controller legge ogni
5 secondi i contatori delle regole con `OFPFlowStatsRequest` e, su ogni edge switch,
conta **solo il traffico che entra dalla porta trunk** (lato core). In condizioni normali
i pacchetti si distribuiscono su più destinazioni e l'entropia è alta; durante un flood
convergono su un'unica vittima e l'entropia crolla. Quando scende sotto una soglia
dinamica appresa dal traffico sano, il controller segnala l'attacco e installa una regola
di drop sul vettore d'attacco: porta d'ingresso, protocollo e porta L4.

Il match di drop non usa mai l'IP sorgente, quindi la mitigazione resta efficace anche
con indirizzi falsificati (`hping3 --rand-source`). La regola ha `hard_timeout`, quindi
scade da sola dopo 30 secondi.

Il dettaglio delle scelte progettuali, dell'evoluzione del rilevatore e delle misure è
nel report PDF.

## Requisiti

| Componente | Versione usata |
|---|---|
| Sistema | Ubuntu 22.04.5 LTS |
| Python | 3.10 |
| Mininet | 2.3.1b4 |
| Open vSwitch | 2.17.12 |
| Ryu | 4.34 |
| hping3 | dai pacchetti della distribuzione |

Mininet, Open vSwitch e hping3 si installano dai pacchetti della distribuzione;
Ryu con `pip`.

## Installazione

```bash
sudo apt install mininet openvswitch-switch hping3
pip install ryu==4.34
```

All'avvio di `ryu-manager` possono comparire avvisi di eventlet (deprecazione,
`RLock(s) were not greened`): non influiscono sul funzionamento del controller.

## Prova rapida

Il controller va avviato **prima** della rete: se gli switch non trovano nessuno sulla
porta 6653 non completano l'handshake OpenFlow.

**Terminale 1 — controller**

```bash
ryu-manager controller.py
```

Atteso: `instantiating app controller.py of DoSController`, poi una riga
`Switch N connesso. Inizio monitoraggio.` per ciascuno dei 4 switch.

**Terminale 2 — rete e test automatico**

```bash
sudo mn -c                                   # pulizia di eventuali istanze precedenti
sudo python3 topology.py --test all          # TCP, UDP e ICMP in sequenza
```

Lo script esegue `pingAll`, configura la vittima `h1`, avvia per 40 s il traffico sano
di `h6` (UDP/5001 verso `h1` e `h2`) e lancia gli attacchi uno alla volta, separati da
32 s, prima di aprire la CLI di Mininet.

**Cosa cercare nel terminale 1**, in quest'ordine:

```
Switch 2 | Pacchetti Entranti: 200 | Entropia: 1.0000         # warm-up: traffico sano
Soglia in uso (Statica (In apprendimento)): Apprendimento
...
Soglia in uso (Dinamica): 0.7                                 # baseline appresa
Switch 2 | Pacchetti Entranti: 2062 | Entropia: 0.2882        # finestra con il flood
!!! ATTACCO DOS RILEVATO SU SWITCH 2 VERSO 10.0.0.1 !!!
Mitigazione L4: blocco TCP/80 ingresso TRUNK 1 verso 10.0.0.1
Switch 2 | Pacchetti Entranti: 189 | Entropia: 1.0000         # flood bloccato, traffico sano attivo
```

I valori numerici variano fra esecuzioni, la sequenza degli eventi no. Per UDP compare
`blocco UDP/53`, per ICMP `Mitigazione L3: blocco Protocollo 1`. Le finestre del
traffico sano restano intorno a 200 pacchetti con entropia ~1 e non generano allarmi.

Per verificare il contenimento anche sul data plane, entro 30 s dall'attacco:

```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=100
```

La entry con `priority=100` non ha azioni: in OpenFlow il drop è l'assenza di azioni.
Il suo `n_packets` cresce finché dura il flood, mentre la regola con `udp_dst=5001`
(traffico sano di `h6`) continua a contare. Scaduto l'`hard_timeout` la entry sparisce
dalla tabella.

## Opzioni del test

```bash
sudo python3 topology.py --test tcp udp            # solo alcuni attacchi
sudo python3 topology.py --test all --spoofing     # attacchi con IP sorgente casuale
sudo python3 topology.py                           # rete interattiva, nessun attacco
```

| Attacco | Host | Comando |
|---|---|---|
| TCP SYN flood | `h3` (edge `s3`) | `hping3 -S -p 80 -i u1000 -c 10000 10.0.0.1` |
| UDP flood | `h4` (edge `s4`) | `hping3 --udp -p 53 -i u1000 -c 10000 10.0.0.1` |
| ICMP flood | `h5` (edge `s4`) | `hping3 -1 -i u1000 -c 10000 10.0.0.1` |

In modalità interattiva il traffico sano va avviato a mano, e gli attacchi vanno
lanciati solo dopo che la soglia è diventata numerica (circa 30-40 s):

```
mininet> pingall
mininet> h6 hping3 --udp -p 5001 -i u50000 10.0.0.1 < /dev/null > /dev/null 2>&1 &
mininet> h6 hping3 --udp -p 5001 -i u50000 10.0.0.2 < /dev/null > /dev/null 2>&1 &
mininet> h3 hping3 -S -p 80 -i u1000 -c 10000 10.0.0.1 < /dev/null > /dev/null 2>&1 &
mininet> h6 pkill hping3
```

## Log

A ogni avvio il controller crea, nella cartella da cui è lanciato,
`metriche_ddos_<timestamp>.csv` con una riga per edge switch e finestra:

```
Timestamp,Switch_DPID,Pacchetti_In_Trunk,Entropia,Soglia,Attacco
16:42:57,2,200,1.0,0.7,False
16:43:02,2,2062,0.2882,0.7,True
```

`Soglia` vale `Apprendimento` finché la baseline non è pronta. Le righe di `s3` e `s4`
con pochi pacchetti ed entropia 0 sono gli ICMP Port Unreachable inviati a `h6`: restano
sotto la soglia minima di pacchetti e non generano decisioni.

## Struttura

```
controller.py      controller Ryu (inoltro, monitoraggio, rilevamento, mitigazione)
topology.py        topologia Mininet e test automatico
README.md          questo file
pw_report.pdf    relazione
```
