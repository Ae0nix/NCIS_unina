1. Avvia il controller Ryu
Nel terminale del controller:
1     ryu-manager slice_controller.py


2. Avvia Mininet
In un altro terminale:
1     sudo mn --custom topology.py --topo mytopo --controller remote

Verifica:
1     mininet> net

3. Apri le shell degli host
1     mininet> xterm h1 h3
Si apriranno due finestre.

4. Avvia il server VIDEO
Nella finestra di H3:
1     iperf -s -u -p 9999
Lascia la finestra aperta.

5. Genera traffico VIDEO
Nella finestra di H1:
1     iperf -c 10.0.0.3 -u -p 9999 -b 10M -t 30
Questo genera:
1     UDP
2     porta 9999
quindi:
1     is_video = True
e il controller dovrebbe mandarlo sulla slice video (S2).
Attendi che finisca.

6. Avvia il server BEST-EFFORT
Sempre su H3 apri un'altra xterm:
1     mininet> xterm h3
e lancia:
1     iperf -s -p 5001

7. Genera traffico BEST-EFFORT
Su H1 apri un'altra xterm:
1     mininet> xterm h1
e lancia:
1     iperf -c 10.0.0.3 -p 5001 -t 30
Questo genera:
1     TCP
2     porta 5001
quindi:
1     is_video = False
e il controller dovrebbe instradarlo sulla slice best-effort (S3).

8. Controlla le flow installate
Da un terminale Linux esterno a Mininet:
1     sudo ovs-ofctl -O OpenFlow13 dump-flows s1
Dovresti vedere qualcosa di simile:
1     priority=20,udp,tp_dst=9999,...
Questa è la regola per il traffico video.

Controlla anche:
1     sudo ovs-ofctl -O OpenFlow13 dump-flows s2
1     sudo ovs-ofctl -O OpenFlow13 dump-flows s3

9. Cattura con Wireshark
Sulla macchina host:
1     sudo wireshark
Filtri utili:
Per il traffico video:
1     udp.port == 9999
Per il traffico TCP:
1     tcp.port == 5001

