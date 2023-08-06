for d in */ ; do
	for f in $d*.pcap ; do
		
		echo -e  "Sto analizzando il file -> $f"
		echo -e " "
		
		#capinfos	
		capinfos -A -B $f >> ./"$f"_capinfos.csv
		echo "Panoramica generale informazioni catture con Capinfos effettuata"
		
		#estrazione dei biflussi TCP e UDP
		tshark -r $f -q -z conv,udp >> "$f"_udp_biflussi.csv
		echo "Estrazione Biflussi UDP effettuata"
	 	tshark -r $f -q -z conv,tcp >> "$f"_tcp_biflussi.csv
		echo "Estrazione Biflussi TCP effettuata"
		
		#DNS
	 	tshark -r $f -T fields -e frame.time_epoch -e frame.protocols -e ip.src -e ip.dst -e ip.proto -e udp.srcport -e udp.dstport -e dns.a -e dns.qry.name -Y "(dns.flags.response == 1 )" >> ./"$f"_dns.csv
		echo "Stampa delle risoluzioni DNS effettuata"

		
		#SNI TLS
		tshark -r $f -T fields -e frame.time_epoch -e frame.protocols -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tls.handshake.extensions_server_name tls.handshake.type == 1  >> "$f"_tls.csv
		echo "Analisi TLS effettuata"
		
	
		#HTTP
		tshark -r $f -T fields -e frame.time_epoch -e frame.protocols -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e http.host -Y "http.host" >> ./"$f"_host_HTTP.csv
		echo -e "HTTP fatto"
		
	done
done
