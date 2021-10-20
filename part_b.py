from analysis_pcap_tcp import *


pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/assignment2.pcap"

src_ip, dst_ip = "130.245.145.12", "128.208.2.198"
analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)


retransmissions = TCPPCapAnalyzer.num_retransmissions(analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
cwnd_sizes = TCPPCapAnalyzer.congestion_window_sizes(analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

for i,conn_cwnd_sizes in enumerate(cwnd_sizes):
    print(f"Connection {i+1}:")
    [print(x) for x in conn_cwnd_sizes[1:11]]


for i in range(len(analysis.tcp_connections)):

    print(f"Connection {i+1}:")
    print(f"Total # of retransmissions: {retransmissions[i][-1]}")
    print(f"# retransmissions due to triple dup acks: {retransmissions[i][0]}")
    print(f"# retransmissions due to timeout: {retransmissions[i][1]}")

# sudo tcpdump -s 0 -v host 34.193.77.105 -w /Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/http_1080.pcap