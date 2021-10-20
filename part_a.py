from analysis_pcap_tcp import *
import traceback
from pretty_print import PrettyPrint
from tcp_exceptions import NoTCPTransactions


pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/assignment2.pcap"

src_ip, dst_ip = "130.245.145.12", "128.208.2.198"
analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)


for connection in analysis.tcp_connections:

    num_transactions_to_print = 10
    try:
        PrettyPrint.print_in_tabular_format(
            dataset = [[segment.src_ip, segment.dst_ip, segment.seq_num, segment.ack_num, segment.payload_size, segment.win_size, segment.flags.syn, segment.flags.ack] \
                        for i, segment in enumerate(connection.segments) \
                        if i<num_transactions_to_print],
            headers= ["SENDER", "RECEIVER", "SEQ #", "ACK #", "PACKET-SIZE", "WIN-SIZE", "SYN-FLAG", "ACK-FLAG"]
        )
        print()
    except Exception as e:
        track = traceback.format_exc()
        raise NoTCPTransactions()



throughputs = TCPPCapAnalyzer.get_empirical_throughput(connections=analysis.tcp_connections)
loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
rtts = TCPPCapAnalyzer.get_rtt(connections=analysis.tcp_connections)
theoretical_throughputs = TCPPCapAnalyzer.get_theoretical_throughput(connections=analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

# My throughput is just seeing how much data is going through including retransmissions
# calculated one penalises retransmissions

for i in range(len(analysis.tcp_connections)):
    print(f"Connection {i+1}:")
    print(f"- Throughput: {throughputs[i]} MBPS")
    print(f"- Loss rate: {loss_rates[i]}")
    print(f"- RTT: {rtts[i]} seconds")
    print(f"- Calculated throughput: {theoretical_throughputs[i]} MBPS")
    print()

# sudo tcpdump -s 0 -v host 34.193.77.105 -w /Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/http_1080.pcap