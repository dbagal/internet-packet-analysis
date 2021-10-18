from analysis_pcap_tcp import *
import traceback
from pretty_print import PrettyPrint
from tcp_exceptions import NoTCPTransactions


pcap_file = "assignment2.pcap"

analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file)


#for connection in analysis.tcp_connections:

connection = analysis.tcp_connections[0]
""" num_transactions_to_print = 50
try:
    PrettyPrint.print_in_tabular_format(
        dataset = [[segment.src, segment.dst, segment.seq_num, segment.ack_num, segment.payload_size, segment.win_size, segment.flags.syn, segment.flags.ack] \
                    for i, segment in enumerate(connection.segments) \
                    if i<num_transactions_to_print],
        headers= ["SRC-PORT", "DST-PORT", "SEQ #", "ACK #", "PACKET-SIZE", "WIN-SIZE", "SYN-FLAG", "ACK-FLAG"]
    )
    print()
except Exception as e:
    track = traceback.format_exc()
    raise NoTCPTransactions() """



throughputs = TCPPCapAnalyzer.get_empirical_throughput(connections=analysis.tcp_connections)
loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=analysis.tcp_connections)
rtts = TCPPCapAnalyzer.get_rtt(connections=analysis.tcp_connections)
theoretical_throughputs = TCPPCapAnalyzer.get_theoretical_throughput(connections=analysis.tcp_connections)


# My throughput is just seeing how much data is going through including retransmissions
# calculated one penalises retransmissions

for i in range(len(analysis.tcp_connections)):
    print(f"Connection {i+1}:")
    print(f"- Throughout: {throughputs[i]} MBPS")
    print(f"- Loss rate: {loss_rates[i]}")
    print(f"- RTT: {rtts[i]} seconds")
    print(f"- Calculated throughput: {theoretical_throughputs[i]} MBPS")
    print()