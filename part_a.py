from analysis_pcap_tcp import *
import traceback
from pretty_print import PrettyPrint
from tcp_exceptions import NoTCPTransactions


pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/assignment2.pcap"
src_ip, dst_ip = "130.245.145.12", "128.208.2.198"

# get analysis components
components = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)

# print transactions after tcp setup for each connection
for connection in components.tcp_connections:

    num_transactions_to_print = 5
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


empirical_throughputs = TCPPCapAnalyzer.get_empirical_throughput(connections=components.tcp_connections)
loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
rtts = TCPPCapAnalyzer.get_rtt(connections=components.tcp_connections)
theoretical_throughputs = TCPPCapAnalyzer.get_theoretical_throughput(connections=components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

# My throughput is just seeing how much data is going through including retransmissions
# calculated one penalises retransmissions

PrettyPrint.print_in_tabular_format(
    dataset=[
                [empirical_throughputs[i], theoretical_throughputs[i], loss_rates[i], rtts[i]]
                for i in range(len(components.tcp_connections))
            ],
    headers = ["Empirical throughput (MBPS)", "Theoretical throughput (MBPS)", "Loss rate", "Avg RTT (ms)"],
    serial_num_heading = "Connection #",
    table_header="TCP FLOW ANALYSIS"
)
