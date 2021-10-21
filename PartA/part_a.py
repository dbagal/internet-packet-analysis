import os, sys
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from analysis_pcap_tcp import *
import traceback
from utils import PrettyPrint

current_dir = os.path.dirname(os.path.realpath(__file__))
root_path = os.path.dirname(current_dir)
pcap_file = os.path.join(root_path, "pcap", "assignment2.pcap")
src_ip, dst_ip = "130.245.145.12", "128.208.2.198"

# get analysis components
components = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)

# print transactions after tcp setup for each connection
for i, connection in enumerate(components.tcp_connections):

    num_transactions_to_print = 5
    try:
        table = PrettyPrint.get_tabular_formatted_string(
            dataset = [[ segment.seq_num, segment.ack_num, segment.win_size] \
                        for i, segment in enumerate(connection.segments) \
                        if i<num_transactions_to_print],
            headers= [ "SEQ #", "ACK #", "WIN-SIZE"],
            table_header= f"CONNECTION {i+1}"
        )
        print(table)
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

table = PrettyPrint.get_tabular_formatted_string(
    dataset=[
                [empirical_throughputs[i], theoretical_throughputs[i], loss_rates[i], rtts[i]]
                for i in range(len(components.tcp_connections))
            ],
    headers = ["EMP THROUGHPUT (MBPS)", "THROUGHPUT (MBPS)", "LOSS RATE", "AVG RTT (MS)"],
    serial_num_heading = "CONN #",
    table_header="TCP FLOW ANALYSIS"
)
print(table)

