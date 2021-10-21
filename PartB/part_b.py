import os, sys
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from analysis_pcap_tcp import *
from utils import PrettyPrint

current_dir = os.path.dirname(os.path.realpath(__file__))
root_path = os.path.dirname(current_dir)
pcap_file = os.path.join(root_path,"pcap", "assignment2.pcap")
src_ip, dst_ip = "130.245.145.12", "128.208.2.198"

# get analysis components
components = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)
retransmissions = TCPPCapAnalyzer.num_retransmissions(components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
cwnd_sizes = TCPPCapAnalyzer.congestion_window_sizes(components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

table = PrettyPrint.get_tabular_formatted_string(
    dataset = [conn_cwnd_sizes[1:11] for conn_cwnd_sizes in cwnd_sizes],
    headers = ["CW1", "CW2", "CW3", "CW4", "CW5", "CW6", "CW7", "CW8", "CW9", "CW10"],
    serial_num_heading="CONN #",
    table_header="CONGESTION WINDOW SIZES"
)
print(table)

table = PrettyPrint.get_tabular_formatted_string(
    dataset = [
                [retransmissions[i][0], retransmissions[i][1], retransmissions[i][2]] 
                for i in range(len(components.tcp_connections))
            ],
    headers = ["TD ACKS", "TIMEOUT", "TOTAL"],
    serial_num_heading="CONN #",
    table_header="RETRANSMISSIONS"
)
print(table)