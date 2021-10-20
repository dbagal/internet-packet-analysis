from analysis_pcap_tcp import *
from pretty_print import PrettyPrint


pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/assignment2.pcap"

src_ip, dst_ip = "130.245.145.12", "128.208.2.198"
analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)


retransmissions = TCPPCapAnalyzer.num_retransmissions(analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
cwnd_sizes = TCPPCapAnalyzer.congestion_window_sizes(analysis.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)


PrettyPrint.print_in_tabular_format(
    dataset = [conn_cwnd_sizes[1:11] for conn_cwnd_sizes in cwnd_sizes],
    headers = ["CWND-1", "CWND-2", "CWND-3", "CWND-4", "CWND-5", "CWND-6", "CWND-7", "CWND-8", "CWND-9", "CWND-10"],
    serial_num_heading="Connection #",
    table_header="CONGESTION WINDOW SIZES"
)

PrettyPrint.print_in_tabular_format(
    dataset = [
                [retransmissions[i][0], retransmissions[i][1], retransmissions[i][2]] 
                for i in range(len(analysis.tcp_connections))
            ],
    headers = ["triple dup acks", "timeout", "total"],
    serial_num_heading="Connection #",
    table_header="RETRANSMISSIONS"
)

# sudo tcpdump -s 0 -v host 34.193.77.105 -w /Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/http_1080.pcap