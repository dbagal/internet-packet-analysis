import os, sys
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from analysis_pcap_tcp import *
from analysis_pcap_http import *
from utils import PrettyPrint

# cd tcp-packet-analysis/
# sudo tcpdump -n port 1080 -w http_1080.pcap
# sudo tcpdump -n port 1081 -w tcp_1081.pcap
# sudo tcpdump -n port 1082 -w tcp_1082.pcap

current_dir = os.path.dirname(os.path.realpath(__file__))
root_path = os.path.dirname(current_dir)
pcap_files = [
    os.path.join(root_path, "pcap", "http_1080.pcap"),
    os.path.join(root_path, "pcap", "tcp_1081.pcap"),
    os.path.join(root_path, "pcap", "tcp_1082.pcap")
]

# get analysis component for the first file
http_1_analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_files[0], src_ip=None, dst_ip=None)

# get request and responses for http 1.0 file 
request_responses = HTTPPCapAnalyzer.reassemble_http_non_pipelined_request_responses(http_1_analysis.tcp_connections)

for i,connection in enumerate(request_responses):
    
    for connection_packets in connection:
        request = connection_packets[0]
        src = f"{request.src_ip}:{request.src_port}"
        dst = f"{request.dst_ip}:{request.dst_port}"
        seq = request.seq_num
        ack = request.ack_num

        dataset = [["request", src, dst, seq, ack]]

        responses = connection_packets[1]
        for response in responses:
            src = f"{response.src_ip}:{response.src_port}"
            dst = f"{response.dst_ip}:{response.dst_port}"
            seq = response.seq_num
            ack = response.ack_num
            dataset += [["response", src, dst, seq, ack]]
        
        table = PrettyPrint.get_tabular_formatted_string(
            dataset = dataset,
            headers = ["PACKET-TYPE", "SRC", "DST", "SEQ-NUM", "ACK-NUM"],
            table_header = f"CONN {i+1}"
        )
        print(table)

# since http 1.1 and 2.0 encrypts the packets, HTTPPCapAnalyzer.reassemble_http_non_pipelined_request_responses 
# returns an empty list as it is not able to parse the encrypted packet
# therefore, we count the number of connections to determine the http version programmatically
http_1_1_analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_files[1], src_ip=None, dst_ip=None)
http_2_analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_files[2], src_ip=None, dst_ip=None)


num_connections_http_1 = len(http_1_analysis.tcp_connections)
num_connections_http_1_1 = len(http_1_1_analysis.tcp_connections)
num_connections_http_2 = len(http_2_analysis.tcp_connections)

num_packets_http_1 = len(http_1_analysis.tcp_segments)
num_packets_http_1_1 = len(http_1_1_analysis.tcp_segments)
num_packets_http_2 = len(http_2_analysis.tcp_segments)

time_http_1 = round(http_1_analysis.tcp_segments[-1].timestamp - http_1_analysis.tcp_segments[0].timestamp, 4)
time_http_1_1 = round(http_1_1_analysis.tcp_segments[-1].timestamp - http_1_1_analysis.tcp_segments[0].timestamp, 4)
time_http_2 = round(http_2_analysis.tcp_segments[-1].timestamp - http_2_analysis.tcp_segments[0].timestamp, 4)

print(http_1_analysis.tcp_segments[-1])
print(http_1_analysis.tcp_segments[0])

dataset = [
    ["HTTP 1.0", num_connections_http_1, num_packets_http_1, str(time_http_1)+" ms"],
    ["HTTP 1.1", num_connections_http_1_1, num_packets_http_1_1, str(time_http_1_1)+" ms"],
    ["HTTP 2", num_connections_http_2, num_packets_http_2, str(time_http_2)+" ms"],
]

table = PrettyPrint.get_tabular_formatted_string(
    dataset = dataset,
    headers = ["HTTP-VERSION", "# CONNECTIONS", "# PACKETS SENT", "TIME TAKEN"],
    table_header = f"HTTP VERSION ANALYSIS",
    include_serial_numbers=False
)
print(table)
