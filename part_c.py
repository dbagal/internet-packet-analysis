from analysis_pcap_tcp import *
from analysis_pcap_http import *
from pretty_print import PrettyPrint


pcap_files = [
    "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/http_1080.pcap",
    "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/tcp_1081.pcap",
    "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/tcp_1082.pcap"
]

analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_files[0], src_ip=None, dst_ip=None)

request_responses = HTTPPCapAnalyzer.reassemble_http_non_pipelined_request_responses(analysis.tcp_connections)

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
        
        PrettyPrint.print_in_tabular_format(
            dataset = dataset,
            headers = ["PACKET-TYPE", "SRC", "DST", "SEQ-NUM", "ACK-NUM"],
            table_header = f"CONNECTION {i+1}"
        )
