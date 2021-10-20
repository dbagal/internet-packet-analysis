from analysis_pcap_tcp import *
from analysis_pcap_http import *
from pretty_print import PrettyPrint


pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/assignment2.pcap"

src_ip, dst_ip = "130.245.145.12", "128.208.2.198"
analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)

request_responses = HTTPPCapAnalyzer.reassemble_http_non_pipelined_request_responses(analysis.tcp_connections, src_ip, dst_ip)

for connection_packets in request_responses:
    print("REQUEST:\n")

    request = connection_packets[0]
    src = f"{request.src_ip}:{request.src_port}"
    dst = f"{request.dst_ip}:{request.dst_port}"
    seq = request.seq_num
    ack = request.ack_num

    dataset = ["request", src, dst, seq, ack]
    PrettyPrint.print_in_tabular_format(
        dataset = dataset,
        headers = ["PACKET-TYPE", "SRC", "DST", "SEQ-NUM", "ACK-NUM"]
    )

    print("RESPONSES:\n")
    responses = []
    for i,resps in enumerate(connection_packets[1]):
        src = f"{resps[i].src_ip}:{resps[i].src_port}"
        dst = f"{resps[i].dst_ip}:{resps[i].dst_port}"
        seq = resps[i].seq_num
        ack = resps[i].ack_num
        responses += [["response", src, dst, seq, ack]]

    PrettyPrint.print_in_tabular_format(
        dataset = responses,
        headers = ["PACKET-TYPE", "SRC", "DST", "SEQ-NUM", "ACK-NUM"]
    )