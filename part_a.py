from analysis_pcap_tcp import *
import traceback
from pretty_print import PrettyPrint
from tcp_exceptions import NoTCPTransactions


pcap_file = "assignment2.pcap"

analysis = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file)


num_tcp_flows = len(analysis.tcp_connections)
print(num_tcp_flows)


for connection in analysis.tcp_connections:

    num_transactions_to_print = 5
    try:
        PrettyPrint.print_in_tabular_format(
            dataset = [[packet.seq_num, packet.ack_num, packet.win_size, packet.flags.syn, packet.flags.ack] \
                        for i, packet in enumerate(connection.packets) \
                        if i<num_transactions_to_print],
            headers= ["SEQ #", "ACK #", "WIN-SIZE", "SYN-FLAG", "ACK-FLAG"]
        )
        print()
    except Exception as e:
        track = traceback.format_exc()
        raise NoTCPTransactions()
        