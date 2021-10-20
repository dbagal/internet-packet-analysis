import dpkt
import pickle
from utils import get_string_representation, get_bits
import os
import base64
import socket
from collections import defaultdict, Counter

class TCPSegment:

    class TCPFlags:
        def __init__(self, flags) -> None:

            self.ns = flags[0]
            self.cwr = flags[1]
            self.ece = flags[2]
            self.urg = flags[3]
            self.ack = flags[4]
            self.psh = flags[5]
            self.rst = flags[6]
            self.syn = flags[7]
            self.fin = flags[8]

        def __str__(self) -> str:
            flags = [
                f"TCP segment FLAGS",
                f"- ns: {self.ns}",
                f"- cwr: {self.cwr}",
                f"- ece: {self.ece}",
                f"- urg: {self.urg}",
                f"- ack: {self.ack}",
                f"- psh: {self.psh}",
                f"- rst: {self.rst}",
                f"- syn: {self.syn}",
                f"- fin: {self.fin}",
            ]
            return get_string_representation(flags)


    def __init__(self, segment, src_ip, dst_ip, ts):
        self.process_segment(segment, src_ip, dst_ip, ts)


    def __str__(self):
        segment_contents = [
            f"TCP SEGMENT",
            f"src-ip: {self.src_ip}",
            f"dest-ip: {self.dst_ip}",
            f"src-port: {self.src_port}",
            f"dest-port: {self.dst_port}",
            f"sequence-num: {self.seq_num}",
            f"ack: {self.ack_num}",
            f"data-offset: {self.data_offset}",
            f"reserved: {self.reserved}",
            f"flags:",
            f"- ns: {self.flags.ns}",
            f"- cwr: {self.flags.cwr}",
            f"- ece: {self.flags.ece}",
            f"- urg: {self.flags.urg}",
            f"- ack: {self.flags.ack}",
            f"- psh: {self.flags.psh}",
            f"- rst: {self.flags.rst}",
            f"- syn: {self.flags.syn}",
            f"- fin: {self.flags.fin}",
            f"window-size: {self.win_size} bytes",
            f"checksum: {self.checksum}",
            f"urgent-ptr: {self.urgent_ptr}",
            f"payload-size: {self.payload_size} bytes",
            f"timestamp: {self.timestamp}",
            f"base64-encoded-payload: {base64.b64encode(self.payload).decode()}"
        ]
        return get_string_representation(segment_contents)


    def process_segment(self, segment_bytes, src_ip, dst_ip, ts):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = int.from_bytes(segment_bytes[0:2], "big", signed=False)
        self.dst_port = int.from_bytes(segment_bytes[2:4], "big", signed=False)
        self.seq_num = int.from_bytes(segment_bytes[4:8], "big", signed=False)
        self.ack_num = int.from_bytes(segment_bytes[8:12], "big", signed=False)
        data_offset_and_reserved_and_flags = get_bits(segment_bytes[12:14])
        self.data_offset = int("".join([str(x) for x in data_offset_and_reserved_and_flags[0:4]]), 2)
        self.reserved = int("".join([str(x) for x in data_offset_and_reserved_and_flags[4:7]]), 2)
        
        flags = data_offset_and_reserved_and_flags[-9:]
        self.flags =  TCPSegment.TCPFlags(flags)

        self.win_size = int.from_bytes(segment_bytes[14:16], "big", signed=False)
        self.checksum = int.from_bytes(segment_bytes[16:18], "big", signed=False)
        self.urgent_ptr = int.from_bytes(segment_bytes[18:20], "big", signed=False)
        self.payload = segment_bytes[60:]
        self.payload_size = len(segment_bytes[60:])
        self.timestamp = float(ts)



class TCPPCapAnalyzer:


    class TCPConnection:

        def __init__(self, addr1, addr2) -> None:
            self.addr1 = addr1
            self.addr2 = addr2
            self.segments = []
    


    class TCPPCapComponents:

        def __init__(self, pcap_file, src_ip, dst_ip) -> None:
            self.tcp_segments = TCPPCapAnalyzer.get_tcp_segments(pcap_file, src_ip, dst_ip)
            self.tcp_connections = TCPPCapAnalyzer.get_tcp_connection_segments(self.tcp_segments)



    @staticmethod
    def process_pcap(pcap_file, src_ip, dst_ip):
        analysis_file = pcap_file.split(".pcap")[0] + "-analysis.pkl"

        if os.path.exists(analysis_file) and False:
            with open(analysis_file, 'rb') as fp:
                analysis = pickle.load(fp)
        else:
            analysis = TCPPCapAnalyzer.TCPPCapComponents(pcap_file, src_ip, dst_ip)
            with open(analysis_file, 'wb') as fp:
                pickle.dump(analysis, fp)

        return analysis


    @staticmethod
    def get_tcp_connection_segments(tcp_segments):
        connections = []

        for tcp_segment in tcp_segments:
            if tcp_segment.flags.syn==1 and tcp_segment.flags.ack==1:
                connections += [ TCPPCapAnalyzer.TCPConnection( addr1 = tcp_segment.src_port, 
                                                                addr2 = tcp_segment.dst_port) ]

        for tcp_segment in tcp_segments:
            for i, connection in enumerate(connections):
                connection_addresses = {connection.addr1, connection.addr2}
                packet_addresses = {tcp_segment.src_port, tcp_segment.dst_port}

                if connection_addresses == packet_addresses:
                    connections[i].segments += [tcp_segment]

        return connections


    @staticmethod
    def get_tcp_segments(pcap_file, src_ip, dst_ip):
        tcp_segments = []
        pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                packet_src_ip, packet_dst_ip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                packet_addresses = {packet_src_ip, packet_dst_ip}
                analysis_addresses = {src_ip, dst_ip}
                
                if isinstance(ip.data, dpkt.tcp.TCP) and packet_addresses==analysis_addresses:
                    tcp_segments += [TCPSegment(segment=bytes(ip.data), src_ip=packet_src_ip, dst_ip=packet_dst_ip, ts=ts)]
        
        return tcp_segments

        
    @staticmethod
    def get_empirical_throughput(connections):
        throughputs = []
        for connection in connections:
            payload_size = sum([segment.payload_size for segment in connection.segments])

            start_time = min([float(transaction_segment.timestamp) for transaction_segment in connection.segments])
            end_time = max([float(transaction_segment.timestamp) for transaction_segment in connection.segments])
            
            time_taken = end_time - start_time
            throughput = round( (payload_size/1048576)/time_taken , 4 )
            throughputs += [throughput]

        return throughputs

    
    @staticmethod
    def get_num_tcp_flows(connections):
        return len(connections)


    @staticmethod
    def get_theoretical_throughput(connections, src_ip, dst_ip):
        def theoretical_throughput(rtt, loss_rate):
            return round((1.31 * (1460/1048576))/(rtt * loss_rate**0.5),4)

        loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=connections, src_ip=src_ip, dst_ip=dst_ip)
        rtts = TCPPCapAnalyzer.get_rtt(connections=connections)

        throughputs = [theoretical_throughput(rtt, loss_rate) for rtt,loss_rate in zip(rtts,loss_rates)]
        
        return throughputs


    @staticmethod   
    def get_loss_rate(connections, src_ip, dst_ip):
        loss_rates=[]
        for connection in connections:

            num_transmissions = {seq_num:count for seq_num, count in \
                                Counter(
                                        [   segment.seq_num 
                                            for segment in connection.segments
                                            if segment.src_ip == src_ip and segment.dst_ip == dst_ip
                                        ]
                                    ).items()}
            
            segments_lost = sum([num_transmitted-1 for num_transmitted in num_transmissions.values()])

            loss_rate = round( segments_lost*1.0/len(connection.segments), 4 )
            loss_rates += [loss_rate]
        
        return loss_rates


    @staticmethod
    def get_rtt(connections):
        rtts = []
        for connection in connections:

            avg_rtt = 0
            alpha = 0.05

            seq_indexed_segments = defaultdict(list)
            ack_indexed_segments = defaultdict(list)

            for segment in connection.segments:
                seq_indexed_segments[segment.seq_num] += [segment.timestamp]
                ack_indexed_segments[segment.ack_num] += [segment.timestamp]

            for segment in connection.segments:
                ack_num = segment.ack_num

                # for every unique ack number, find a unique seq number which is same as the ack number
                ts1_list = seq_indexed_segments.get(ack_num, None)
                ts2_list = ack_indexed_segments.get(ack_num, None)

                # don't sample rtt for retransmissions
                if ts1_list is not None and ts2_list is not None and \
                    len(ts1_list)==1 and len(ts2_list)==1:
                    rtt_sample = abs(ts1_list[0] - ts2_list[0])
                    avg_rtt = (1-alpha)*avg_rtt + alpha*rtt_sample

            rtts += [round(avg_rtt, 4)]

        return rtts

    
    @staticmethod
    def congestion_window_sizes(connections, src_ip, dst_ip):
        cwnd_sizes_for_connections = []
        for connection in connections:
            cwnd_sizes = []
            latest_seq_num_sent = None
            for segment in connection.segments:
                # congestion window is the amount of data the TCP can send into the network 
                # before receiving an ACK
                if segment.src_ip == src_ip and segment.dst_ip == dst_ip:
                    latest_seq_num_sent = segment.seq_num
                elif segment.dst_ip == src_ip and segment.dst_ip == src_ip and latest_seq_num_sent is not None:
                    cwnd_size = latest_seq_num_sent - segment.ack_num
                    cwnd_sizes += [cwnd_size]
            
            cwnd_sizes_for_connections += [cwnd_sizes]
        return cwnd_sizes_for_connections

    
    @staticmethod
    def num_retransmissions(connections, src_ip, dst_ip):

        retransmissions = []
        for connection in connections:
            
            # packets with ack flag set should come from server
            # hence src_ip should be server's ip and dst_ip should be client's ip
            transmissions_for_ack_num = {ack_num:count 
                                            for ack_num, count in 
                                            Counter([
                                                        segment.ack_num 
                                                        for segment in connection.segments
                                                        if segment.src_ip == dst_ip and segment.dst_ip == src_ip
                                                    ]).items() 
                                            if count>=3}

            retransmissions_for_seq_num = {seq_num:count-1 
                                            for seq_num, count in 
                                            Counter([
                                                        segment.seq_num 
                                                        for segment in connection.segments
                                                        if segment.src_ip == src_ip and segment.dst_ip == dst_ip
                                                    ]).items()
                                        }

            
            total_retransmissions = sum([num_transmitted for num_transmitted in retransmissions_for_seq_num.values()])
            
            retransmits_due_to_triple_dup_ack = 0
            for ack_num in transmissions_for_ack_num.keys():
                retransmits_due_to_triple_dup_ack += retransmissions_for_seq_num.get(ack_num,0)
            
            retransmits_due_to_timeout = total_retransmissions - retransmits_due_to_triple_dup_ack
            retransmissions += [(retransmits_due_to_triple_dup_ack, retransmits_due_to_timeout, total_retransmissions)]
        
        return retransmissions
            
            