import dpkt
import pickle
from utils import get_string_representation, get_bits, unpack
import os
import base64
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


    def __init__(self, segment_bytes, src_ip, dst_ip, ts):
        """  
        @params:
        - segment_bytes:    ip packet's payload, i.e tcp segment bytes
        - src_ip:           ip of the sender of interest
        - dst_ip:           ip of the receiver of interest
        - ts:               timestamp in the pcap file when the packet was captured
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = int.from_bytes(segment_bytes[0:2], "big", signed=False)
        self.dst_port = int.from_bytes(segment_bytes[2:4], "big", signed=False)
        self.seq_num = int.from_bytes(segment_bytes[4:8], "big", signed=False)
        self.ack_num = int.from_bytes(segment_bytes[8:12], "big", signed=False)
        control_fields = get_bits(segment_bytes[12:14])
        self.data_offset = int("".join([str(x) for x in control_fields[0:4]]), 2)
        self.reserved = int("".join([str(x) for x in control_fields[4:7]]), 2)
        self.flags =  TCPSegment.TCPFlags(control_fields[-9:])
        self.win_size = int.from_bytes(segment_bytes[14:16], "big", signed=False)
        self.checksum = int.from_bytes(segment_bytes[16:18], "big", signed=False)
        self.urgent_ptr = int.from_bytes(segment_bytes[18:20], "big", signed=False)
        self.payload = segment_bytes[20:]
        self.payload_size = len(segment_bytes[20:])
        self.timestamp = float(ts)


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



class TCPPCapAnalyzer:


    class TCPConnection:
        def __init__(self, addr1, addr2) -> None:
            self.addr1 = addr1
            self.addr2 = addr2
            self.segments = []


    class TCPPCapComponents:
            def __init__(self, pcap_file, src_ip, dst_ip) -> None:
                """  
                @params:
                - pcap_file:    path to the pcap file to be analysed
                - src_ip:       ip of the sender of interest
                - dst_ip:       ip of the receiver of interest
                """
                self.tcp_segments = TCPPCapAnalyzer.get_tcp_segments(pcap_file, src_ip, dst_ip)
                self.tcp_connections = TCPPCapAnalyzer.get_tcp_connection_segments(self.tcp_segments)
    

    @staticmethod
    def process_pcap(pcap_file, src_ip, dst_ip):
        """  
        @params:
        - pcap_file:    path to the pcap file to be analysed
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - analysis:     TCPPCapAnalyzer.TCPPCapComponents object containing the components required for analysis
        """
        # to speed up processing, the components required for the analysis are stored in a pickle file
        analysis_components = pcap_file.split(".pcap")[0] + "-analysis.pkl"

        if os.path.exists(analysis_components):
            with open(analysis_components, 'rb') as fp:
                analysis = pickle.load(fp)
        else:
            analysis = TCPPCapAnalyzer.TCPPCapComponents(pcap_file, src_ip, dst_ip)
            with open(analysis_components, 'wb') as fp:
                pickle.dump(analysis, fp)

        return analysis


    @staticmethod
    def get_tcp_connection_segments(tcp_segments):
        """  
        @params:
        - tcp_segments:    list of TCPSegment objects

        @returns:
        - connections:      list of TCPPCapAnalyzer.TCPConnection objects containing the 
                            addresses of the two nodes and the packets sent between them.
        """
        connections = []

        for tcp_segment in tcp_segments:

            # on second handshake, consider the connection to be established and 
            # create and append a TCPConnection object to connections
            if tcp_segment.flags.syn==1 and tcp_segment.flags.ack==1:
                connections += [ TCPPCapAnalyzer.TCPConnection( addr1 = tcp_segment.src_port, 
                                                                addr2 = tcp_segment.dst_port) ]

        # traverse all the segments and populate the 'segments' field in every connection 
        # with the segments having same addresses as in the connection
        for tcp_segment in tcp_segments:
            for i, connection in enumerate(connections):
                connection_addresses = {connection.addr1, connection.addr2}
                packet_addresses = {tcp_segment.src_port, tcp_segment.dst_port}

                if connection_addresses == packet_addresses:
                    connections[i].segments += [tcp_segment]

        return connections


    @staticmethod
    def get_tcp_segments(pcap_file, src_ip, dst_ip):
        """  
        @params:
        - pcap_file:    path to the pcap file to be analysed
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - tcp_segments: list of TCPSegment objects containing the tcp segment from each packet captured in the pcap file
        """
        tcp_segments = []
        pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))

        # traverse every packet captured in the pcap
        for ts, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)

            # consider only TCP/IP packets for analysis
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                packet_src_ip = ".".join([ str(unpack(">B", buf[i:i+1])) for i in range(26,30) ])
                packet_dst_ip = ".".join([ str(unpack(">B", buf[i:i+1])) for i in range(30,34) ])

                if isinstance(ip.data, dpkt.tcp.TCP):
                    if src_ip is not None and dst_ip is not None:
                        
                        # process packets only between nodes having src_ip and dst_ip addresses
                        packet_addresses = {packet_src_ip, packet_dst_ip}
                        analysis_addresses = {src_ip, dst_ip}

                        if packet_addresses==analysis_addresses:
                            tcp_segments += [TCPSegment(segment_bytes=bytes(buf[34:]), src_ip=packet_src_ip, dst_ip=packet_dst_ip, ts=ts)]
                    else:
                        # process any packet without checking the address field
                        tcp_segments += [TCPSegment(segment_bytes=bytes(buf[34:]), src_ip=packet_src_ip, dst_ip=packet_dst_ip, ts=ts)]
                
        return tcp_segments

        
    @staticmethod
    def get_empirical_throughput(connections):
        """  
        @params:
        - connections:      list of TCPPCapAnalyzer.TCPConnection objects containing the 
                            addresses of the two nodes and the packets sent between them.
        
        @returns:
        - empirical_throughputs:    list of floats representing empirical throughputs for each connection
                                    in Megabytes per second
        """
        empirical_throughputs = []
        for connection in connections:

            # sum up the payload size for all segments in the connection
            payload_size = sum([segment.payload_size for segment in connection.segments])

            # record the timestamps
            start_time = connection.segments[0].timestamp 
            end_time = connection.segments[-1].timestamp 
            time_taken = end_time - start_time

            # throughput = total_bytes_sent / time_taken
            throughput = round( (payload_size/1048576)/time_taken , 4 )
            empirical_throughputs += [throughput]

        return empirical_throughputs

    
    @staticmethod
    def get_theoretical_throughput(connections, src_ip, dst_ip):
        """  
        @params:
        - connections:  list of TCPPCapAnalyzer.TCPConnection objects containing the 
                        addresses of the two nodes and the packets sent between them.
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - theoretical_throughputs:    list of floats representing theoretical throughputs for each connection in Megabytes per second
        """
        loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=connections, src_ip=src_ip, dst_ip=dst_ip)
        rtts = TCPPCapAnalyzer.get_rtt(connections=connections)
        
        return  [
                    round((1.31 * (1460/1048576))/(rtt/1000 * loss_rate**0.5),4) 
                    for rtt,loss_rate in zip(rtts,loss_rates)
                ]


    @staticmethod   
    def get_loss_rate(connections, src_ip, dst_ip):
        """  
        @params:
        - connections:  list of TCPPCapAnalyzer.TCPConnection objects containing the 
                        addresses of the two nodes and the packets sent between them.
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - loss_rates:    list of floats representing loss rate for each connection
        """
        loss_rates=[]
        for connection in connections:
            
            # count number of transmissions for every segment indexed by seq_num
            num_transmissions = {seq_num:count for seq_num, count in \
                                Counter(
                                        [   segment.seq_num 
                                            for segment in connection.segments
                                            if segment.src_ip == src_ip and segment.dst_ip == dst_ip
                                        ]
                                    ).items()}
            
            # # of segments lost is same as # of retransmissions
            segments_lost = sum([num_transmitted-1 for num_transmitted in num_transmissions.values()])

            loss_rate = round( segments_lost*1.0/len(connection.segments), 4 )
            loss_rates += [loss_rate]
        
        return loss_rates


    @staticmethod
    def get_rtt(connections):
        """  
        @params:
        - connections:  list of TCPPCapAnalyzer.TCPConnection objects containing the 
                        addresses of the two nodes and the packets sent between them.

        @returns:
        - rtts:         list of floats representing avg rtt for each connection
        """
        rtts = []
        for connection in connections:

            avg_rtt = 0
            alpha = 0.0125

            seq_indexed_segments = defaultdict(list)
            ack_indexed_segments = defaultdict(list)

            for segment in connection.segments:
                seq_indexed_segments[segment.seq_num] += [segment.timestamp]
                ack_indexed_segments[segment.ack_num] += [segment.timestamp]

            for segment in connection.segments:
                ack_num = segment.ack_num

                # for every unique ack number, find a unique seq number which is same as the ack number
                req_sent_ts = seq_indexed_segments.get(ack_num-1, None)
                response_received_ts = ack_indexed_segments.get(ack_num, None)

                # according to karne's algorithm don't sample rtt for retransmissions 
                if req_sent_ts is not None and response_received_ts is not None and \
                    len(req_sent_ts)==1 and len(response_received_ts)==1:

                    # take the weighted average for rtt estimation
                    rtt_sample = abs(response_received_ts[0] - req_sent_ts[0])
                    avg_rtt = (1-alpha)*avg_rtt + alpha*rtt_sample

            rtts += [round(avg_rtt*1000, 4)]

        return rtts

    
    @staticmethod
    def congestion_window_sizes(connections, src_ip, dst_ip):
        """  
        @params:
        - connections:  list of TCPPCapAnalyzer.TCPConnection objects containing the 
                        addresses of the two nodes and the packets sent between them.
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - cwnd_sizes_for_connections:   list of list of ints representing congestion   
                                        window sizes for each connection
        """
        cwnd_sizes_for_connections = []
        for connection in connections:
            cwnd_sizes = []
            latest_seq_num_sent = None

            for segment in connection.segments:
                # congestion window is the amount of data the TCP can send into the network 
                # before receiving an ACK
                if segment.src_ip == src_ip and segment.dst_ip == dst_ip:
                    latest_seq_num_sent = segment.seq_num

                # on receiving an acknowledgement from the receiver 'cwnd_size' is calculated as 
                # number of unacknowledged bytes
                elif segment.dst_ip == src_ip and segment.dst_ip == src_ip and latest_seq_num_sent is not None:
                    cwnd_size = latest_seq_num_sent - segment.ack_num
                    cwnd_sizes += [cwnd_size]
            
            cwnd_sizes_for_connections += [cwnd_sizes]
        return cwnd_sizes_for_connections

    
    @staticmethod
    def num_retransmissions(connections, src_ip, dst_ip):
        """  
        @params:
        - connections:  list of TCPPCapAnalyzer.TCPConnection objects containing the 
                        addresses of the two nodes and the packets sent between them.
        - src_ip:       ip of the sender of interest
        - dst_ip:       ip of the receiver of interest

        @returns:
        - retransmissions:  list containing tuples (retransmits_due_to_triple_dup_ack, 
                            retransmits_due_to_timeout, total_retransmissions)
        """
        retransmissions = []
        for connection in connections:
            
            # packets with ack flag set should come from server
            # hence src_ip should be server's ip and dst_ip should be client's ip
            transmissions_for_acks = {ack_num:count 
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
            for ack_num in transmissions_for_acks.keys():
                retransmits_due_to_triple_dup_ack += retransmissions_for_seq_num.get(ack_num,0)
            
            # retransmissions can be only due to timeout or triple dup acks
            retransmits_due_to_timeout = total_retransmissions - retransmits_due_to_triple_dup_ack
            retransmissions += [(retransmits_due_to_triple_dup_ack, retransmits_due_to_timeout, total_retransmissions)]
        
        return retransmissions