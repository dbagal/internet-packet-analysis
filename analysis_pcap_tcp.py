import dpkt
import pickle
from utils import get_string_representation
import os

class TCPHeader:

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
                f"TCP PACKET FLAGS",
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


    def __init__(self, packet):
        self.process_packet(packet)


    def get_bits(self, bytes, byteorder="big"):
        bits = []
        if byteorder=="big":
            bit_indices = range(7,-1,-1)
        elif byteorder=="little":
            bit_indices = range(0,8)

        for byte in bytes:
            bits += [(byte>>i)&1 for i in bit_indices]

        return bits


    def __str__(self):
        packet_contents = [
            f"TCP PACKET",
            f"src-port: {self.src}",
            f"dest-port: {self.dst}",
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
            f"urgent-ptr: {self.urgent_ptr}"
        ]
        return get_string_representation(packet_contents)


    def process_packet(self, packet_bytes):
        self.src = int.from_bytes(packet_bytes[0:2], "big", signed=False)
        self.dst = int.from_bytes(packet_bytes[2:4], "big", signed=False)
        self.seq_num = int.from_bytes(packet_bytes[4:8], "big", signed=False)
        self.ack_num = int.from_bytes(packet_bytes[8:12], "big", signed=False)
        data_offset_and_reserved_and_flags = self.get_bits(packet_bytes[12:14])
        self.data_offset = int("".join([str(x) for x in data_offset_and_reserved_and_flags[0:4]]), 2)
        self.reserved = int("".join([str(x) for x in data_offset_and_reserved_and_flags[4:7]]), 2)
        
        flags = data_offset_and_reserved_and_flags[-9:]
        self.flags =  TCPHeader.TCPFlags(flags)

        self.win_size = int.from_bytes(packet_bytes[14:16], "big", signed=False)
        self.checksum = int.from_bytes(packet_bytes[16:18], "big", signed=False)
        self.urgent_ptr = int.from_bytes(packet_bytes[18:20], "big", signed=False)



        

class TCPPCapAnalyzer:


    class TCPConnection:

        def __init__(self, sender, receiver) -> None:
            self.sender = sender
            self.receiver = receiver
            self.packets = []

        def add_transaction_packet_header(self, packet):
            self.packets += [packet]
    


    class TCPPCapComponents:

        def __init__(self, pcap_file) -> None:
            self.tcp_segments = TCPPCapAnalyzer.get_tcp_segments(pcap_file)
            self.tcp_packet_headers = TCPPCapAnalyzer.get_tcp_packet_headers(self.tcp_segments)
            self.tcp_connections = TCPPCapAnalyzer.get_tcp_connection_packet_headers(self.tcp_packet_headers)



    @staticmethod
    def process_pcap(pcap_file):
        analysis_file = pcap_file.split(".pcap")[0] + "-analysis.pkl"

        if os.path.exists(analysis_file):
            with open(analysis_file, 'rb') as fp:
                analysis = pickle.load(fp)
        else:
            analysis = TCPPCapAnalyzer.TCPPCapComponents(pcap_file)
            with open(analysis_file, 'wb') as fp:
                pickle.dump(analysis, fp)

        return analysis


    @staticmethod
    def get_tcp_connection_packet_headers(tcp_packet_headers):
        connections = []

        for tcp_packet_header in tcp_packet_headers:
            if tcp_packet_header.flags.syn==1 and tcp_packet_header.flags.ack==1:
                connections += [ TCPPCapAnalyzer.TCPConnection( sender = tcp_packet_header.src, receiver = tcp_packet_header.dst) ]

        for tcp_packet_header in tcp_packet_headers:
            for i, connection in enumerate(connections):
                packet_src, packet_dst = tcp_packet_header.src, tcp_packet_header.dst
                if (packet_src == connection.receiver and packet_dst == connection.sender) or \
                    (packet_src == connection.sender and packet_dst == connection.receiver):
                    connections[i].add_transaction_packet_header(tcp_packet_header)

        return connections


    @staticmethod
    def get_tcp_packet_headers(segments):
        tcp_packet_headers = [TCPHeader(segment) for segment in segments]
        return tcp_packet_headers


    @staticmethod
    def get_tcp_segments(pcap_file):
        tcp_segments = []
        pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp_segments.append(bytes(ip.data))
        
        #print("\n\n\n\TEST\n\n\n")
        #print("\n\n\n\TEST\n\n\n",tcp_segments[0],"\nTEST_END\n")
                
        return tcp_segments

        
