import dpkt
import pickle
from utils import get_string_representation, get_bits
import os, re
import base64
import socket
from collections import defaultdict, Counter
from analysis_pcap_tcp import TCPSegment


class HTTPPacketType:
    def __init__(self, tcp_payload) -> None:
        packet_type = tcp_payload[0].decode() + tcp_payload[1].decode() + tcp_payload[2].decode() + tcp_payload[3].decode()

        header_chars = []
        for i in range(len(packet_type)+1):
            header_chars += [tcp_payload[i:i+1].decode()]
            
        header_string = "".join(header_chars)

        self.packet_type = re.search(r"(?:(GET|HTTP)).*", header_string).groups()[0]

        request_http_pat = r'''GET (.*) HTTP/([0-9].[0-9])\nHost: ([^\n]+)\nUser-Agent: ([^\n]+)\nAccept: ([^\n]+)\nAccept-Language: ([^\n]+)\nAccept-Encoding: ([^\n]+)\nReferer: ([^\n]+)\nConnection: ([^\n]+)\nUpgrade-Insecure-Requests: ([^\n]+)\nIf-Modified-Since: ([^\n]+)\nIf-None-Match: ([^\n]+)\nCache-Control: ([^\n]+).*'''
        


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

                packet_src_ip, packet_dst_ip = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
                packet_addresses = {packet_src_ip, packet_dst_ip}
                analysis_addresses = {src_ip, dst_ip}

                if isinstance(ip.data, dpkt.tcp.TCP) and packet_addresses==analysis_addresses:
                    tcp_segments.append( (ts, bytes(ip.data)) )
        
        tcp_segments = [TCPSegment(segment=segment, src_ip=packet_src_ip, dst_ip=packet_dst_ip, ts=ts) \
                for ts,segment in tcp_segments]

        return tcp_segments