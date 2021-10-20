from utils import  unpack
from analysis_pcap_tcp import *


class HTTPPCapAnalyzer:


    @staticmethod
    def get_http_packet_type(tcp_payload):
        if len(tcp_payload)>32:

            chars = []
            for i in range(32,36):
                chars += [unpack(">s", tcp_payload[i:i+1])]

            initial_chars = ""
            for i in range(len(chars)):
                try:
                    initial_chars += chars[i].decode()
                except:
                    break
            
            if initial_chars.startswith("GET"):
                return "request"
            elif initial_chars.startswith("HTTP"):
                return "response"
            else:
                return None
        


    @staticmethod
    def reassemble_http_non_pipelined_request_responses(connections):
        reassembled_req_response = []
        for connection in connections:
            http_packets = []
            num_requests = 0
            for segment in connection.segments:
                packet_type = HTTPPCapAnalyzer.get_http_packet_type(segment.bytes)

                if packet_type == "request" :
                    http_packets += [[segment, []]]
                    num_requests += 1

                elif packet_type == "response" and num_requests != 0:
                    http_packets[num_requests-1][-1] += [segment]
            
            reassembled_req_response += [http_packets]

        return reassembled_req_response

            

                    
