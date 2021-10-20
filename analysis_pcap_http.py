from utils import  unpack
from analysis_pcap_tcp import *


class HTTPPCapAnalyzer:


    @staticmethod
    def get_http_packet_type(tcp_payload):
        """  
        @params:
        - tcp_payload:  tcp payload bytes starting from 20th byte (options field + data payload) 

        @returns:
        - type of http packet header or None if no  matches
        """
        # within a tcp packet, the strings GET and HTTP to identify the type of http header
        # occurs from 12th byte
        if len(tcp_payload)>12:

            chars = [unpack(">s", tcp_payload[i:i+1]) for i in range(12,16)]

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
        """  
        @params:
        - connections:      list of TCPPCapAnalyzer.TCPConnection objects containing the 
                            addresses of the two nodes and the packets sent between them.
        
        @returns:
        - reassembled_req_response:    list of the format [ [request1, [response-1, response-2, ...]], 
                                                            [request2, [...]] ]
        """
        reassembled_req_response = []
        for connection in connections:
            http_packets = []
            for segment in connection.segments:
                packet_type = HTTPPCapAnalyzer.get_http_packet_type(segment.payload)

                if packet_type == "request" :
                    http_packets.append([segment, []])

                elif packet_type == "response":
                    http_packets[-1][-1] += [segment]
            
            reassembled_req_response += [http_packets]

        return reassembled_req_response

            

                    
