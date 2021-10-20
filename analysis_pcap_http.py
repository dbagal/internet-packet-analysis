from typing import OrderedDict
import dpkt
import pickle
from utils import get_string_representation, get_bits
import os, re
import base64
import socket
from collections import defaultdict, Counter
from analysis_pcap_tcp import *


class HTTPPCapAnalyzer:


    @staticmethod
    def get_http_packet_type(tcp_payload):
        print(tcp_payload[0:50])
        packet_type = str(tcp_payload[6:7]) + str(tcp_payload[7:8]) + str(tcp_payload[8:9]) + str(tcp_payload[9:10])
        packet_head = re.search(r"(?:(GET|HTTP)).*", packet_type).groups()[0]
        if packet_head == "GET":
            return "request"
        else:
            return "response"


    @staticmethod
    def reassemble_http_non_pipelined_request_responses(connections, src_ip, dst_ip):
        for connection in connections:
            for segment in connection.segments:
                print(segment.payload[0:50])


        reassembled_req_response = []
        for connection in connections:
            http_packets = []
            num_requests = 0
            for segment in connection.segments:
                if len(segment.payload)<=0: continue
                packet_type = HTTPPCapAnalyzer.get_http_packet_type(segment.payload)

                if packet_type == "request" :
                    http_packets += [(segment, [])]
                    num_requests += 1

                elif packet_type == "response" and num_requests != 0:
                    http_packets[num_requests][-1] += [segment]
            
            reassembled_req_response += [http_packets]

        return reassembled_req_response

            

                    
