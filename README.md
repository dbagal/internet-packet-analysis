# TCP PCap Analysis

This project implements a pcap file parser to parse tcp segments and analyse them.

**Programming Language:** *Python*

# External libraries used

- *dpkt==1.9.7.2*
- *pickle*
- *base64*
- *struct*

# Project structure

- **analysis_components/:** Folder containing processed pcap files serialized and stored in pickle format
- **PartA/part_a.py:** Analysis for part A
- **PartA/part_b.py:** Analysis for part B
- **PartA/part_c.py:** Analysis for part C
- **PartA/part_d.txt:** Analysis for part D
- **pcap/:** Folder which stores all the pcap files used in the analysis
- **analysis_pcap_tcp.py** Provides classes to analyze tcp segments in the pcap files
- **analysis_pcap_http.py:** Provides classes to analyze http packets in the pcap files
- **utils.py:** Provides basic utilities for printing results and unpacking binary data from the pcap files
- **performance-report.txt:** Contains the response times for all the top 25 sites using mydig resolver, local resolver and google's resolver
- **documentation.pdf:** Documentation of the methods used for parsing and analysis

# Installation and setup

```
$ pip3 install -r requirements.txt
```

# Usage

For running the files for different parts, use the following commands:
```
$ python3 ./PartA/part_a.py
$ python3 ./PartB/part_b.py
$ python3 ./PartC/part_c.py
```

**analysis_pcap_tcp.py** and **analysis_pcap_http.py** provides some classes and functions which are used in each of the four parts for the analysis

Usage for **analysis_pcap_tcp.py**
```
from analysis_pcap_tcp.py import *

pcap_file = "" # pcap file name

# get the components required for analysis from the pcap_file
# you can form components only for packets with specific source and destination, 
# by specifying it in src_ip and dst_ip parameters
components = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_file, src_ip=src_ip, dst_ip=dst_ip)

# print tcp segment to see its contents
print(components.tcp_segments[0])

# output
"""
========================================================
| TCP SEGMENT                                          |
| src-ip: 130.245.145.12                               |
| dest-ip: 128.208.2.198                               |
| src-port: 43498                                      |
| dest-port: 80                                        |
| sequence-num: 705669102                              |
| ack: 0                                               |
| data-offset: 10                                      |
| reserved: 0                                          |
| flags:                                               |
| - ns: 0                                              |
| - cwr: 0                                             |
| - ece: 0                                             |
| - urg: 0                                             |
| - ack: 0                                             |
| - psh: 0                                             |
| - rst: 0                                             |
| - syn: 1                                             |
| - fin: 0                                             |
| window-size: 42340 bytes                             |
| checksum: 63936                                      |
| urgent-ptr: 0                                        |
| payload-size: 20 bytes                               |
| timestamp: 1487361393.534537                         |
| base64-encoded-payload: AgQFtAEBCAoObomWAAAAAAEDAw4= |
========================================================

# get throughput for every connection
empirical_throughput = TCPPCapAnalyzer.get_empirical_throughput(components.tcp_connections)
theoretical_throughputs = TCPPCapAnalyzer.get_theoretical_throughput(connections=components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

# get loss rate for every connection
loss_rates = TCPPCapAnalyzer.get_loss_rate(connections=components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

# get avg rtt for every connection
rtts = TCPPCapAnalyzer.get_rtt(connections=components.tcp_connections)

# get retransmissions due to triple dup acks, timeout and total retransmissions as a tuple for every connection
retransmissions = TCPPCapAnalyzer.num_retransmissions(components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)

# get congestion window sizes for every connection
cwnd_sizes = TCPPCapAnalyzer.congestion_window_sizes(components.tcp_connections, src_ip=src_ip, dst_ip=dst_ip)
"""
```

Usage for **analysis_pcap_tcp.py**
```
from analysis_pcap_tcp import *
from analysis_pcap_http import *

pcap_file = "" # pcap file name

# get analysis components for all packets with any source or destination
components = TCPPCapAnalyzer.process_pcap(pcap_file=pcap_files[0], src_ip=None, dst_ip=None)

# get request and responses for http
request_responses = HTTPPCapAnalyzer.reassemble_http_non_pipelined_request_responses(components.tcp_connections)
```

Usage for **utils.py**
```
from utils import PrettyPrint

d = [ ["Mark", 12, 95],
     ["Jay", 11, 88],
     ["Jack", 14, 90]]
h = ["name", "age", "score"]
PrettyPrint.print_in_tabular_format(d,h, table_header="DATA")

# output
"""
======================================
|                DATA                |
|------------------------------------|
|  Sr.No  |  name  |  age  |  score  |  
|====================================|
|  1      |  Mark  |  12   |  95     |  
|  2      |  Jay   |  11   |  88     |  
|  3      |  Jack  |  14   |  90     |  
======================================
"""
```

# Exceptions

- **NoTCPTransactions:** Raised when a connection has no packet transactions after the setup

