import dpkt, struct

pcap_file = "/Users/dhavalbagal/Documents/GitHub/tcp-packet-analysis/http_1080.pcap"

pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))

def unpack(fmt, buf):
    return struct.unpack(fmt, buf)[0]

k = 0
for ts, buf in pcap:
    if len(buf)>66:
        c1 = unpack(">s", buf[66:67])
        c2 = unpack(">s", buf[67:68])
        c3 = unpack(">s", buf[68:69])
        try:
            print(c1.decode()+c2.decode()+c3.decode())
        except:
            pass
    k+=1
    if k>10:
        break