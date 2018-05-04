from scapy.all import *
def isHTTP(packet):
    tcp_packet = packet.getlayer(TCP)
    if tcp_packet.dport == 80:
        if packet.haslayer(Raw):
            packet_str = packet.getlayer(Raw).load.decode(errors = 'ignore')
            if packet_str.startswith('GET'):
                return True
            elif packet_str.startswith('POST'):
                return True
    if tcp_packet.sport == 80:
        if packet.haslayer(Raw):
            packet_str = packet.getlayer(Raw).load.decode(errors = 'ignore')
            if packet_str.startswith('HTTP'):
                return True
    return False

def generateInfo(packet):
    if isHTTP(packet) is not True:
        return ""
    tcp_packet = packet.getlayer(TCP)
    if tcp_packet.dport == 80:
        if packet.haslayer(Raw):
            packet_str = packet.getlayer(Raw).load.decode(errors = 'ignore')
            if packet_str.startswith('GET') or packet_str.startswith('POST'):
                if 'HTTP' in packet_str:
                    end_index = packet_str.index('HTTP') if packet_str.index('HTTP') <= 100 else 100
                    return packet_str[0:end_index]
    if tcp_packet.sport == 80:
        if packet.haslayer(Raw):
            packet_str = packet.getlayer(Raw).load.decode(errors = 'ignore')
            if packet_str.startswith('HTTP'):
                if 'Server' in packet_str:
                    end_index = packet_str.index('Server') if packet_str.index('Server') <= 100 else 100
                    return packet_str[0:end_index]
    return ""

    