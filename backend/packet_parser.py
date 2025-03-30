from scapy.all import rdpcap

def load_file(file_path):
    packets = rdpcap(file_path)
    return packets

def process_packets(packets):
    all_http_packets = []
    all_tcp_udp_packets = []
    all_arp_packets = []
    all_icmp_packets = []

    for packet in packets:
        if packet.haslayer("HTTP"):
            all_http_packets.append(extract_http_packets(packet))
        elif packet.haslayer("TCP") or packet.haslayer("UDP"):
            all_tcp_udp_packets.append(extract_tcp_udp_packets(packet))
        elif packet.haslayer("ARP"):
            all_arp_packets.append(extract_arp_packets(packet))
        elif packet.haslayer("ICMP"):
            all_icmp_packets.append(extract_icmp_packets(packet))

    return {
        "http": all_http_packets,
        "tcp_udp": all_tcp_udp_packets,
        "arp": all_arp_packets,
        "icmp": all_icmp_packets
    }


def extract_http_packets(packet):

    http_packets = []
    
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        if packet["TCP"].dport == 80 or packet["TCP"].sport == 80:
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            payload = packet["TCP"].payload.decode(errors="ignore")

            method = None
            for m in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
                if m in payload:
                    method = m
                    break

            host = None
            if "Host:" in payload:
                try:
                    host = payload.split("Host: ")[1].split("\r\n")[0]
                except IndexError:
                    pass

            http_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "method": method,
                "host": host,
                "payload": payload[:100] if len(payload) > 100 else payload
            }
            http_packets.append(http_info)

    return http_packets

def extract_tcp_udp_packets(packet):

    packets = []

    if packet.haslayer("IP") and (packet.haslayer("TCP") or packet.haslayer("UDP")):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        payload = str(packet["TCP"].payload) if packet.haslayer("TCP") else str(packet["UDP"].payload)
        protocol = "TCP" if packet.haslayer("TCP") else "UDP"
        src_port = packet["TCP"].sport if packet.haslayer("TCP") else packet["UDP"].sport
        dst_port = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport

        packet_info = {
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload[:100] if len(payload) > 100 else payload
        }
        packets.append(packet_info)

    return packets

def extract_arp_packets(packet):

    arp_packets = []

    if packet.haslayer("ARP"):
        src_ip = packet["ARP"].psrc
        dst_ip = packet["ARP"].pdst
        src_mac = packet["ARP"].hwsrc
        dst_mac = packet["ARP"].hwdst

        arp_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac
        }
        arp_packets.append(arp_info)

    return arp_packets

def extract_icmp_packets(packet):

    icmp_packets = []

    if packet.haslayer("ICMP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        icmp_type = packet["ICMP"].type
        icmp_code = packet["ICMP"].code

        icmp_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code
        }
        icmp_packets.append(icmp_info)

    return icmp_packets