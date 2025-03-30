from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, ARP

ip_activity = defaultdict(int)
mac_to_ip = defaultdict(list)
icmp_packets = defaultdict(int)

SYN_SCAN_THRESHOLD = 10
SUSPICIOUS_IP_THRESHOLD = 100 
ICMP_PAYLOAD_THRESHOLD = 1000
ARP_SPOOF_THRESHOLD = 1
DNS_QUERY_THRESHOLD = 50


def detect_unencrypted_traffic(packet):

    unencrypted_ports = [80, 21, 23]
    unencrypted_protocols = []

    if packet.haslayer(TCP):

        if packet[TCP].dport in unencrypted_ports or packet[TCP].sport in unencrypted_ports:
            protocol = "FTP" if packet[TCP].dport == 21 else "Telnet" if packet[TCP].dport == 23 else "HTTP"
            unencrypted_protocols.append(protocol)
            
    return unencrypted_protocols

def detect_syn_scan(packet):

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        ip_activity[src_ip] += 1
        if ip_activity[src_ip] > SYN_SCAN_THRESHOLD:
            return f"SYN scan detected from {src_ip}"
    return None

def detect_suspicious_ip_activity(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_activity[src_ip] += 1
        if ip_activity[src_ip] > SUSPICIOUS_IP_THRESHOLD:
            return f"Suspicious IP activity detected from {src_ip}"
    return None

def detect_arp_spoofing(packet):

    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        mac_to_ip[ip].append(mac)

        if len(set(mac_to_ip[ip])) > ARP_SPOOF_THRESHOLD:
            return f"ARP spoofing detected for IP {ip}"
    return None

def detect_icmp_anomalies(packet):

    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload_length = len(packet[ICMP].payload)

        if payload_length > ICMP_PAYLOAD_THRESHOLD:
            return f"Large ICMP payload detected from {src_ip} to {dst_ip}"

        icmp_packets[src_ip] += 1
        if icmp_packets[src_ip] > SYN_SCAN_THRESHOLD:
            return f"ICMP flood detected from {src_ip}"
    return None

def analyze_packet(packet):

    threats = []

    unencrypted_traffic = detect_unencrypted_traffic(packet)
    if unencrypted_traffic:
        threats.append(f"Unencrypted traffic detected: {', '.join(unencrypted_traffic)}")

    syn_scan = detect_syn_scan(packet)
    if syn_scan:
        threats.append(syn_scan)

    suspicious_ip = detect_suspicious_ip_activity(packet)
    if suspicious_ip:
        threats.append(suspicious_ip)

    arp_spoof = detect_arp_spoofing(packet)
    if arp_spoof:
        threats.append(arp_spoof)

    icmp_anomaly = detect_icmp_anomalies(packet)
    if icmp_anomaly:
        threats.append(icmp_anomaly)

    return threats
