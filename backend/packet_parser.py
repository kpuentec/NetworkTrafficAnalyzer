from scapy.all import IP, TCP, UDP, ICMP, ARP
from loguru import logger
from backend.threat_detector import detect_arp_spoofing, detect_icmp_anomalies, detect_suspicious_ip_activity, detect_syn_scan, detect_unencrypted_traffic
from datetime import datetime

def process_packets(packet):
    threats = []

    unencrypted_traffic = detect_unencrypted_traffic(packet)
    if unencrypted_traffic:
        threats.append(f"SECURITY ALERT | Unencrypted traffic detected: {', '.join(unencrypted_traffic)}")

    syn_scan = detect_syn_scan(packet)
    if syn_scan:
        threats.append(f"SECURITY ALERT | {syn_scan}")

    suspicious_ip = detect_suspicious_ip_activity(packet)
    if suspicious_ip:
        threats.append(f"SECURITY ALERT | {suspicious_ip}")

    arp_spoof = detect_arp_spoofing(packet)
    if arp_spoof:
        threats.append(f"SECURITY ALERT | {arp_spoof}")

    icmp_anomaly = detect_icmp_anomalies(packet)
    if icmp_anomaly:
        threats.append(f"SECURITY ALERT | {icmp_anomaly}")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = "N/A"
        dst_ip = "N/A"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        log_message = f"{timestamp} | TCP | Src IP: {src_ip}, Dst IP: {dst_ip}, Src Port: {src_port}, Dst Port: {dst_port}"
        logger.info(log_message)
        print(log_message)

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        log_message = f"{timestamp} | UDP | Src IP: {src_ip}, Dst IP: {dst_ip}, Src Port: {src_port}, Dst Port: {dst_port}"
        logger.info(log_message)
        print(log_message)

    elif packet.haslayer(ICMP):
        log_message = f"{timestamp} | ICMP | Src IP: {src_ip}, Dst IP: {dst_ip}"
        logger.info(log_message)
        print(log_message)

    elif packet.haslayer(ARP):
        src_mac = packet[ARP].hwsrc
        dst_mac = packet[ARP].hwdst
        log_message = f"{timestamp} | ARP | Src IP: {src_ip}, Dst IP: {dst_ip}, Src MAC: {src_mac}, Dst MAC: {dst_mac}"
        logger.info(log_message)
        print(log_message)

    return threats

