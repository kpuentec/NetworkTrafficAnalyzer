import sys
from backend.packet_parser import load_file, process_packets
from backend.threat_detector import analyze_packet

def main(file_path):
    print(f"Loading .pcapng file: {file_path}")
    packets = load_file(file_path)
    
    print("Processing packets:")
    categorized_packets = process_packets(packets)

    print("Analyzing packets for security threats:")
    all_threats = []
    for packet_category, packets in categorized_packets.items():
        for packet in packets:
            threats = analyze_packet(packet)
            if threats:
                all_threats.extend(threats)


if __name__ == "__main__":
    main(sys.arg[1])
