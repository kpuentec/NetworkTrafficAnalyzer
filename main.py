from loguru import logger
from backend.packet_parser import process_packets
from config import PCAPNG
from scapy.all import rdpcap


def logger_setup():
    logger.add("security.log", format="{level} | {message}", rotation="1 MB", compression="zip")
    print("Logger has been set up to write security logs")

def main():
    pcap_file = PCAPNG

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: The PCAPNG file '{pcap_file}' was not found.")
        return

    all_threats = []
    print("Processing packets...")

    for packet in packets:
        print(f"Analyzing packet: {packet.summary()}")
        threats = process_packets(packet)
        all_threats.extend(threats)

        for threat in threats:
            logger.info(threat)

    print("\nDetected security threats:")
    if all_threats:
        for threat in all_threats:
            print(threat)
            logger.info(threat)
    else:
        print("No security threats detected.")
        logger.info("No security threats detected.")

if __name__ == "__main__":
    logger_setup()
    main()