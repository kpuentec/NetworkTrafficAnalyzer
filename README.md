# NetworkTrafficAnalyzer

NetworkTrafficAnalyzer is a Python-based tool designed to analyze network traffic from `.pcapng` files captured with Wireshark. It helps detect various security threats, including unencrypted traffic, SYN scans, suspicious IP activity, ARP spoofing, and ICMP anomalies. The tool uses the Scapy library for packet analysis and Loguru for logging detected threats. Ddetection thresholds in the Network Traffic Analyzer are fully configurable, so you can tailor the sensitivity to better fit your specific use case or network environment.

Features:

* Detects unencrypted traffic on common ports like HTTP, FTP, and Telnet

* Flags SYN scan attempts based on the number of TCP SYN packets from a source IP.

* Identifies suspicious IP activity based on the frequency of incoming packets.

* Detects ARP spoofing by analyzing MAC address inconsistencies

* Flags large ICMP payloads and ICMP flood attempts from source IPs.

* Logs detected threats into a rotating log file (`security.log`) for analysis.

Requirements:

Install Python3 onto your system(If you don't have it already).

Install Wireshark to create .pcapng files that contain network traffic data to be analyzed.

Install:

1. Clone repository:

         git clone https://github.com/kpuentec/NetworkTrafficAnalyzer.git

2. Navigate to the project directory: cd NetworkTrafficAnalyzer

3. Install requirements:

         pip install -r requirements.txt

Run:

* Navigate to the root directory, cd NetworkTrafficAnalyzer
  
* Upload your .pcapng file in the root folder
  
* Modify variable in config.py to the name of your .pcapng file.
  
* Run python main.py

* Edit threat_detector.py variables and adjust them depending on how aggressive or lenient you'd like the threat detector to be.

           SYN_SCAN_THRESHOLD = 10
           SUSPICIOUS_IP_THRESHOLD = 100
           ICMP_PAYLOAD_THRESHOLD = 1000
           ARP_SPOOF_THRESHOLD = 1
           DNS_QUERY_THRESHOLD = 50
           UNENCRYPTED_PORTS = [80, 21, 23]


Structure:

*backend/ : Contains Python functions for the program

    *packet_parser.py : Parses packets and triggers threat detection.
    *threat_detector.py: Contains the logic for detecting specific network threats (SYN scans, ARP spoofing, etc.).

*main.py : Main script that ties everything together, reads packets from the `.pcapng` file, and processes them.

*config.py : Configuration file to specify the `.pcapng` file location and other settings.

*.gitignore : Git ignore file to exclude unnecessary files

*LICENSE : Project license info

*README.md: This file

Output:

security.log: A rotating log file that logs detected network traffic security threats

**Note:** Changes to the code and other features are susceptible in the future

2025
