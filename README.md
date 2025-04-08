# NetworkTrafficAnalyzer

NetworkTrafficAnalyzer is a Python-based tool designed to analyze network traffic from `.pcapng` files captured with Wireshark. It helps detect various security threats, including unencrypted traffic, SYN scans, suspicious IP activity, ARP spoofing, and ICMP anomalies. The tool uses the Scapy library for packet analysis and Loguru for logging detected threats.

Features:

* Detects unencrypted traffic on common ports like HTTP, FTP, and Telnet

* Flags SYN scan attempts based on the number of TCP SYN packets from a source IP.

* Identifies suspicious IP activity based on the frequency of incoming packets.

* Detects ARP spoofing by analyzing MAC address inconsistencies

* Flags large ICMP payloads and ICMP flood attempts from source IPs.

* Logs detected threats into a rotating log file (`security.log`) for analysis.

Requirements:

Install Python3 onto your system(If you don't have it already).

Install:

1. Clone repository:

         git clone https://github.com/kpuentec/NetworkTrafficAnalyzer.git

4. Navigate to the project directory: cd NetworkTrafficAnalyzer

5. Install requirements:

         pip install -r requirements.txt

Run:

* Navigate to the root directory, cd NetwrokTrafficAnalyzer
  
* Upload your .pcapng file in the root folder
  
* Modify variable in config.py to the name of your .pcapng file.
  
* Run python main.py

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
