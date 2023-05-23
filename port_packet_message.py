import sys
import nmap
import time
import os
from collections import Counter
import matplotlib.pyplot as plt
from scapy.all import *

packet_count = 0
packet_sizes = []  # List to store packet sizes
protocols = Counter()  # Counter to track packet protocols

nm = nmap.PortScanner()
nm.scan("192.168.35.0/24")

iot_ip = None
for host in nm.all_hosts():
    if nm[host].has_tcp(554) and nm[host]["tcp"][554]["state"] == "open":
        iot_ip = host
        break

if iot_ip is None:
    print("IoT 기기를 찾을 수 없습니다.")
else:
    print("IoT 기기의 IP 주소: ", iot_ip)


def handle_packet(packet):
    global packet_count, packet_sizes, protocols
    if Ether in packet:
        src = packet[Ether].src
        dst = packet[Ether].dst
        length = len(packet[Ether])
        checksum = packet[Ether].chksum

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ip_length = packet[IP].len
            ip_checksum = packet[IP].chksum

            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                data = (
                    packet[TCP].payload.load
                    if hasattr(packet[TCP].payload, "load")
                    else b""
                )
                print(
                    f"TCP packet: source={ip_src}, source_port={sport}, destination={ip_dst}, destination_port={dport}, length={ip_length}, checksum={ip_checksum}, data={data}"
                )
                packet_count += 1
                packet_sizes.append(ip_length)  # Store packet size for visualization
                protocols["TCP"] += 1

            if packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                data = (
                    packet[UDP].payload.load
                    if hasattr(packet[UDP].payload, "load")
                    else b""
                )
                print(
                    f"UDP packet: source={ip_src}, source_port={sport}, destination={ip_dst}, destination_port={dport}, length={ip_length}, checksum={ip_checksum}, data={data}"
                )
                packet_count += 1
                packet_sizes.append(ip_length)  # Store packet size for visualization
                protocols["UDP"] += 1


sniffingTime = input("Sniffing Time: ")
if iot_ip:
    print("프로그램 시작")
    sniff(prn=handle_packet, timeout=int(sniffingTime), filter=f"host {iot_ip}")
    print("Finish Capture Packet")
    if packet_count == 0:
        print("No Packet")
        sys.exit()
    else:
        packet_rate = packet_count / float(sniffingTime)
        print("Total Packet: %s" % packet_count)
        print("Packets per second: %.2f" % packet_rate)

        # Visualization - Packet Size Distribution
        plt.hist(packet_sizes, bins=20, color="skyblue")
        plt.xlabel("Packet Size")
        plt.ylabel("Frequency")
        plt.title("Packet Size Distribution")
        plt.show()

        # Print Traffic Statistics
        print("\nTraffic Statistics:")
        for protocol, count in protocols.items():
            print(f"{protocol}: {count} packets")
else:
    print("프로그램을 실행할 수 없습니다.")
