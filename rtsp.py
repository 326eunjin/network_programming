import sys
import nmap
from datetime import datetime
from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter

packet_count = 0
protocols = Counter()

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


def handle_tcp_packet(packet):
    global packet_count, protocols
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        data = packet[TCP].payload.load if hasattr(packet[TCP].payload, "load") else b""
        print(f"TCP packet: source_port={sport}, destination_port={dport}")

        # Hexdump of packet data
        hexdump(data)

        print()

        packet_count += 1
        protocols["TCP"] += 1


def handle_udp_packet(packet):
    global packet_count, protocols
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        data = packet[UDP].payload.load if hasattr(packet[UDP].payload, "load") else b""
        print(f"UDP packet: source_port={sport}, destination_port={dport}")

        # Hexdump of packet data
        hexdump(data)

        print()

        packet_count += 1
        protocols["UDP"] += 1


def handle_rtp_packet(packet):
    global packet_count, protocols
    if packet.haslayer(RTP):
        payload = packet[RTP].payload
        if payload:
            print("RTP packet:")

            # Extract RTP header fields
            version = packet[RTP].version
            padding = packet[RTP].padding
            extension = packet[RTP].extension
            marker = packet[RTP].marker
            ssrc = packet[RTP].ssrc
            timestamp = packet[RTP].timestamp
            sequence = packet[RTP].seq

            print(f"Version: {version}")
            print(f"Padding: {padding}")
            print(f"Extension: {extension}")
            print(f"Marker: {marker}")
            print(f"SSRC: {ssrc}")
            print(f"Timestamp: {timestamp}")
            print(f"Sequence number: {sequence}")

            # Handle RTP payload (video frames)
            # You may need to decode the payload based on the video codec used
            # and extract individual frames

            print()

            packet_count += 1
            protocols["RTP"] += 1


sniffingTime = input("Sniffing Time (in seconds): ")
start_time = datetime.now()
end_time = start_time + timedelta(seconds=int(sniffingTime))

if iot_ip:
    print("프로그램 시작")

    while datetime.now() <= end_time:
        sniff(
            prn=handle_tcp_packet,
            timeout=1,
            filter=f"host {iot_ip} and tcp",
        )
        sniff(
            prn=handle_udp_packet,
            timeout=1,
            filter=f"host {iot_ip} and udp",
        )
        sniff(
            prn=handle_rtp_packet,
            timeout=1,
            filter=f"host {iot_ip} and udp and port 554",
        )

    print("Finish Capture Packet")
    if packet_count == 0:
        print("No Packet")
        sys.exit()
    else:
        print("Total Packet: %s" % packet_count)

        # Visualization - Protocol Distribution
        labels = protocols.keys()
        values = protocols.values()

        plt.pie(values, labels=labels, autopct="%1.1f%%")
        plt.title("Protocol Distribution")
        plt.show()
else:
    print("프로그램을 실행할 수 없습니다.")
