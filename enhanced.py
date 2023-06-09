import sys
import nmap
from datetime import datetime, timedelta
from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter

packet_count = 0
protocols = Counter()
captured_packets = []
latency_values = []
communication_flow = {}

nm = nmap.PortScanner()
nm.scan("192.168.35.0/24")

iot_ip = None
for host in nm.all_hosts():
    if nm[host].has_tcp(554) and nm[host]["tcp"][554]["state"] == "open":
        iot_ip = host
        break

if iot_ip is None:
    print("IoT 기기를 찾을 수 없습니다.")
    sys.exit()

print("IoT 기기의 IP 주소:", iot_ip)

# protocol 횟수 카운트
protocol_count = {}


def analyze_packet(packet):
    if packet.haslayer(IP):
        if packet.haslayer(UDP):
            protocol = "UDP"
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(TCP):
            protocol = "TCP"
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        else:
            return

        flow_key = (src, sport, dst, dport, protocol)
        if flow_key in communication_flow:
            communication_flow[flow_key] += 1
        else:
            communication_flow[flow_key] = 1

        if protocol in protocol_count:
            protocol_count[protocol] += 1
        else:
            protocol_count[protocol] = 1


def handle_tcp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        data = packet[TCP].payload.load if hasattr(packet[TCP].payload, "load") else b""
        print(f"TCP packet: source_port={sport}, destination_port={dport}")

        hexdump(data)

        print()

        packet_count += 1
        protocols["TCP"] += 1
        captured_packets.append(packet)
        latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


def handle_udp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        data = packet[UDP].payload.load if hasattr(packet[UDP].payload, "load") else b""
        print(f"UDP packet: source_port={sport}, destination_port={dport}")

        hexdump(data)

        print()

        packet_count += 1
        protocols["UDP"] += 1
        captured_packets.append(packet)
        latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


def handle_rtp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(RTP):
        payload = packet[RTP].payload
        if payload:
            print("RTP packet:")

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

            print()

            packet_count += 1
            protocols["RTP"] += 1
            captured_packets.append(packet)
            latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


def service_detection(ip):
    nm.scan(ip, arguments="-sV")
    if nm[ip].state() == "up":
        print("Open ports:")
        for port in nm[ip]["tcp"]:
            if nm[ip]["tcp"][port]["state"] == "open":
                print(
                    f"Port {port} - {nm[ip]['tcp'][port]['name']} - {nm[ip]['tcp'][port]['product']}"
                )
    else:
        print("No open ports found for the specified IP.")


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
        print("Total Packet:", packet_count)

        # Visualization - Protocol Distribution
        labels = protocols.keys()
        values = protocols.values()

        plt.figure(figsize=(8, 6))
        plt.pie(values, labels=labels, autopct="%1.1f%%")
        plt.title("Protocol Distribution")
        plt.show()
        print("Protocol Distribution: ")
        for label, value in zip(labels, values):
            print(f"{label}: {value} packets")

        # Visualization - Packet Size Distribution
        packet_sizes = [len(packet.payload) for packet in captured_packets]
        plt.figure(figsize=(8, 6))
        plt.hist(packet_sizes, bins=50)
        plt.xlabel("Packet Size")
        plt.ylabel("Frequency")
        plt.title("Packet Size Distribution")
        plt.show()
        print("Packet Size Distribution")

        # Payload Analysis
        print("Payload Analysis:")
        for packet in captured_packets:
            if packet.haslayer(TCP):
                if packet[TCP].payload:
                    payload = packet[TCP].payload.load
                    print("Payload:", payload)

        # Service Detection
        print("Service Detection:")
        service_detection(iot_ip)

        # Latency Analysis
        src_ips = set()
        dst_ips = set()
        rtt_values = []

        for src_ip, dst_ip, timestamp in latency_values:
            src_ips.add(src_ip)
            dst_ips.add(dst_ip)
            rtt = (datetime.fromtimestamp(timestamp) - start_time).total_seconds()
            rtt_values.append(rtt)

        print("Latency Analysis:")
        for src_ip in src_ips:
            for dst_ip in dst_ips:
                rtt = [
                    rtt
                    for src, dst, rtt in latency_values
                    if src == src_ip and dst == dst_ip
                ]
                print(
                    f"RTT from {src_ip} to {dst_ip}: Min={min(rtt)}, Max={max(rtt)}, Average={sum(rtt) / len(rtt)}"
                )

        # Visualization - Round Trip Time (RTT) Distribution
        plt.figure(figsize=(8, 6))
        plt.hist(rtt_values, bins=50)
        plt.xlabel("Round Trip Time (RTT)")
        plt.ylabel("Frequency")
        plt.title("RTT Distribution")
        plt.show()

else:
    print("No IoT device found in the network.")
