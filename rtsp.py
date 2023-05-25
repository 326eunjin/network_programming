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

        # 송신자와 수신자를 키로 사용하여 통신 흐름 저장
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

        # Hexdump of packet data
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

        # Hexdump of packet data
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
            captured_packets.append(packet)
            latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


sniffingTime = input("Sniffing Time (in seconds): ")
start_time = datetime.now()
end_time = start_time + timedelta(seconds=int(sniffingTime))

# UDP 및 TCP 패킷 캡처
sniff(filter="udp or tcp", prn=analyze_packet, timeout=int(sniffingTime))

# 통신 흐름 출력
for flow, count in communication_flow.items():
    src, sport, dst, dport, protocol = flow
    print(f"Flow: {protocol} {src}:{sport} -> {dst}:{dport}, Count: {count}")

#프로토콜 횟수 분석 결과 출력
for protocol, count in protocol_count.items():
    print(f"Protocol: {protocol}, Count : {count}")

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
                latencies = [
                    rtt
                    for src, dst, rtt in latency_values
                    if src == src_ip and dst == dst_ip
                ]
                if len(latencies) > 0:
                    avg_latency = sum(latencies) / len(latencies)
                    print(f"Average Latency (Source: {src_ip}, Destination: {dst_ip}): {avg_latency} seconds")
                else:
                    print(f"No packets found for Source: {src_ip}, Destination: {dst_ip}")


        # Visualization - Latency Analysis
        plt.figure(figsize=(12, 6))
        plt.plot(rtt_values, marker="o")
        plt.xlabel("Packet Index")
        plt.ylabel("Round-trip Time (RTT) in seconds")
        plt.title("Latency Analysis")
        plt.show()

        # Visualization - Traffic Analysis
        intervals = []
        packet_counts = []

        current_time = start_time
        while current_time <= end_time:
            next_time = current_time + timedelta(seconds=1)
            interval_packets = [
                packet
                for packet in captured_packets
                if current_time <= datetime.fromtimestamp(packet.time) <= next_time
            ]
            intervals.append(current_time.strftime("%H:%M:%S"))
            packet_counts.append(len(interval_packets))
            current_time = next_time

        # Determine the number of x-axis labels to display
        max_labels = 10
        num_labels = min(len(intervals), max_labels)

        # Determine the step size for selecting the labels
        step = max(len(intervals) // num_labels, 1)

        # Select a subset of labels and counts for display
        selected_intervals = intervals[::step]
        selected_packet_counts = packet_counts[::step]

        plt.figure(figsize=(12, 6))
        plt.plot(intervals, packet_counts, marker="o")
        plt.xlabel("Time")
        plt.ylabel("Packet Count")
        plt.title("Traffic Analysis")
        plt.xticks(rotation=45)
        plt.xticks(selected_intervals)  # Set the selected labels on the x-axis
        plt.plot(selected_intervals, selected_packet_counts, marker="o")  # Plot the selected data points
        plt.show()

        print("Traffic Analysis:")
        for time, count in zip(selected_intervals, selected_packet_counts):
            print(f"{time}: {count} packets")


else:
    print("프로그램을 실행할 수 없습니다.")
