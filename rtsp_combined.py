import sys
import nmap
from datetime import datetime, timedelta
from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter

# 전역 변수 초기화
packet_count = 0  # 캡처된 패킷 수를 저장하는 변수
protocols = Counter()  # 프로토콜별 패킷 수를 저장하는 Counter 객체
captured_packets = []  # 캡처된 패킷을 저장하는 리스트
latency_values = []  # 패킷의 지연 시간 정보를 저장하는 리스트
start_time = datetime.now()  # 패킷 캡처 시작 시간을 저장하는 변수


# IoT 디바이스를 검색하는 함수
def scan_iot_device():
    nm = nmap.PortScanner()
    nm.scan("192.168.35.0/24")

    iot_ip = None
    for host in nm.all_hosts():
        # 포트 554에서 TCP 연결이 열린 경우 IoT 디바이스로 가정
        if nm[host].has_tcp(554) and nm[host]["tcp"][554]["state"] == "open":
            iot_ip = host
            break

    if iot_ip is None:
        print("IoT 기기를 찾을 수 없습니다.")
        sys.exit()

    print("IoT 기기의 IP 주소:", iot_ip)
    return iot_ip


# TCP 패킷을 처리하는 함수
def handle_tcp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        data = packet[TCP].payload.load if hasattr(packet[TCP].payload, "load") else b""
        print(f"TCP 패킷: 소스 포트={sport}, 목적지 포트={dport}")

        # 패킷 데이터의 16진수 덤프 출력
        hexdump(data)

        print()

        packet_count += 1
        protocols["TCP"] += 1
        captured_packets.append(packet)
        latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


# UDP 패킷을 처리하는 함수
def handle_udp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        data = packet[UDP].payload.load if hasattr(packet[UDP].payload, "load") else b""
        print(f"UDP 패킷: 소스 포트={sport}, 목적지 포트={dport}")

        # 패킷 데이터의 16진수 덤프 출력
        hexdump(data)

        print()

        packet_count += 1
        protocols["UDP"] += 1
        captured_packets.append(packet)
        latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


# RTP 패킷을 처리하는 함수
def handle_rtp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(RTP):
        payload = packet[RTP].payload
        if payload:
            print("RTP 패킷:")

            # RTP 헤더 필드 추출
            version = packet[RTP].version
            padding = packet[RTP].padding
            extension = packet[RTP].extension
            marker = packet[RTP].marker
            ssrc = packet[RTP].ssrc
            timestamp = packet[RTP].timestamp
            sequence = packet[RTP].seq

            print(f"버전: {version}")
            print(f"패딩: {padding}")
            print(f"확장: {extension}")
            print(f"마커: {marker}")
            print(f"SSRC: {ssrc}")
            print(f"타임스탬프: {timestamp}")
            print(f"시퀀스 번호: {sequence}")

            # RTP 페이로드 (비디오 프레임) 처리
            # 사용된 비디오 코덱에 따라 페이로드를 디코딩하고 개별 프레임을 추출해야 할 수도 있습니다.

            print()

            packet_count += 1
            protocols["RTP"] += 1
            captured_packets.append(packet)
            latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


# ICMP 패킷을 처리하는 함수
def handle_icmp_packet(packet):
    global packet_count, protocols, captured_packets, latency_values
    if packet.haslayer(ICMP):
        print("ICMP 패킷:")
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        print(f"타입: {icmp_type}")
        print(f"코드: {icmp_code}")

        packet_count += 1
        protocols["ICMP"] += 1
        captured_packets.append(packet)
        latency_values.append((packet[IP].src, packet[IP].dst, packet.time))


# 패킷을 캡처하는 함수
def capture_packets(iot_ip, sniffing_time):
    global start_time, end_time
    start_time = datetime.now()
    end_time = start_time + timedelta(seconds=int(sniffing_time))

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
            sniff(
                prn=handle_icmp_packet,
                timeout=1,
                filter=f"host {iot_ip} and icmp",
            )

        print("패킷 캡처 완료")
        if packet_count == 0:
            print("캡처된 패킷이 없습니다.")
            sys.exit()
        else:
            print("총 패킷 수:", packet_count)


# 프로토콜 분포 시각화 함수
def visualize_protocol_distribution():
    labels = protocols.keys()
    values = protocols.values()

    plt.figure(figsize=(8, 6))
    plt.pie(values, labels=labels, autopct="%1.1f%%")
    plt.title("프로토콜 분포")
    plt.show()

    print("프로토콜 분포:")
    for label, value in zip(labels, values):
        print(f"{label}: {value} 패킷")


# 패킷 크기 분포 시각화 함수
def visualize_packet_size_distribution():
    packet_sizes = [len(packet.payload) for packet in captured_packets]
    plt.figure(figsize=(8, 6))
    plt.hist(packet_sizes, bins=50)
    plt.xlabel("패킷 크기")
    plt.ylabel("빈도")
    plt.title("패킷 크기 분포")
    plt.show()
    print("패킷 크기 분포")


# 지연 시간 분석 함수
def analyze_latency():
    src_ips = set()
    dst_ips = set()
    rtt_values = []

    for src_ip, dst_ip, timestamp in latency_values:
        src_ips.add(src_ip)
        dst_ips.add(dst_ip)
        rtt = (datetime.fromtimestamp(timestamp) - start_time).total_seconds()
        rtt_values.append(rtt)

    print("지연 시간 분석:")
    for src_ip in src_ips:
        for dst_ip in dst_ips:
            latencies = [
                rtt
                for src, dst, rtt in latency_values
                if src == src_ip and dst == dst_ip
            ]
            if len(latencies) > 0:
                avg_latency = sum(latencies) / len(latencies)
                print(f"평균 지연 시간 (출발지: {src_ip}, 목적지: {dst_ip}): {avg_latency} 초")
            else:
                print(f"출발지: {src_ip}, 목적지: {dst_ip}에 대한 패킷이 발견되지 않았습니다.")

    plt.figure(figsize=(12, 6))
    plt.plot(rtt_values, marker="o")
    plt.xlabel("패킷 인덱스")
    plt.ylabel("왕복 시간 (RTT, Round-trip Time) (초)")
    plt.title("지연 시간 분석")
    plt.show()


# 트래픽 분석 시각화 함수
def visualize_traffic_analysis():
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

    max_labels = 10
    num_labels = min(len(intervals), max_labels)
    step = max(len(intervals) // num_labels, 1)
    selected_intervals = intervals[::step]
    selected_packet_counts = packet_counts[::step]

    plt.figure(figsize=(12, 6))
    plt.plot(intervals, packet_counts, marker="o")
    plt.xlabel("시간")
    plt.ylabel("패킷 수")
    plt.title("트래픽 분석")
    plt.xticks(rotation=45)
    plt.xticks(selected_intervals)
    plt.plot(selected_intervals, selected_packet_counts, marker="o")
    plt.show()

    print("트래픽 분석:")
    for time, count in zip(selected_intervals, selected_packet_counts):
        print(f"{time}: {count} 패킷")


def main():
    iot_ip = scan_iot_device()  # IoT 디바이스 스캔 및 IP 주소 가져오기
    sniffing_time = input("캡처 시간 (초): ")  # 캡처 시간 입력

    capture_packets(iot_ip, sniffing_time)  # 패킷 캡처

    if packet_count == 0:
        print("캡처된 패킷이 없습니다.")
        sys.exit()
    # 한글 폰트 사용을 위해서 세팅
    from matplotlib import font_manager, rc

    font_path = "/System/Library/Fonts/Supplemental/AppleGothic.ttf"
    font = font_manager.FontProperties(fname=font_path).get_name()
    rc("font", family=font)
    visualize_protocol_distribution()  # 프로토콜 분포 시각화
    visualize_packet_size_distribution()  # 패킷 크기 분포 시각화
    analyze_latency()  # 지연 시간 분석
    visualize_traffic_analysis()  # 트래픽 분석 시각화


if __name__ == "__main__":
    main()
