from scapy.all import *

import nmap

# 네트워크 스캐너를 사용하여 iot 기기의 IP 주소를 스캔
nm = nmap.PortScanner()
nm.scan("192.168.35.0/24")  # 네트워크 주소 범위 지정

# 스캔된 IP 주소 리스트 추출
scanned_ips = []
for host in nm.all_hosts():
    # iot 기기의 특정 포트 번호가 열려있는지 확인
    if nm[host].has_tcp(554) and nm[host]["tcp"][554]["state"] == "open":
        scanned_ips.append(host)

# 통신 흐름을 저장할 딕셔너리
communication_flow = {}

# 네트워크 스캐너를 사용하여 iot 기기의 IP 주소를 스캔
nm = nmap.PortScanner()
nm.scan("192.168.35.0/24")  # 네트워크 주소 범위 지정

# 스캔된 IP 주소 리스트 추출
scanned_ips = []
for host in nm.all_hosts():
        # iot 기기의 특정 포트 번호가 열려있는지 확인
            if nm[host].has_tcp(554) and nm[host]["tcp"][554]["state"] == "open":
                        scanned_ips.append(host)
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

#몇 초간 캡쳐할 건지(초 넣어줘)
sniffingTime = input("Sniffing Time: ")

# UDP 및 TCP 패킷 캡처
sniff(filter="udp or tcp", prn=analyze_packet, timeout=int(sniffingTime))

# 통신 흐름 출력
for flow, count in communication_flow.items():
    src, sport, dst, dport, protocol = flow
    print(f"Flow: {protocol} {src}:{sport} -> {dst}:{dport}, Count: {count}")

#프로토콜 횟수 분석 결과 출력
for protocol, count in protocol_count.items():
    print(f"Protocol: {protocol}, Count : {count}")
