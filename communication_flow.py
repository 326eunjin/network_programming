from scapy.all import *

# 통신 흐름을 저장할 딕셔너리
communication_flow = {}
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

# UDP 및 TCP 패킷 캡처
sniff(filter="udp or tcp", prn=analyze_packet)

# 통신 흐름 출력
for flow, count in communication_flow.items():
    src, sport, dst, dport, protocol = flow
    print(f"Flow: {protocol} {src}:{sport} -> {dst}:{dport}, Count: {count}")

#프로토콜 횟수 분석 결과 출력
for protocol, count in protocol_count.items():
    print(f"Protocol: {protocol}, Count : {count}")
