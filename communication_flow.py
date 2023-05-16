from scapy.all import *

# 통신 흐름을 저장할 딕셔너리
communication_flow = {}

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
        flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        if flow_key in communication_flow:
            communication_flow[flow_key] += 1
        else:
            communication_flow[flow_key] = 1

# UDP 및 TCP 패킷 캡처
sniff(filter="udp or tcp", prn=analyze_packet)

# 통신 흐름 출력
for flow, count in communication_flow.items():
    src_ip, src_port, dst_ip, dst_port, protocol = flow
    print(f"Flow: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Count: {count}")

