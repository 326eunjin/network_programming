import nmap
from scapy.all import *

# 네트워크 스캐너를 사용하여 iot 기기의 IP 주소를 스캔
nm = nmap.PortScanner()
nm.scan("192.168.35.0/24")  # 네트워크 주소 범위 지정

# iot 기기의 IP 주소 선택
iot_ip = None
for host in nm.all_hosts():
    # iot 기기의 특정 포트 번호가 열려있는지 확인
    if nm[host].has_tcp(80) and nm[host]["tcp"][80]["state"] == "open":
        iot_ip = host
        break

if iot_ip is None:
    print("IoT 기기를 찾을 수 없습니다.")
else:
    print("IoT 기기의 IP 주소: ", iot_ip)


# Scapy를 사용하여 해당 IP 주소로 전송되는 패킷 스니핑
def handle_packet(packet):
    if packet.haslayer(TCP):
        # TCP 패킷 분석 코드 작성
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        length = packet[IP].len
        checksum = packet[IP].chksum
        data = packet[TCP].payload.load
        print(
            f"TCP packet: source={src}, source_port={sport}, destination={dst}, destination_port={dport}, length={length}, checksum={checksum}, data={data}"
        )

    if packet.haslayer(UDP):
        # UDP 패킷 분석 코드 작성
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        length = packet[IP].len
        checksum = packet[IP].chksum
        data = packet[UDP].payload.load
        print(
            f"UDP packet: source={src}, source_port={sport}, destination={dst}, destination_port={dport}, length={length}, checksum={checksum}, data={data}"
        )


if iot_ip:
    sniff(filter=f"host {iot_ip}", prn=handle_packet)
