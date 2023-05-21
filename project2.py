import sys
import nmap
import time
from scapy.all import *

packet_count = 0

nm = nmap.PortScanner() # 네트워크 스캐너를 사용하여 iot 기기의 IP 주소를 스캔
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

def handle_packet(packet):
    global packet_count
    if packet.haslayer(TCP):
        # TCP 패킷 분석 코드 작성
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        length = packet[IP].len
        checksum = packet[IP].chksum
        data = packet[TCP].payload.load
        print(f"TCP packet: source={src}, source_port={sport}, destination={dst}, destination_port={dport}, length={length}, checksum={checksum}, data={data}")
        packet_count += 1 # 패킷 개수 증가

    if packet.haslayer(UDP):
        # UDP 패킷 분석 코드 작성
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        length = packet[IP].len
        checksum = packet[IP].chksum
        data = packet[UDP].payload.load
        print(f"UDP packet: source={src}, source_port={sport}, destination={dst}, destination_port={dport}, length={length}, checksum={checksum}, data={data}")
        packet_count += 1 # 패킷 개수 증가

sniffingTime = input("Sniffing Time: ") # 몇 초간 패킷 캡쳐할 것인지
if iot_ip:
    print("프로그램 시작")
    pcap_file = sniff(prn=handle_packet, timeout=int(sniffingTime), filter=f"host {iot_ip}")
    print("Finish Capture Packet")
    if packet_count == 0: # 아무 패킷도 캡쳐되지 않음
        print("No Packet")
        sys.exit()
    else:
        print("Total Packet: %s" % packet_count)
        print("Packets per second: %.2f" % packet_count/sniffingTime)
        file_name = input("Enter File Name: ")
        wrpcap(str(file_name), pcap_file) # pcap 파일로 저장

else:
    print("프로그램을 실행할 수 없습니다.")