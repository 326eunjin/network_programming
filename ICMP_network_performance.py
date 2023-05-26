import socket
import time
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

destination_port = 554

def measure_network_performance(destination_ip, destination_port):
    # ICMP Echo Request/Reply를 위한 RAW 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(1.0)  # 응답 대기 시간 설정 (1초)

    # 송신 및 수신 시간 측정을 위한 변수 초기화
    num_packets = 10
    packets_sent = 0
    packets_received = 0
    packets_lost = 0
    total_rtt = 0

    try:
        for _ in range(num_packets):
            # ICMP Echo Request 메시지 생성
            icmp_request = b"\x08\x00\x00\x00\x00\x01\x00\x00"

            # 현재 시간 기록
            start_time = time.time()

            # ICMP Echo Request 메시지 송신
            sock.sendto(icmp_request, (destination_ip, 0))
            packets_sent += 1

            # 수신 대기
            try:
                data, address = sock.recvfrom(1024)
                end_time = time.time()
                elapsed_time = end_time - start_time
                packets_received += 1
                total_rtt += elapsed_time * 1000
            except socket.timeout:
                packets_lost += 1
                print("Packet loss")
                continue

    except socket.error as e:
        print(f"Socket error: {e}")
        return

    if packets_received == 0:
        print("No packets received.")
        return

    # 패킷 손실률, 평균 RTT 계산
    packet_loss_rate = (packets_lost / num_packets) * 100
    avg_rtt = total_rtt / packets_received

    print(f"Packets Lost: {packets_lost}/{num_packets}")
    print(f"Packet Loss Rate: {packet_loss_rate}%")
    print(f"Average RTT: {avg_rtt} ms")

    # 소켓 닫기
    sock.close()

# 네트워크 성능 평가 실행
for ip_address in scanned_ips:
    measure_network_performance(ip_address, destination_port)

