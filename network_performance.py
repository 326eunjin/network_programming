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

def measure_network_performance(destination_ip, destination_port):
    # UDP 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # 응답 대기 시간 설정 (1초)

    # 송신 및 수신 시간 측정을 위한 변수 초기화
    num_packets = 10
    total_bytes_sent = 0
    total_time_elapsed = 0
    packets_received = 0

    for _ in range(num_packets):
        # 현재 시간 기록
        start_time = time.time()

        # UDP 패킷 송신
        sock.sendto(b"", (destination_ip, destination_port))

        # 수신 대기
        try:
            data, _ = sock.recvfrom(1024)
            packets_received += 1
        except socket.timeout:
            print("Packet loss")
            continue

        # 현재 시간 기록 및 송신-수신 시간 계산
        end_time = time.time()
        elapsed_time = end_time - start_time

        # 송신 및 수신 시간 업데이트
        total_bytes_sent += len(data)
        total_time_elapsed += elapsed_time

    if packets_received == 0:
        print("No packets received.")
        return

    # 네트워크 대역폭 및 평균 지연 시간 계산
    bandwidth = (total_bytes_sent * 8) / (total_time_elapsed * 1024 * 1024)
    avg_latency = (total_time_elapsed / packets_received) * 1000

    print(f"Average Bandwidth: {bandwidth} Mbps")
    print(f"Average Latency: {avg_latency} ms")

    # 소켓 닫기
    sock.close()

# 네트워크 성능 측정 대상 지정 (웹캠의 IP 주소와 포트 써줘)
destination_ip = "192.168.35.51"
destination_port = 554

# 네트워크 성능 평가 실행
measure_network_performance(destination_ip, destination_port)
