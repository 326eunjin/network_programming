import socket
import time

def measure_network_performance(destination_ip, destination_port):
    # UDP 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # 응답 대기 시간 설정 (1초)

    # 송신 및 수신 시간 측정을 위한 변수 초기화
    num_packets = 10
    total_bytes_sent = 0
    total_time_elapsed = 0

    for _ in range(num_packets):
        # 현재 시간 기록
        start_time = time.time()

        # UDP 패킷 송신
        sock.sendto(b"", (destination_ip, destination_port))

        # 수신 대기
        try:
            data, _ = sock.recvfrom(1024)
        except socket.timeout:
            print("Packet loss")
            continue

        # 현재 시간 기록 및 송신-수신 시간 계산
        end_time = time.time()
        elapsed_time = end_time - start_time

        # 송신 및 수신 시간 업데이트
        total_bytes_sent += len(data)
        total_time_elapsed += elapsed_time

    # 네트워크 대역폭 및 평균 지연 시간 계산
    bandwidth = (total_bytes_sent * 8) / (total_time_elapsed * 1024 * 1024)
    avg_latency = (total_time_elapsed / num_packets) * 1000

    print(f"Average Bandwidth: {bandwidth} Mbps")
    print(f"Average Latency: {avg_latency} ms")

    # 소켓 닫기
    sock.close()

# 네트워크 성능 측정 대상 지정 (웹캠의 IP 주소와 포트 써줘)
destination_ip = 
destination_port = 

# 네트워크 성능 평가 실행
measure_network_performance(destination_ip, destination_port)

