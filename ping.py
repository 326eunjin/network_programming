import subprocess
import re

def measure_network_performance(destination):
    try:
        # ping 명령 실행
        ping_process = subprocess.Popen(["ping", "-c", "10", "-i", "0.2", destination], stdout=subprocess.PIPE)
        output, _ = ping_process.communicate()

        # 평균 대역폭 및 평균 지연 시간 추출
        bandwidth = re.search(r"(\d+\.\d+)\s+packet loss", output.decode())
        latency = re.search(r"(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)\s+ms", output.decode())

        if bandwidth and latency:
            avg_bandwidth = bandwidth.group(1)
            avg_latency = latency.group(2)
            print(f"Average Bandwidth: {avg_bandwidth} Mbps")
            print(f"Average Latency: {avg_latency} ms")
        else:
            print("Failed to measure network performance.")

    except Exception as e:
        print("An error occurred:", str(e))

# 네트워크 성능 측정 대상 지정 (웹캠 ip 주소 넣으셈)
destination = 


# 네트워크 성능 평가 실행
measure_network_performance(destination)

