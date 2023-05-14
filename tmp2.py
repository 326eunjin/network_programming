import nmap
from scapy.all import *
import os
import cv2
import numpy as np
from playsound import playsound


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


# 카메라 캡처 객체 생성
cap = cv2.VideoCapture(0)

# 이전 프레임 초기화
# 이전 프레임 초기화
initial_frame = None
_, prev_frame = cap.read()

# 모션 감지 임계값 설정
threshold = 5000

# 모션 감지 여부 변수 초기화
motion_detected = False

while True:
    # 비디오 캡처
    ret, frame = cap.read()

    # 현재 프레임과 이전 프레임 비교를 위해 회색조 변환 후 가우시안 블러 적용
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (21, 21), 0)

    # 이전 프레임과 현재 프레임 비교를 위해 초기 프레임 설정
    if initial_frame is None:
        initial_frame = gray
        continue

    # 현재 프레임과 초기 프레임의 차이 계산
    frame_diff = cv2.absdiff(initial_frame, gray)

    # 차이 이미지 이진화
    thresh = cv2.threshold(frame_diff, threshold, 255, cv2.THRESH_BINARY)[1]

    # 이진화 이미지에서 컨투어 찾기
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    # 컨투어가 하나라도 발견되면 모션 감지 여부 변수를 True로 설정
    if len(contours) > 0:
        motion_detected = True
    else:
        motion_detected = False

    # 모션 감지 여부에 따라 소리 출력
    if motion_detected != previous_motion_detected:
        if motion_detected:
            print("Motion Detected!")
            # 소리 재생 코드 추가
        else:
            print("Motion Stopped.")
            # 소리 중지 코드 추가

    # 현재 프레임을 이전 프레임으로 설정
    initial_frame = gray.copy()

    # 이전 모션 감지 여부 변수를 현재 값으로 업데이트
    previous_motion_detected = motion_detected
