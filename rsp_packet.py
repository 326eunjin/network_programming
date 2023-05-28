from scapy.all import *

# Define the source and destination IP addresses
src_ip = "192.168.35.136"
dst_ip = "192.168.35.51"

# Define the source and destination ports
src_port = 3306
dst_port = 554

# Define the RTP payload data
payload_data = b"\x80\x00\x00\x00"  # Replace with your actual RTP payload

# Craft an RTP packet
rtp_packet = (
    IP(src=src_ip, dst=dst_ip)
    / UDP(sport=src_port, dport=dst_port)
    / Raw(load=payload_data)
)

# Send the packet multiple times
for _ in range(15):
    send(rtp_packet)
