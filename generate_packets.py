
# Network Traffic Analyzer
# Sample Packet Generator
# Developed by Irmak Arslan

from scapy.all import IP, TCP, UDP, ICMP, wrpcap

packets = [
    IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=12345, dport=80),

    IP(src="192.168.1.15", dst="8.8.8.8") /
    UDP(sport=54321, dport=53),

    IP(src="192.168.1.20", dst="192.168.1.10") /
    ICMP(type=8),

    IP(src="192.168.1.10", dst="192.168.1.30") /
    TCP(sport=23456, dport=443),

    IP(src="192.168.1.25", dst="192.168.1.1") /
    UDP(sport=34567, dport=123)
]

# Simulate unusual traffic from one source IP.
# Packets are saved to a file, not sent to a network.
suspicious_ip = "192.168.1.50"

for port in range(20, 30):
    packet = (
        IP(src=suspicious_ip, dst="192.168.1.100") /
        TCP(sport=40000 + port, dport=port, flags="S")
    )
    packets.append(packet)

# Add more packets from the same IP.
for _ in range(5):
    packets.append(
        IP(src=suspicious_ip, dst="192.168.1.100") /
        UDP(sport=50000, dport=53)
    )

wrpcap("sample_traffic.pcap", packets)

print("Sample PCAP file created successfully!")
print(f"Total packets generated: {len(packets)}")
