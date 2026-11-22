
# NetScope - Network Traffic Analyzer
# Automated Security Tests
# Developed by Irmak Arslan

from scapy.all import IP, TCP, UDP, ICMP

from main import get_protocol
from security import detect_suspicious_traffic


def test_tcp_protocol():
    packet = IP() / TCP()
    assert get_protocol(packet) == "TCP"


def test_udp_protocol():
    packet = IP() / UDP()
    assert get_protocol(packet) == "UDP"


def test_icmp_protocol():
    packet = IP() / ICMP()
    assert get_protocol(packet) == "ICMP"


def test_high_packet_volume():
    packets = [
        IP(src="192.168.1.50", dst="192.168.1.100")
        / UDP(dport=53)
        for _ in range(15)
    ]

    alerts = detect_suspicious_traffic(packets)

    assert any(
        alert["type"] == "High Packet Volume"
        for alert in alerts
    )


def test_port_scanning_detection():
    packets = [
        IP(src="192.168.1.50", dst="192.168.1.100")
        / TCP(dport=port, flags="S")
        for port in range(20, 30)
    ]

    alerts = detect_suspicious_traffic(packets)

    assert any(
        alert["type"] == "Possible Port Scanning"
        for alert in alerts
    )


def test_normal_traffic():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(dport=80, flags="S"),

        IP(src="192.168.1.15", dst="8.8.8.8")
        / UDP(dport=53)
    ]

    alerts = detect_suspicious_traffic(packets)

    assert len(alerts) == 0


def test_custom_packet_threshold():
    packets = [
        IP(src="192.168.1.50", dst="192.168.1.100")
        / UDP(dport=53)
        for _ in range(8)
    ]

    alerts = detect_suspicious_traffic(
        packets,
        packet_threshold=5
    )

    assert any(
        alert["type"] == "High Packet Volume"
        for alert in alerts
    )


def test_custom_port_threshold():
    packets = [
        IP(src="192.168.1.50", dst="192.168.1.100")
        / TCP(dport=port, flags="S")
        for port in range(20, 24)
    ]

    alerts = detect_suspicious_traffic(
        packets,
        port_threshold=3
    )

    assert any(
        alert["type"] == "Possible Port Scanning"
        for alert in alerts
    )
