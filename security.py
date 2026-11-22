
# Network Traffic Analyzer
# Security Detection Module
# Developed by Irmak Arslan

from collections import Counter, defaultdict
from scapy.all import IP, TCP


def detect_suspicious_traffic(
    packets,
    packet_threshold=10,
    port_threshold=5
):
    """
    Detect potentially unusual traffic patterns.

    These are heuristic alerts, not proof of attacks.
    """

    source_counts = Counter()
    destination_ports = defaultdict(set)
    syn_ports = defaultdict(set)

    for packet in packets:
        if IP not in packet:
            continue

        source_ip = packet[IP].src
        source_counts[source_ip] += 1

        if TCP in packet:
            destination_port = packet[TCP].dport
            destination_ports[source_ip].add(
                destination_port
            )

            # SYN set, ACK not set: initial TCP attempt.
            flags = int(packet[TCP].flags)

            if flags & 0x02 and not flags & 0x10:
                syn_ports[source_ip].add(
                    destination_port
                )

    alerts = []

    for ip, count in source_counts.items():
        if count > packet_threshold:
            alerts.append({
                "type": "High Packet Volume",
                "source_ip": ip,
                "severity": "Medium",
                "details": (
                    f"{count} packets observed "
                    f"(threshold: {packet_threshold})"
                )
            })

    for ip, ports in syn_ports.items():
        if len(ports) >= port_threshold:
            alerts.append({
                "type": "Possible Port Scanning",
                "source_ip": ip,
                "severity": "High",
                "details": (
                    f"SYN packets targeting "
                    f"{len(ports)} distinct TCP ports"
                )
            })

    return alerts
