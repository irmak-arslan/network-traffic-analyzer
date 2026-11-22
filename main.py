
# Network Traffic Analyzer
# Developed by Irmak Arslan

from visualization import create_visualizations
from security import detect_suspicious_traffic
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def get_protocol(packet):
    """Identify the network protocol."""

    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "OTHER"


def analyze_traffic(file_path):
    """Analyze packets from a PCAP file."""

    packets = rdpcap(file_path)

    protocol_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()

    print("=" * 50)
    print("NETWORK TRAFFIC ANALYZER")
    print("=" * 50)

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = get_protocol(packet)

        protocol_counts[protocol] += 1
        source_ips[source_ip] += 1
        destination_ips[destination_ip] += 1

    print(f"\nTotal captured packets: {len(packets)}")
    print(f"IPv4 packets analyzed: {sum(protocol_counts.values())}")

    print("\n--- PROTOCOL DISTRIBUTION ---")

    for protocol, count in protocol_counts.most_common():
        print(f"{protocol}: {count} packets")

    print("\n--- TOP SOURCE IP ADDRESSES ---")

    for ip, count in source_ips.most_common(5):
        print(f"{ip}: {count} packets")

    print("\n--- TOP DESTINATION IP ADDRESSES ---")

    for ip, count in destination_ips.most_common(5):
        print(f"{ip}: {count} packets")


    print("\n--- SECURITY ANALYSIS ---")

    alerts = detect_suspicious_traffic(packets)

    if not alerts:
        print("No suspicious traffic patterns detected.")
    else:
        print(f"Total security alerts: {len(alerts)}")

        for index, alert in enumerate(alerts, start=1):
            print(f"\nAlert #{index}")
            print(f"Type: {alert['type']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Severity: {alert['severity']}")
            print(f"Details: {alert['details']}")
            print("-" * 50)

        create_visualizations(
        protocol_counts,
        source_ips,
        alerts
    )
        print("\nAnalysis completed successfully!")


def main():
    analyze_traffic("sample_traffic.pcap")


if __name__ == "__main__":
    main()
