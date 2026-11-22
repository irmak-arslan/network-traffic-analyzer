
# Network Traffic Analyzer
# Data Visualization Module
# Developed by Irmak Arslan

from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


def create_visualizations(
    protocol_counts,
    source_ips,
    alerts
):
    """Generate charts from network traffic analysis."""

    output_dir = Path("charts")
    output_dir.mkdir(exist_ok=True)

    # 1. Protocol distribution
    if protocol_counts:
        plt.figure(figsize=(8, 6))

        plt.pie(
            protocol_counts.values(),
            labels=protocol_counts.keys(),
            autopct="%1.1f%%",
            startangle=90
        )

        plt.title("Network Protocol Distribution")
        plt.tight_layout()
        plt.savefig(
            output_dir / "protocol_distribution.png",
            dpi=150
        )
        plt.close()

    # 2. Top source IP addresses
    top_sources = source_ips.most_common(5)

    if top_sources:
        ips, counts = zip(*top_sources)

        plt.figure(figsize=(10, 6))
        plt.bar(ips, counts)

        plt.title("Top 5 Source IP Addresses")
        plt.xlabel("Source IP Address")
        plt.ylabel("Number of Packets")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()

        plt.savefig(
            output_dir / "top_source_ips.png",
            dpi=150
        )
        plt.close()

    # 3. Security alert severity
    if alerts:
        severity_counts = Counter(
            alert["severity"] for alert in alerts
        )

        plt.figure(figsize=(8, 5))
        plt.bar(
            severity_counts.keys(),
            severity_counts.values()
        )

        plt.title("Security Alerts by Severity")
        plt.xlabel("Severity")
        plt.ylabel("Number of Alerts")
        plt.tight_layout()

        plt.savefig(
            output_dir / "security_alerts.png",
            dpi=150
        )
        plt.close()

    print("\nCharts generated successfully!")
    print(f"Saved to: {output_dir.resolve()}")
