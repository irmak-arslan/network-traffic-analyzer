
# Network Traffic Analyzer
# Professional Security Dashboard
# Developed by Irmak Arslan

from collections import Counter
from io import BytesIO

import pandas as pd
import streamlit as st
from scapy.all import IP, TCP, UDP, ICMP, rdpcap

from security import detect_suspicious_traffic


# PAGE CONFIGURATION
st.set_page_config(
    page_title="NetScope | Network Traffic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# CUSTOM STYLING
st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }

    .main-title {
        font-size: 2.4rem;
        font-weight: 750;
        color: #F1F5F9;
        margin-bottom: 0.2rem;
    }

    .subtitle {
        color: #94A3B8;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    .metric-card {
        background: #172338;
        border: 1px solid #283850;
        border-radius: 14px;
        padding: 22px;
        margin-bottom: 12px;
    }

    .metric-label {
        color: #94A3B8;
        font-size: 0.85rem;
        margin-bottom: 8px;
    }

    .metric-value {
        color: #F1F5F9;
        font-size: 2.1rem;
        font-weight: 700;
    }

    .section-heading {
        color: #E2E8F0;
        font-size: 1.25rem;
        font-weight: 650;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }

    .security-card {
        background: #172338;
        border: 1px solid #283850;
        border-left: 4px solid #F59E0B;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 12px;
    }

    .high-risk {
        border-left-color: #EF4444;
    }

    .medium-risk {
        border-left-color: #F59E0B;
    }

    .risk-label {
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05rem;
    }
</style>
""", unsafe_allow_html=True)


# SIDEBAR
with st.sidebar:
    st.title("🛡️ NetScope")
    st.caption("Network Security Analytics")

    st.divider()

    st.subheader("Traffic Analysis")

    uploaded_file = st.file_uploader(
        "Upload PCAP File",
        type=["pcap", "cap"]
    )

    st.divider()

    st.subheader("Detection Rules")

    packet_threshold = st.slider(
        "Packet Volume Threshold",
        min_value=5,
        max_value=100,
        value=10
    )

    port_threshold = st.slider(
        "Distinct TCP Port Threshold",
        min_value=3,
        max_value=30,
        value=5
    )

    st.divider()

    st.caption("Developed by Irmak Arslan")
    st.caption("Python • Scapy • Streamlit")


# MAIN HEADER
st.markdown(
    '<div class="main-title">Network Security Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Analyze network traffic and identify potential security findings.'
    '</div>',
    unsafe_allow_html=True
)


# DATA PROCESSING
if uploaded_file is not None:

    try:
        packets = rdpcap(BytesIO(uploaded_file.getvalue()))

    except Exception:
        st.error(
            "Unable to read this file. "
            "Please upload a valid PCAP capture."
        )
        st.stop()

    protocol_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    packet_data = []

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        protocol_counts[protocol] += 1
        source_ips[source_ip] += 1
        destination_ips[destination_ip] += 1

        packet_data.append({
            "Source IP": source_ip,
            "Destination IP": destination_ip,
            "Protocol": protocol,
            "Packet Size": len(packet)
        })

    alerts = detect_suspicious_traffic(
        packets,
        packet_threshold=packet_threshold,
        port_threshold=port_threshold
    )

    st.caption(
        f"Analysis completed • File: {uploaded_file.name}"
    )

    # METRIC CARDS
    st.markdown(
        '<div class="section-heading">Traffic Overview</div>',
        unsafe_allow_html=True
    )

    total_packets = len(packets)
    total_protocols = len(protocol_counts)
    total_sources = len(source_ips)
    total_alerts = len(alerts)

    metrics = [
        ("TOTAL PACKETS", total_packets),
        ("PROTOCOLS", total_protocols),
        ("SOURCE IPs", total_sources),
        ("SECURITY ALERTS", total_alerts)
    ]

    columns = st.columns(4)

    for column, (label, value) in zip(columns, metrics):
        with column:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.divider()

    # TRAFFIC CHARTS
    st.markdown(
        '<div class="section-heading">Traffic Analytics</div>',
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Protocol Distribution")

        if protocol_counts:
            protocol_df = pd.DataFrame(
                protocol_counts.items(),
                columns=["Protocol", "Packets"]
            ).set_index("Protocol")

            st.bar_chart(
                protocol_df,
                horizontal=True
            )
        else:
            st.info("No IPv4 traffic available.")

    with col2:
        st.subheader("Top Source IP Addresses")

        if source_ips:
            source_df = pd.DataFrame(
                source_ips.most_common(5),
                columns=["Source IP", "Packets"]
            ).set_index("Source IP")

            st.bar_chart(
                source_df,
                horizontal=True
            )
        else:
            st.info("No source IP addresses available.")

    st.divider()

    # SECURITY FINDINGS
    st.markdown(
        '<div class="section-heading">Security Findings</div>',
        unsafe_allow_html=True
    )

    if alerts:

        st.warning(
            f"{len(alerts)} potential security findings detected."
        )

        for alert in alerts:

            severity = alert["severity"]
            risk_class = (
                "high-risk"
                if severity == "High"
                else "medium-risk"
            )

            st.markdown(
                f"""
                <div class="security-card {risk_class}">
                    <strong>{alert['type']}</strong>
                    <p>Source IP: {alert['source_ip']}</p>
                    <span class="risk-label">
                        {severity.upper()} RISK
                    </span>
                    <p>{alert['details']}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

    else:
        st.success("No suspicious patterns detected.")

    st.caption(
        "Security findings are heuristic indicators, "
        "not confirmed attacks."
    )

    st.divider()

    
    # PACKET EXPLORER
    st.markdown(
        '<div class="section-heading">Packet Explorer</div>',
        unsafe_allow_html=True
    )

    if packet_data:
        packet_df = pd.DataFrame(packet_data)

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            protocol_filter = st.selectbox(
                "Filter by Protocol",
                ["ALL", "TCP", "UDP", "ICMP", "OTHER"]
            )

        with filter_col2:
            source_filter = st.selectbox(
                "Filter by Source IP",
                ["ALL"] + sorted(source_ips.keys())
            )

        filtered_df = packet_df.copy()

        if protocol_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["Protocol"] == protocol_filter
            ]

        if source_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["Source IP"] == source_filter
            ]

        st.caption(
            f"Showing {len(filtered_df)} "
            f"of {len(packet_df)} IPv4 packets"
        )

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No IPv4 packet details available.")

    # REPORT EXPORT
    st.divider()

    st.markdown(
        '<div class="section-heading">Export Reports</div>',
        unsafe_allow_html=True
    )

    st.caption(
        "Download filtered packet data or "
        "the complete security analysis."
    )

    report = {
        "project": "NetScope Network Traffic Analyzer",
        "capture_file": uploaded_file.name,
        "total_packets": len(packets),
        "analyzed_ipv4_packets": len(packet_data),
        "protocol_distribution": dict(protocol_counts),
        "top_source_ips": dict(
            source_ips.most_common(5)
        ),
        "detection_thresholds": {
            "packet_threshold": packet_threshold,
            "port_threshold": port_threshold
        },
        "security_alerts": alerts,
        "note": (
            "Heuristic security findings are not "
            "confirmed cyberattacks."
        )
    }

    import json

    json_report = json.dumps(
        report,
        indent=4
    )

    if packet_data:
        csv_report = filtered_df.to_csv(index=False)
    else:
        csv_report = pd.DataFrame(
            columns=[
                "Source IP",
                "Destination IP",
                "Protocol",
                "Packet Size"
            ]
        ).to_csv(index=False)

    export_col1, export_col2 = st.columns(2)

    with export_col1:
        st.download_button(
            label="Download Packet Data (CSV)",
            data=csv_report,
            file_name="netscope_packets.csv",
            mime="text/csv",
            use_container_width=True
        )

    with export_col2:
        st.download_button(
            label="Download Security Report (JSON)",
            data=json_report,
            file_name="netscope_security_report.json",
            mime="application/json",
            use_container_width=True
        )

else:
    st.info(
        "Upload a PCAP file from the sidebar to start analysis."
    )


