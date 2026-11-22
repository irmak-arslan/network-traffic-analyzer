
# 🛡️ NetScope — Network Traffic Analyzer

A Python-based network traffic analysis and security
monitoring application built with Scapy and Streamlit.

## Overview

NetScope analyzes PCAP files, visualizes network traffic,
and identifies potentially suspicious activity using
rule-based detection techniques.

The application provides an interactive dashboard for
exploring network packets and exporting analysis reports.

## Features

- PCAP file analysis
- TCP, UDP, and ICMP protocol identification
- Source and destination IP analysis
- Network traffic statistics
- High packet volume detection
- Potential TCP port scanning detection
- Configurable detection thresholds
- Interactive Streamlit dashboard
- Protocol and source IP filtering
- CSV packet export
- JSON security report export
- Automated testing with pytest

## Tech Stack

- Python
- Scapy
- Pandas
- Matplotlib
- Streamlit
- Pytest

## Installation

Clone the repository:

```bash
git clone https://github.com/irmak-arslan/network-traffic-analyzer.git
cd network-traffic-analyzer
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Generate synthetic sample traffic:

```bash
python generate_packets.py
```

Run the dashboard:

```bash
python -m streamlit run dashboard.py
```

Upload the generated `sample_traffic.pcap` file
to explore the application.

## Automated Testing

Run:

```bash
python -m pytest -v
```

## Security Detection

NetScope implements two rule-based detection methods:

1. High Packet Volume Detection
2. Potential TCP Port Scanning Detection

These detections are heuristic indicators and do not
confirm malicious activity.

## Privacy and Ethical Use

NetScope is intended for educational purposes and
authorized network traffic analysis.

Only analyze network captures you own or have explicit
permission to inspect.

## Author

Irmak Arslan

Software Engineering Student

GitHub: https://github.com/irmak-arslan
