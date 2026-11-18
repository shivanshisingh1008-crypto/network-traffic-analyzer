# NetGuard — Network Traffic Analysis and Anomaly Detection

A defensive learning application for offline PCAP/PCAPNG metadata analysis. It extracts packet metadata, visualizes traffic, flags unusual patterns for review, and exports CSV/PDF reports.

## Features
- PCAP and PCAPNG upload (offline; no live capture)
- IPv4/IPv6 addresses, protocol, ports, packet length and timestamp extraction
- TCP/UDP/ICMP/DNS traffic summaries
- Transparent review rules and Isolation Forest outlier flagging
- Dashboard, traffic charts, alert review and CSV/PDF downloads
- Included synthetic sample traffic for demonstrations

## Requirements
Python 3.10–3.12 is recommended. Install packages:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Run locally

```bash
streamlit run app.py
```

Choose **Load safe sample dataset** in the sidebar, or upload a capture you are authorized to analyze.

## Deploy to Streamlit Community Cloud
1. Create a GitHub repository and upload the complete contents of this project.
2. Visit https://share.streamlit.io/ and sign in with GitHub.
3. Select **Create app**, choose the repository and branch, and set the main file path to `app.py`.
4. Deploy. Streamlit installs packages from `requirements.txt`.
5. Open the app URL and load the included sample dataset to smoke-test it.

No secrets or API keys are required. The app uses relative paths and processes uploaded capture bytes in memory.

## Project structure

```text
network_traffic_analyzer/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── detection.py
│   └── reports.py
├── sample_data/
│   └── sample_traffic.csv
├── tests/
│   └── test_detection.py
└── assets/
```

## Detection notes and limitations
- High packet/DNS rates, selected service ports, TCP SYN counts and Isolation Forest outliers are review indicators, not confirmed attacks.
- Thresholds are intentionally simple teaching defaults and should be tuned to the network being studied.
- Payload contents are not inspected; encrypted traffic is not decrypted.
- Only analyze network captures that you own or are explicitly authorized to examine.
- The sample dataset is synthetic and must not be presented as real incident evidence.

## Troubleshooting
- If package installation fails, use a supported Python version (3.10–3.12) and retry in a fresh virtual environment.
- PCAP uploads must be valid PCAP/PCAPNG files and contain IPv4 or IPv6 packets.
- For large captures, begin with a smaller filtered capture to stay within hosting memory limits.
