import streamlit as st
import pandas as pd
import plotly.express as px
from config import APP_TITLE, PAGE_NAMES
from modules.analyzer import analyze_upload, load_sample_data
from modules.detection import detect_anomalies
from modules.reports import build_pdf_report

st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background: linear-gradient(135deg,#07111f 0%,#0b1728 60%,#101d32 100%); color:#e7f1ff;}
[data-testid="stSidebar"] {background:#081321;}
.metric-card {background:#10243a;border:1px solid #1b4968;padding:16px;border-radius:12px;}
h1,h2,h3 {color:#d9f4ff;}
div[data-testid="stMetric"] {background:#10243a;border:1px solid #1b4968;padding:14px;border-radius:12px;}
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ NetGuard")
st.sidebar.caption("Network Traffic Analysis")
page = st.sidebar.radio("Navigation", PAGE_NAMES)
st.sidebar.divider()
st.sidebar.caption("Defensive analysis of uploaded captures or safe sample data.")

if "traffic" not in st.session_state:
    st.session_state.traffic = None
if "source_name" not in st.session_state:
    st.session_state.source_name = "No dataset loaded"

def load_data(df, name):
    st.session_state.traffic = df
    st.session_state.source_name = name
    st.session_state.alerts = detect_anomalies(df)

def require_data():
    if st.session_state.traffic is None:
        st.warning("No traffic data loaded. Upload a capture or load the included sample dataset.")
        return False
    return True

st.sidebar.subheader("Data source")
if st.sidebar.button("Load safe sample dataset", use_container_width=True):
    load_data(load_sample_data(), "Built-in synthetic sample")
    st.sidebar.success("Sample data loaded.")
st.sidebar.caption(f"Current source: {st.session_state.source_name}")

if page == "Home Dashboard":
    st.title("🛡️ Network Security Dashboard")
    st.write("Inspect network metadata, review unusual patterns, and export a defensive analysis report.")
    if st.session_state.traffic is None:
        st.info("Start by loading the safe sample dataset from the sidebar or uploading a PCAP/PCAPNG file.")
    else:
        df = st.session_state.traffic
        alerts = st.session_state.get("alerts", pd.DataFrame())
        suspicious = len(alerts)
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Packets analyzed", f"{len(df):,}")
        c2.metric("Unique conversations", f"{df['connection'].nunique():,}")
        c3.metric("Potential alerts", f"{suspicious:,}")
        c4.metric("Anomalous time windows", f"{df['is_anomaly'].sum():,}" if "is_anomaly" in df else "—")
        st.subheader("Traffic overview")
        if "timestamp" in df and len(df):
            timeline = df.set_index("timestamp").resample("1min").size().reset_index(name="packets")
            st.plotly_chart(px.area(timeline, x="timestamp", y="packets", title="Packets per minute",
                                    color_discrete_sequence=["#20c5d8"]), use_container_width=True)
        left,right = st.columns(2)
        with left:
            st.plotly_chart(px.pie(df, names="protocol", title="Protocol distribution",
                                   color_discrete_sequence=px.colors.sequential.Teal), use_container_width=True)
        with right:
            top = df["src_ip"].value_counts().head(8).rename_axis("Source IP").reset_index(name="Packets")
            st.plotly_chart(px.bar(top, x="Source IP", y="Packets", title="Top source addresses",
                                   color="Packets", color_continuous_scale="Teal"), use_container_width=True)
        st.caption("An alert is a review signal, not proof of malicious activity.")

elif page == "Upload Network Traffic":
    st.title("📂 Upload Network Traffic")
    st.write("Upload a packet capture for offline metadata extraction. Files are processed in memory and are not saved by this app.")
    upload = st.file_uploader("Choose a PCAP or PCAPNG file", type=["pcap","pcapng"])
    if upload is not None and st.button("Analyze uploaded capture", type="primary"):
        try:
            with st.spinner("Reading packet metadata..."):
                df = analyze_upload(upload.getvalue(), upload.name)
                load_data(df, upload.name)
            st.success(f"Analyzed {len(df):,} packets from {upload.name}.")
        except Exception as exc:
            st.error(f"Could not analyze this capture: {exc}")
            st.caption("Check that the file is a valid PCAP/PCAPNG capture and is not empty.")
    st.info("For a quick demonstration, use **Load safe sample dataset** in the sidebar. No live capture or administrator access is needed.")

elif page == "Traffic Analysis":
    st.title("📡 Traffic Analysis")
    if require_data():
        df = st.session_state.traffic
        st.subheader("Packet metadata")
        st.dataframe(df.drop(columns=["connection"], errors="ignore"), use_container_width=True, hide_index=True)
        a,b = st.columns(2)
        with a:
            proto = df["protocol"].value_counts().rename_axis("Protocol").reset_index(name="Count")
            st.plotly_chart(px.bar(proto, x="Protocol", y="Count", title="Packets by protocol"), use_container_width=True)
        with b:
            ports = df["dst_port"].fillna(0).astype(int).value_counts().head(10).rename_axis("Destination port").reset_index(name="Count")
            st.plotly_chart(px.bar(ports, x="Destination port", y="Count", title="Top destination ports"), use_container_width=True)
        st.download_button("Download packet metadata CSV", df.to_csv(index=False).encode("utf-8"),
                           "packet_metadata.csv", "text/csv")

elif page == "Anomaly Detection":
    st.title("🔎 Anomaly Detection")
    if require_data():
        df = st.session_state.traffic
        alerts = st.session_state.get("alerts", pd.DataFrame())
        st.write("Rule-based indicators and an Isolation Forest model identify patterns that may deserve investigation.")
        st.metric("Potential anomaly records", len(alerts))
        if not alerts.empty:
            st.dataframe(alerts, use_container_width=True, hide_index=True)
            st.download_button("Download anomaly results", alerts.to_csv(index=False).encode("utf-8"),
                               "anomaly_results.csv", "text/csv")
        else:
            st.success("No configured indicators were triggered in this dataset.")
        st.caption("Isolation Forest labels unusual feature combinations; it does not identify a specific attacker or confirm an incident.")

elif page == "Security Alerts":
    st.title("🚨 Security Alerts")
    if require_data():
        alerts = st.session_state.get("alerts", pd.DataFrame())
        if alerts.empty:
            st.success("No potential alerts in the current dataset.")
        else:
            for _, alert in alerts.iterrows():
                with st.container(border=True):
                    st.markdown(f"**{alert['alert_type']}** · `{alert['severity']}`")
                    st.write(f"Source: `{alert['src_ip']}` → Destination: `{alert['dst_ip']}`")
                    st.write(alert["reason"])
                    st.info("Suggested defensive action: " + alert["recommendation"])
            st.download_button("Export alerts CSV", alerts.to_csv(index=False).encode("utf-8"),
                               "security_alerts.csv", "text/csv")

elif page == "Generate Reports":
    st.title("📄 Generate Reports")
    if require_data():
        df = st.session_state.traffic
        alerts = st.session_state.get("alerts", pd.DataFrame())
        st.write("Create a summary for documentation and defensive review.")
        st.download_button("Download full analysis CSV", df.to_csv(index=False).encode("utf-8"),
                           "network_analysis.csv", "text/csv")
        st.download_button("Download alerts CSV", alerts.to_csv(index=False).encode("utf-8"),
                           "network_alerts.csv", "text/csv")
        pdf = build_pdf_report(df, alerts, st.session_state.source_name)
        st.download_button("Download PDF summary", pdf, "network_security_report.pdf", "application/pdf")

elif page == "About Project":
    st.title("ℹ️ About NetGuard")
    st.markdown("""
**Network Traffic Analysis and Anomaly Detection System** is a defensive learning tool for a Cyber Analyst course.

**What it does**
- Reads offline PCAP/PCAPNG captures supplied by the user.
- Extracts basic packet metadata (addresses, protocol, ports, size and timestamp).
- Highlights unusual traffic patterns using transparent rules and an optional unsupervised model.
- Exports results for further investigation.

**Important limitations**
- This is not an intrusion prevention system and does not block traffic.
- A flagged pattern is not proof of an attack.
- Encrypted payload contents are not inspected.
- Results depend on capture quality, traffic volume and configured thresholds.
- Only analyze captures you are authorized to use.
""")
    st.subheader("Protocol coverage")
    st.write("IPv4/IPv6 metadata, TCP, UDP, ICMP and DNS indicators where packet layers are available.")
