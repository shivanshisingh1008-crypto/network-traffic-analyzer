import pandas as pd
from modules.detection import detect_anomalies

def test_empty_dataframe_returns_empty_alerts():
    result = detect_anomalies(pd.DataFrame())
    assert result.empty

def test_high_frequency_source_is_flagged():
    times = pd.date_range("2026-01-01", periods=35, freq="s")
    df = pd.DataFrame({
        "timestamp": times, "src_ip": ["192.0.2.10"]*35,
        "dst_ip": ["198.51.100.2"]*35, "protocol": ["TCP"]*35,
        "src_port": [50000]*35, "dst_port": [443]*35,
        "packet_size": [500]*35, "tcp_syn": [False]*35,
        "is_dns": [False]*35, "connection": ["sample"]*35
    })
    result = detect_anomalies(df)
    assert "High packet frequency" in result["alert_type"].values
