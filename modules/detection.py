import pandas as pd
from sklearn.ensemble import IsolationForest

KNOWN_REVIEW_PORTS = {23, 2323, 4444, 3389, 445}

def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Return review indicators; these are not confirmed attack classifications."""
    if df.empty:
        return pd.DataFrame(columns=["alert_type","severity","src_ip","dst_ip","reason","recommendation"])
    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")
    alerts = []

    # High per-source packet rate in one-minute windows.
    per_min = (work.dropna(subset=["timestamp"])
               .set_index("timestamp").groupby("src_ip").resample("1min").size()
               .rename("count").reset_index())
    for _, row in per_min[per_min["count"] >= 30].iterrows():
        alerts.append(dict(alert_type="High packet frequency", severity="Medium",
            src_ip=row["src_ip"], dst_ip="Multiple/unknown",
            reason=f"{int(row['count'])} packets from this source in one minute.",
            recommendation="Review the source, destination spread and expected application behaviour."))

    # Review known sensitive service ports without claiming maliciousness.
    port_hits = work[work["dst_port"].fillna(-1).astype(int).isin(KNOWN_REVIEW_PORTS)]
    for _, row in port_hits.head(25).iterrows():
        alerts.append(dict(alert_type="Service port for review", severity="Low",
            src_ip=row["src_ip"], dst_ip=row["dst_ip"],
            reason=f"Traffic observed to destination port {int(row['dst_port'])}; context is required.",
            recommendation="Confirm whether this service is expected and appropriately secured."))

    # DNS request volume per source in a one-minute window.
    dns = work[work["is_dns"].astype(bool)].dropna(subset=["timestamp"])
    if not dns.empty:
        dns_counts = dns.set_index("timestamp").groupby("src_ip").resample("1min").size().rename("count").reset_index()
        for _, row in dns_counts[dns_counts["count"] >= 20].iterrows():
            alerts.append(dict(alert_type="High DNS request frequency", severity="Medium",
                src_ip=row["src_ip"], dst_ip="DNS resolver",
                reason=f"{int(row['count'])} DNS packets from this source in one minute.",
                recommendation="Review queried domains and determine whether the request rate is expected."))

    syn = work[work["tcp_syn"].astype(bool)]
    if len(syn) >= 20:
        counts = syn["src_ip"].value_counts()
        for src, count in counts[counts >= 20].items():
            alerts.append(dict(alert_type="Elevated TCP SYN count", severity="Medium",
                src_ip=src, dst_ip="Multiple/unknown",
                reason=f"{int(count)} TCP SYN packets observed from this source.",
                recommendation="Review connection outcomes and destination distribution; SYN counts alone are inconclusive."))

    # Isolation Forest on per-source aggregate features; skip tiny datasets.
    if work["src_ip"].nunique() >= 8 and len(work) >= 30:
        features = work.groupby("src_ip").agg(
            packet_count=("packet_size","count"),
            mean_size=("packet_size","mean"),
            total_bytes=("packet_size","sum"),
            unique_destinations=("dst_ip","nunique"),
            unique_ports=("dst_port","nunique"),
        ).fillna(0)
        if len(features) >= 8:
            model = IsolationForest(contamination=0.08, random_state=42)
            labels = model.fit_predict(features)
            for src in features.index[labels == -1][:15]:
                alerts.append(dict(alert_type="Isolation Forest outlier", severity="Low",
                    src_ip=src, dst_ip="Multiple/unknown",
                    reason="This source's aggregate traffic profile differs from the majority in this capture.",
                    recommendation="Compare with normal baseline traffic before escalating."))

    result = pd.DataFrame(alerts, columns=["alert_type","severity","src_ip","dst_ip","reason","recommendation"])
    if not result.empty:
        result = result.drop_duplicates().reset_index(drop=True)
    return result
