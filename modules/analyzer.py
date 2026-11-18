from io import BytesIO
import pandas as pd
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from datetime import datetime, timezone

COLUMNS = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
           "packet_size", "tcp_syn", "is_dns", "connection"]

def _protocol(packet):
    if packet.haslayer(TCP): return "TCP"
    if packet.haslayer(UDP): return "DNS" if packet.haslayer(DNS) else "UDP"
    if packet.haslayer(ICMP): return "ICMP"
    if packet.haslayer(DNS): return "DNS"
    return "OTHER"

def _packet_row(packet):
    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip_layer is None:
        return None
    src, dst = str(ip_layer.src), str(ip_layer.dst)
    sport = dport = None
    if packet.haslayer(TCP):
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
    proto = _protocol(packet)
    try:
        stamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        stamp = datetime.utcnow()
    return {
        "timestamp": stamp, "src_ip": src, "dst_ip": dst, "protocol": proto,
        "src_port": sport, "dst_port": dport, "packet_size": int(len(packet)),
        "tcp_syn": bool(packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02),
        "is_dns": bool(packet.haslayer(DNS)),
        "connection": f"{src}:{sport or 0}-{dst}:{dport or 0}-{proto}",
    }

def analyze_upload(content: bytes, filename: str = "capture.pcap") -> pd.DataFrame:
    if not content:
        raise ValueError("The uploaded file is empty.")
    try:
        packets = rdpcap(BytesIO(content))
    except Exception as exc:
        raise ValueError("The file could not be parsed as a PCAP/PCAPNG capture.") from exc
    rows = [row for packet in packets if (row := _packet_row(packet)) is not None]
    if not rows:
        raise ValueError("No IPv4 or IPv6 packets were found in this capture.")
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values("timestamp").reset_index(drop=True)

def load_sample_data() -> pd.DataFrame:
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "sample_data" / "sample_traffic.csv"
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df
