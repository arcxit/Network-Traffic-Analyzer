from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from pathlib import Path
import sys

def summarize(pcap_path):
    pkts = rdpcap(pcap_path)
    rows = []
    for p in pkts:
        if IP in p:
            src = p[IP].src
            dst = p[IP].dst
            proto = "TCP" if TCP in p else "UDP" if UDP in p else "OTHER"
            dport = p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else None)
            rows.append({"src": src, "dst": dst, "proto": proto, "dport": dport})
    df = pd.DataFrame(rows)
    if df.empty:
        print("No IP packets found.")
        return
    top_talkers = df["src"].value_counts().head(10).reset_index()
    top_talkers.columns = ["src", "count"]
    top_ports = df["dport"].value_counts().head(10).reset_index()
    top_ports.columns = ["port", "count"]

    top_talkers.to_csv("top_talkers.csv", index=False)
    top_ports.to_csv("top_ports.csv", index=False)
    print("Wrote top_talkers.csv and top_ports.csv")

if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    if not Path(pcap).exists():
        print(f"PCAP not found: {pcap}")
    else:
        summarize(pcap)
