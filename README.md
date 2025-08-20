# Network Traffic Analyzer

A simple Python-based tool that analyzes **packet captures (.pcap)** to identify top talkers, suspicious ports, and repeated errors.  
Complements the Mini SOC Dashboard by providing deeper **traffic analysis** for root cause identification.

---

## 🚀 Features
- Parses `.pcap` files using Scapy
- Lists top source IPs ("Top Talkers")
- Detects unusual/repeated ports and anomalies
- Supports faster **Incident Resolution** during SOC analysis

---

## ⚙️ Setup
```bash
cd traffic-analyzer
pip install -r requirements.txt
python analyzer.py
