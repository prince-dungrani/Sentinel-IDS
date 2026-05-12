# Sentinel-IDS 🛡️

**Sentinel-IDS** is a high-performance, Python-based Network Intrusion Detection System (NIDS) equipped with a dynamic real-time Security Operations Center (SOC) dashboard. 

It leverages multiprocessing to bypass the Python Global Interpreter Lock (GIL) for rapid packet processing, dynamically identifies both signature-based and heuristic anomalies, and visualizes network threats in real-time.

---

## 🚀 Core Features

- **High-Performance Packet Sniffing**: Uses asynchronous multiprocessing queues to inspect traffic without dropping packets. Captures standard Ethernet and Npcap Loopback/Null frames.
- **Dual-Engine Detection**:
  - **Signature Engine**: Supports hot-reloadable custom JSON rules and parses industry-standard Suricata NIDS rules.
  - **Heuristic Engine**: Automatically detects behavior-based anomalies like SYN Floods, Port Scans, and DNS Tunneling.
- **Stateful Flow Management**: Tracks TCP states and buffers fragmented payloads to prevent evasion via packet fragmentation.
- **Dynamic SOC Dashboard**: Built with Flask, offering live metric tracking, alerts, and connection graphs using an AJAX-polling frontend.
- **Live Threat Intelligence**: Dynamically ranks attacking IPs (0-100 risk score) based on severity and maps triggered rules to the **MITRE ATT&CK Framework** (Initial Access, Discovery, C2, Denial of Service).
- **ML-Ready Architecture**: Fully decoupled core engine and web dashboard, cleanly outputting parsed packet features for future Machine Learning integration.

---

## 📂 Architecture Overview

The system is separated into two decoupled environments communicating via `logs/alerts.json`:

1. **`core/` (Detection Engine)**
   - `sniffer.py`: Captures packets via Scapy.
   - `protocol_parser.py`: Decodes raw bytes into Layer 3/4/7 features.
   - `detector.py`: Routes features through the Signature and Heuristic rule engines.
2. **`dashboard/` (Web UI)**
   - `app.py`: Flask REST API serving endpoints for live polling (`/api/alerts`, `/api/intel`).
   - `threat_intel.html` & `alerts.html`: The frontend visualizing active threats.

*(See `ids_system_architecture.md` for deep technical details).*

---

## 🛠️ Installation & Usage

### Prerequisites
- Python 3.8+
- [Npcap](https://npcap.com/) (Required on Windows for loopback capturing)
- `pip install -r requirements.txt` *(Make sure Scapy and Flask are installed)*

### Running the System
1. Edit `config/config.json` to define your target network interface (e.g., `Software Loopback Interface 1`).
2. Run the unified startup script:
   ```bash
   .\start.bat
   ```
3. Open your browser to `http://localhost:5000` to access the SOC Dashboard.

### Simulating Attacks
You can use the built-in attack simulator to verify the IDS is functioning correctly. In a separate terminal, run:
```bash
python attacker.py
```
This will simulate SQL Injections, XSS payloads, SYN Floods, and Port Scans against your local network.

---

## 🔮 Future Roadmap
- **Phase 1**: Rule-Based & Heuristic Detection (Complete)
- **Phase 2**: Real-time Threat Intelligence and MITRE Mapping (Complete)
- **Phase 3**: Machine Learning Integration (In Progress)
  - Train and deploy a Random Forest / Neural Network model inside `detector.py` for continuous anomaly detection using the structured `features` dictionary.

---
*Developed by Prince Dungrani*
