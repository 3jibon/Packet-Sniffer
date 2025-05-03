# 🛡️ Network Packet Sniffer

### ⚠️ Disclaimer:
This tool is intended for **educational and ethical use only**.  
Always get **proper authorization** before scanning networks or devices.

![Python](https://img.shields.io/badge/Built%20With-Python-blue)
![Scapy](https://img.shields.io/badge/Library-Scapy-yellow)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

A Python-based **Network Packet Sniffer** using **Scapy** to capture and analyze HTTP and DNS traffic. It detects sensitive information (like passwords, usernames) and identifies suspicious DNS queries in real-time. Ideal for learning about network traffic analysis and basic cybersecurity practices.

---

## 🚀 Features

- 🔍 Capture HTTP packets and detect plaintext credentials  
- 🌐 Monitor DNS queries and flag suspicious domain names  
- ⚡ Real-time packet analysis on any network interface  
- 🧠 Lightweight, simple, and built with Python and Scapy  

---

## 🛠️ Installation

### Prerequisites
- Python 3.6 or higher
- Administrator/root privileges (for packet capture)

### Step-by-Step Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd network-packet-sniffer
2. **Run**:
   ```bash
   pip install -r requirements.txt
   sudo python packet-sniffer.py -i <your_interface>
