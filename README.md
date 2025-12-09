# Cerberus-Hash 🛡️

A web-based PCAP analyzer that detects malicious network traffic using YARA rules and MD5 hash matching.

## 🎯 Features

- Upload and analyze `.pcap`/`.pcapng` files
- Extract MD5 hashes from packet payloads
- YARA-based malware detection with 200+ signatures
- Interactive web dashboard with scan statistics

## 🏗️ Project Structure

```
Cerberus-Hash/
├── app.py                 # Flask web application
├── pcap_parser.py        # PCAP processing & hash extraction
├── yara_scanner.py       # YARA malware detection
├── requirements.txt      # Dependencies
├── templates/            # HTML templates
├── uploads/              # Uploaded PCAP files
└── yara_rules/          # Malware detection rules
```

## 🚀 Quick Start

```bash
git clone https://github.com/pradeeshl/Cerberus-Hash.git
cd Cerberus-Hash
pip install -r requirements.txt
python app.py
```

Access at: `http://localhost:5000`

**Dependencies:** Flask, Scapy, YARA-Python

## 🎮 Usage

1. Upload a PCAP file via the web interface
2. System extracts packets and generates MD5 hashes
3. Scans hashes against YARA malware rules
4. View detailed results and statistics

## 🔍 How It Works

1. **Packet Extraction** - Scapy parses PCAP files
2. **Hash Generation** - MD5 hashes computed for payloads  
3. **Signature Matching** - Hashes compared against YARA rules
4. **Result Display** - Bootstrap web interface shows detections

## 🛠️ Customization

Add custom YARA rules to `yara_rules/malware_rules.yar` for new threat patterns.

## 👨‍💻 Author

**PRADEESH L** - [@pradeeshl](https://github.com/pradeeshl)

## ⚠️ Disclaimer

For cybersecurity research purposes. Analyze PCAP files in isolated environments and comply with applicable laws.

---
*Cerberus-Hash - Network threat detection through packet analysis* 🛡️
