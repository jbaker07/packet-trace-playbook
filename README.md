# Packet Trace Playbook (MVP)

Turn messy pcaps into a **clean escalation bundle**:
- Ordered timeline of **DHCP / DNS / TCP / TLS / ICMP** events with quick reasons (timeouts, RSTs, TLS alerts)
- Ready-to-paste **Wireshark display filters**
- **Trimmed pcap** that includes only relevant packets for faster review

---

## Requirements
- **Wireshark CLI tools**: `tshark`, `editcap` (install with `brew install wireshark` or `sudo apt-get install tshark`)
- **Python 3.8+**

## Quick start
```bash
python3 pktplay.py --pcap sample.pcapng --case "TLS fails to api.example.com" --out ./out
