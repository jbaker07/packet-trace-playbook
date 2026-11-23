# Packet Trace Playbook

Turns a packet capture into an escalation bundle that another engineer can review quickly: an ordered timeline of DHCP, DNS, TCP, TLS and ICMP events, the Wireshark display filters used to build it, and a trimmed pcap that keeps only the matching packets.

It is a thin Python wrapper around `tshark`, so the parsing is Wireshark's and the output can be checked against Wireshark directly.

## What it produces

Each run writes a new folder, `bundle_<UTC timestamp>/`, under the output directory:

| File | Contents |
|------|----------|
| `timeline.md` | One line for each packet that gets a reason (listed below), with time, frame number, the reason, and source and destination |
| `filters.txt` | The per-protocol display filters and their union, ready to paste into Wireshark |
| `case_min.pcapng` | The input capture filtered down to packets that match the union filter |
| `MANIFEST.txt` | Generation time, source pcap path, case description and a list of the files |

### Timeline reasons

Each packet gets the first reason that applies, checked in this order:

1. DHCP message type
2. DNS query name
3. TCP SYN
4. TCP RST
5. TLS alert
6. TLS handshake type
7. ICMP type and code
8. TCP retransmission or lost segment

Private IPv4 addresses (10/8, 172.16/12, 192.168/16) and IPv6 link-local addresses are masked in the timeline, for example `192.168.x.x`, so the timeline can be pasted into a ticket. The trimmed pcap is not masked.

### Display filters

| Name | Filter |
|------|--------|
| dhcp | `(bootp \|\| dhcp)` |
| dns | `dns` |
| tcp | `tcp.flags.syn==1 \|\| tcp.flags.reset==1 \|\| tcp.analysis.retransmission` |
| tls | `tls \|\| ssl \|\| tcp.port==443` |
| icmp | `icmp \|\| icmpv6` |

The trimmed pcap uses the union of all five. Because the tls filter includes `tcp.port==443`, all port 443 traffic is kept.

## Requirements

- Python 3
- Wireshark command-line tools on the PATH. The script checks for both `tshark` and `editcap` at startup and exits if either is missing. Install with `brew install wireshark` on macOS or `sudo apt-get install tshark` on Debian and Ubuntu.

## Usage

```bash
python3 pktplay.py --pcap capture.pcapng --case "TLS fails to api.example.com" --out ./out
```

| Flag | Default | Description |
|------|---------|-------------|
| `--pcap` | required | Input pcap or pcapng file |
| `--case` | empty | Short case description written into the timeline and manifest |
| `--out` | `./out` | Parent directory for the bundle folder |

The script prints the bundle path when it finishes:

```text
Bundle written: /path/to/out/bundle_2025-11-07T08:07:17Z
```

### Capturing a reproduction

`cap.sh` records a time-limited capture with tshark. It runs tshark with sudo.

```bash
./cap.sh en0 capture.pcapng 60
```

The arguments are the interface (default `eth0`), the output file (default `capture.pcapng`) and the duration in seconds (default 60). On macOS the Wi-Fi or Ethernet interface is usually `en0`.

## Limitations

- Source and destination come from the IPv4 header fields, so IPv6 packets appear in the timeline without addresses.
- Only the first value of each field is used per packet.
