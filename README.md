# Packet Trace Playbook

Turns a packet capture into an escalation bundle that another engineer can review quickly: an ordered timeline of DHCP, DNS, TCP, TLS and ICMP events, the Wireshark display filters used to build it, and a trimmed pcap that keeps only the matching packets.

It is a thin Python wrapper around `tshark`, so the parsing is Wireshark's and the output can be checked against Wireshark directly.

## What it produces

Each run writes a new folder, `bundle_<UTC timestamp>/`, under the output directory:

| File | Contents |
|------|----------|
| `timeline.md` | One line for each packet that gets a reason (listed below), with the UTC time, frame number, the reason, and source and destination |
| `filters.txt` | The per-protocol display filters and their union, ready to paste into Wireshark |
| `case_min.pcapng` | The input capture filtered down to packets that match the union filter |
| `MANIFEST.txt` | Generation time, source pcap path, case description, the number of timeline events and a list of the files |

### Timeline reasons

Each packet gets the first reason that applies, checked in this order:

1. ICMP or ICMPv6 type, with the code for destination unreachable (for example `ICMP destination unreachable, fragmentation needed`)
2. DHCP message type (`DHCP Discover`, `DHCP Offer`, `DHCP Request`, `DHCP ACK` and so on)
3. DNS query name, and for responses the result code (`DNS response missing.example.test NXDOMAIN`)
4. TCP SYN, or SYN/ACK for the server's answer
5. TCP RST
6. TLS alert level and description (`TLS alert fatal unknown_ca (48)`)
7. TLS handshake messages, all of them when one record carries several (`TLS handshake ServerHello, Certificate, ServerKeyExchange, ServerHelloDone`)
8. TCP retransmission, then a segment tshark marks as lost

ICMP is checked first because an ICMP error carries a copy of the packet that caused it, and tshark dissects that copy too. Without that order a port unreachable sent back for a DNS query would be reported as the DNS query.

Example lines from the test capture:

```text
- 2026-11-23T21:57:27.135257Z [3] DHCP Discover (0.0.0.0 → 255.255.255.255)
- 2026-11-23T21:57:28.212713Z [13] DNS response missing.playbook.test NXDOMAIN (192.168.x.x → 192.168.x.x)
- 2026-11-23T21:57:29.249093Z [25] TCP RST (198.51.100.10 → 192.168.x.x)
- 2026-11-23T21:57:29.291423Z [53] TLS alert fatal unknown_ca (48) (192.168.x.x → 198.51.100.10)
- 2026-11-23T21:57:30.019684Z [63] TCP retransmission (192.168.x.x → 198.51.100.10)
```

Private IPv4 addresses (10/8, 172.16/12, 192.168/16), IPv6 link-local addresses (fe80::/10) and IPv6 unique local addresses (fc00::/7) are masked in the timeline, for example `192.168.x.x`, so the timeline can be pasted into a ticket. The trimmed pcap is not masked.

### Display filters

| Name | Filter |
|------|--------|
| dhcp | `dhcp` |
| dns | `dns` |
| tcp | `tcp.flags.syn==1 \|\| tcp.flags.reset==1 \|\| tcp.analysis.retransmission \|\| tcp.analysis.lost_segment` |
| tls | `tls \|\| tcp.port==443` |
| icmp | `icmp \|\| icmpv6` |

Wireshark 3.0 renamed the `bootp` protocol to `dhcp` and `ssl` to `tls`. The filters and the fields the script reads (`dhcp.option.dhcp`, `tls.alert_message.desc` and so on) use the current names.

The trimmed pcap uses the union of all five. Because the tls filter includes `tcp.port==443`, all port 443 traffic is kept.

## Requirements

- Python 3
- `tshark` 3.0 or later on the PATH. The script exits with a message if it is missing. Install with `brew install wireshark` on macOS or `sudo apt-get install tshark` on Debian and Ubuntu.

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
Bundle written: /path/to/out/bundle_20261123T215646Z
```

### Capturing a reproduction

`cap.sh` records a time-limited capture with tshark. It runs tshark with sudo unless it already runs as root.

```bash
./cap.sh en0 capture.pcapng 60
```

The arguments are the interface (default `eth0`), the output file (default `capture.pcapng`) and the duration in seconds (default 60). On macOS the Wi-Fi or Ethernet interface is usually `en0`.

## Tests

`tests/run_tests.sh` runs the script against `tests/sample.pcapng` and checks the bundle: the timeline line for line against `tests/expected_timeline.md`, that every timeline reason appears, that private addresses are masked, that each display filter is accepted by tshark and matches the expected number of packets, that the trimmed pcap holds exactly the packets the union filter matches, the manifest, an ARP only capture that gives the empty timeline message, and a missing input file. It needs tshark but no root and no network.

```bash
./tests/run_tests.sh
```

```text
Using TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).
[PASS] pktplay.py exits 0 and writes a bundle folder
...
[PASS] missing pcap exits non-zero
Summary: 30 passed, 0 failed
```

The expected files were made with tshark 4.2.2, the version in Ubuntu 24.04. Another tshark version can flag a packet differently, so a timeline diff on a different version is worth reading before treating it as a bug.

The sample capture is 72 packets recorded between two network namespaces on Linux. `tests/make_sample_capture.sh` rebuilds it (it needs root, tshark, dnsmasq, dhclient, openssl, curl and dig). The server side runs dnsmasq for DHCP and DNS and openssl s_server for TLS. The client side then does a DHCP exchange and release, a DNS lookup that works and one that returns NXDOMAIN, IPv4 and IPv6 pings, a UDP packet to a closed port that draws an ICMP port unreachable, a TCP connect to a closed port that draws a RST, a TLS 1.3 handshake that works, a TLS 1.2 handshake the client rejects with an `unknown_ca` alert, and a TCP stream whose next segment is lost on purpose so it is retransmitted. The public server address is 198.51.100.10, a documentation range, so it shows up unmasked.

The GitHub Actions workflow in `.github/workflows/tests.yml` installs tshark on Ubuntu 24.04 and runs the same script on every push and pull request.

## Limitations

- Only the first value of the address, DNS, DHCP, TLS alert and ICMP fields is used per packet. For an ICMP error that is the outer header, which is the one that matters.
- TLS 1.3 encrypts everything after the ServerHello, including most alerts, so a TLS 1.3 failure shows up as a ClientHello and ServerHello followed by a FIN or RST rather than as a named alert.
- The reason names cover the common codes. Anything else is printed as its number, for example `TLS alert fatal type 113`.
