#!/usr/bin/env python3
import argparse, os, sys, subprocess, json, datetime, re, shutil

# Wireshark 3.0 renamed the bootp protocol to dhcp and ssl to tls, so these
# names need tshark 3.0 or later.
FILTERS = {
  "dhcp":  "dhcp",
  "dns":   "dns",
  "tcp":   "tcp.flags.syn==1 || tcp.flags.reset==1 || tcp.analysis.retransmission || tcp.analysis.lost_segment",
  "tls":   "tls || tcp.port==443",
  "icmp":  "icmp || icmpv6",
}
MIN_FILTER = "(" + ") || (".join(FILTERS.values()) + ")"

FIELDS = [
  "frame.number",
  "frame.time_epoch",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "dns.qry.name",
  "dns.flags.response",
  "dns.flags.rcode",
  "dhcp.option.dhcp",
  "tcp.flags.syn",
  "tcp.flags.ack",
  "tcp.flags.reset",
  "tcp.analysis.retransmission",
  "tcp.analysis.lost_segment",
  "tls.handshake.type",
  "tls.alert_message.level",
  "tls.alert_message.desc",
  "icmp.type",
  "icmp.code",
  "icmpv6.type",
  "icmpv6.code",
]

# Names for the numeric codes tshark prints, so the timeline reads without a lookup table
DHCP_TYPES = {"1": "Discover", "2": "Offer", "3": "Request", "4": "Decline",
              "5": "ACK", "6": "NAK", "7": "Release", "8": "Inform"}

DNS_RCODES = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN",
              "4": "NOTIMP", "5": "REFUSED"}

TLS_HANDSHAKE_TYPES = {"0": "HelloRequest", "1": "ClientHello", "2": "ServerHello",
                       "4": "NewSessionTicket", "8": "EncryptedExtensions",
                       "11": "Certificate", "12": "ServerKeyExchange",
                       "13": "CertificateRequest", "14": "ServerHelloDone",
                       "15": "CertificateVerify", "16": "ClientKeyExchange",
                       "20": "Finished"}

TLS_ALERT_LEVELS = {"1": "warning", "2": "fatal"}

TLS_ALERTS = {"0": "close_notify", "10": "unexpected_message", "20": "bad_record_mac",
              "22": "record_overflow", "40": "handshake_failure", "42": "bad_certificate",
              "43": "unsupported_certificate", "44": "certificate_revoked",
              "45": "certificate_expired", "46": "certificate_unknown",
              "47": "illegal_parameter", "48": "unknown_ca", "49": "access_denied",
              "50": "decode_error", "51": "decrypt_error", "70": "protocol_version",
              "71": "insufficient_security", "80": "internal_error",
              "86": "inappropriate_fallback", "90": "user_canceled",
              "109": "missing_extension", "110": "unsupported_extension",
              "112": "unrecognized_name", "116": "certificate_required",
              "120": "no_application_protocol"}

ICMP_TYPES = {"0": "echo reply", "3": "destination unreachable", "5": "redirect",
              "8": "echo request", "11": "time exceeded"}

# Codes for ICMP type 3. Code 4 is the one that matters for path MTU problems.
ICMP_UNREACH_CODES = {"0": "net unreachable", "1": "host unreachable",
                      "2": "protocol unreachable", "3": "port unreachable",
                      "4": "fragmentation needed", "9": "network prohibited",
                      "10": "host prohibited", "13": "administratively prohibited"}

ICMPV6_TYPES = {"1": "destination unreachable", "2": "packet too big",
                "3": "time exceeded", "128": "echo request", "129": "echo reply",
                "133": "router solicitation", "134": "router advertisement",
                "135": "neighbor solicitation", "136": "neighbor advertisement",
                "143": "multicast listener report"}

def need(cmd):
  if shutil.which(cmd) is None:
    sys.exit(f"Missing required tool: {cmd}. Install the Wireshark command line tools (tshark 3.0 or later).")

def run(cmd):
  p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  return p.returncode, p.stdout, p.stderr

def utc_now():
  return datetime.datetime.now(datetime.timezone.utc)

def ts():
  return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")

def ensure_dir(p):
  os.makedirs(p, exist_ok=True)

def build_bundle_dir(outdir):
  # No colons in the folder name, so the bundle can be copied to Windows or zipped as is
  d = os.path.join(outdir, "bundle_" + utc_now().strftime("%Y%m%dT%H%M%SZ"))
  ensure_dir(d)
  return d

def shorten_ip(ip):
  if not ip: return ""
  # Mask private ranges to non-identifying placeholders (timeline only)
  priv = [
    (re.compile(r"^10\."), "10.x.x.x"),
    (re.compile(r"^192\.168\."), "192.168.x.x"),
    (re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."), "172.16-31.x.x"),
    (re.compile(r"^fe80:", re.IGNORECASE), "fe80::/64"),
    (re.compile(r"^f[cd][0-9a-f]{2}:", re.IGNORECASE), "fc00::/7"),
  ]
  for rx, repl in priv:
    if rx.search(ip): return repl
  return ip

def tshark_json(pcap, display_filter):
  cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "json"]
  for name in FIELDS:
    cmd += ["-e", name]
  rc, out, err = run(cmd)
  if rc != 0:
    raise RuntimeError(f"tshark failed: {err.strip()}")
  try:
    return json.loads(out) if out.strip() else []
  except json.JSONDecodeError:
    return []

def field_all(pkt, name):
  try:
    return list(pkt["_source"]["layers"][name])
  except Exception:
    return []

def field(pkt, name):
  # First value only. ICMP errors carry a copy of the original IP header, and
  # the first ip.src is the outer one, which is the one that matters here.
  values = field_all(pkt, name)
  if values:
    return values[0]
  return ""

def b(v):  # bool-ish
  return v in ("1", 1, True, "True", "true")

def name_for(table, code):
  if code in table:
    return f"{table[code]} ({code})"
  return f"type {code}"

def format_epoch(epoch):
  # tshark prints epoch time as text with nine decimal places. The whole seconds
  # and the fraction are split as text, because a float would round the last digits.
  whole, _, fraction = str(epoch).partition(".")
  try:
    when = datetime.datetime.fromtimestamp(int(whole), datetime.timezone.utc)
  except (TypeError, ValueError):
    return str(epoch)
  return when.strftime("%Y-%m-%dT%H:%M:%S") + "." + (fraction + "000000")[:6] + "Z"

def classify(pkt):
  syn = b(field(pkt, "tcp.flags.syn"))
  ack = b(field(pkt, "tcp.flags.ack"))
  rst = b(field(pkt, "tcp.flags.reset"))
  rtx = b(field(pkt, "tcp.analysis.retransmission"))
  lost = b(field(pkt, "tcp.analysis.lost_segment"))
  dhcp = field(pkt, "dhcp.option.dhcp")
  qname = field(pkt, "dns.qry.name")
  dns_response = b(field(pkt, "dns.flags.response"))
  rcode = field(pkt, "dns.flags.rcode")
  alert_level = field(pkt, "tls.alert_message.level")
  alert_desc = field(pkt, "tls.alert_message.desc")
  hs_types = field_all(pkt, "tls.handshake.type")
  icmp_t = field(pkt, "icmp.type")
  icmp_c = field(pkt, "icmp.code")
  icmp6_t = field(pkt, "icmpv6.type")
  icmp6_c = field(pkt, "icmpv6.code")

  # ICMP goes first. An ICMP error carries a copy of the packet that caused it,
  # and tshark dissects that copy too, so a port unreachable for a DNS query
  # would otherwise be reported as the DNS query.
  if icmp_t:
    text = f"ICMP {ICMP_TYPES.get(icmp_t, 'type ' + icmp_t)}"
    if icmp_t == "3":
      text += f", {ICMP_UNREACH_CODES.get(icmp_c, 'code ' + icmp_c)}"
    elif icmp_c and icmp_c != "0":
      text += f", code {icmp_c}"
    return text
  if icmp6_t:
    text = f"ICMPv6 {ICMPV6_TYPES.get(icmp6_t, 'type ' + icmp6_t)}"
    if icmp6_c and icmp6_c != "0":
      text += f", code {icmp6_c}"
    return text
  if dhcp:
    return f"DHCP {DHCP_TYPES.get(dhcp, 'message type ' + dhcp)}"
  if qname:
    if dns_response:
      return f"DNS response {qname} {DNS_RCODES.get(rcode, 'rcode ' + rcode)}"
    return f"DNS query {qname}"
  if syn and not rst:
    return "TCP SYN/ACK" if ack else "TCP SYN"
  if rst:
    return "TCP RST"
  if alert_desc:
    level = TLS_ALERT_LEVELS.get(alert_level, "level " + alert_level)
    return f"TLS alert {level} {name_for(TLS_ALERTS, alert_desc)}"
  if hs_types:
    names = []
    for code in hs_types:
      names.append(TLS_HANDSHAKE_TYPES.get(code, "type " + code))
    return "TLS handshake " + ", ".join(names)
  if rtx:
    return "TCP retransmission"
  if lost:
    return "TCP previous segment not captured"
  return None

def summarize_events(pcap):
  events = []
  data = tshark_json(pcap, MIN_FILTER)
  for pkt in data:
    reason = classify(pkt)
    if not reason:
      continue
    src = field(pkt, "ip.src") or field(pkt, "ipv6.src")
    dst = field(pkt, "ip.dst") or field(pkt, "ipv6.dst")
    events.append({
      "frame": field(pkt, "frame.number"),
      "time": format_epoch(field(pkt, "frame.time_epoch")),
      "src": shorten_ip(src),
      "dst": shorten_ip(dst),
      "reason": reason
    })
  return events

def write_timeline(events, case_desc, outpath):
  with open(outpath, "w") as f:
    f.write(f"# Packet timeline, generated {ts()}\n\n")
    if case_desc:
      f.write(f"**Case:** {case_desc}\n\n")
    if not events:
      f.write("_No events captured with default filters. Consider widening filters or capturing longer._\n")
      return
    f.write("Times are UTC. Private addresses are masked.\n\n")
    for e in events:
      f.write(f"- {e['time']} [{e['frame']}] {e['reason']} ({e['src']} → {e['dst']})\n")

def write_filters(outpath):
  with open(outpath, "w") as f:
    for k, v in FILTERS.items():
      f.write(f"# {k}\n{v}\n\n")
    f.write("# minimal union\n" + MIN_FILTER + "\n")

def slice_min_pcap(pcap, out_pcap):
  # Keep only DHCP/DNS/TCP/TLS/ICMP packets for compact escalation file
  cmd = ["tshark", "-r", pcap, "-Y", MIN_FILTER, "-w", out_pcap]
  rc, out, err = run(cmd)
  if rc != 0:
    raise RuntimeError(f"tshark slice failed: {err.strip()}")

def write_manifest(bundle_dir, pcap, case_desc, event_count):
  with open(os.path.join(bundle_dir, "MANIFEST.txt"), "w") as f:
    f.write("Packet Trace Playbook escalation bundle\n")
    f.write(f"Generated: {ts()}\n")
    f.write(f"Source PCAP: {pcap}\n")
    if case_desc:
      f.write(f"Case: {case_desc}\n")
    f.write(f"Timeline events: {event_count}\n")
    f.write("\nContents:\n")
    f.write("  timeline.md      ordered DHCP, DNS, TCP, TLS and ICMP events with reasons\n")
    f.write("  filters.txt      Wireshark display filters\n")
    f.write("  case_min.pcapng  trimmed pcap with only the packets that match the filters\n")

def main():
  ap = argparse.ArgumentParser(description="Packet Trace Playbook: escalation bundle generator")
  ap.add_argument("--pcap", required=True, help="Input pcap/pcapng")
  ap.add_argument("--case", default="", help="Short case description")
  ap.add_argument("--out", default="./out", help="Output directory (default: ./out)")
  args = ap.parse_args()

  need("tshark")

  pcap = os.path.abspath(args.pcap)
  if not os.path.isfile(pcap):
    sys.exit(f"pcap not found: {pcap}")

  out_root = os.path.abspath(args.out)
  ensure_dir(out_root)
  bundle = build_bundle_dir(out_root)

  # Produce artifacts
  events = summarize_events(pcap)
  write_timeline(events, args.case, os.path.join(bundle, "timeline.md"))
  write_filters(os.path.join(bundle, "filters.txt"))

  min_pcap = os.path.join(bundle, "case_min.pcapng")
  slice_min_pcap(pcap, min_pcap)

  write_manifest(bundle, pcap, args.case, len(events))

  print(f"Bundle written: {bundle}")
  sys.exit(0)

if __name__ == "__main__":
  main()
