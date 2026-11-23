#!/usr/bin/env python3
import argparse, os, sys, subprocess, shlex, json, datetime, pathlib, re

REQ_CMDS = ["tshark", "editcap"]

FILTERS = {
  "dhcp":  "(bootp || dhcp)",
  "dns":   "dns",
  "tcp":   "tcp.flags.syn==1 || tcp.flags.reset==1 || tcp.analysis.retransmission",
  "tls":   "tls || ssl || tcp.port==443",
  "icmp":  "icmp || icmpv6",
}
MIN_FILTER = "(" + ") || (".join(FILTERS.values()) + ")"

FIELDS = [
  "frame.number",
  "frame.time",
  "ip.src",
  "ip.dst",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "dns.qry.name",
  "bootp.option.dhcp",
  "tcp.flags.syn",
  "tcp.flags.ack",
  "tcp.flags.reset",
  "tcp.analysis.retransmission",
  "tcp.analysis.lost_segment",
  "tls.record.content_type",
  "tls.handshake.type",
  "tls.alert_message",
  "icmp.type",
  "icmp.code",
]

def need(cmd):
  try:
    subprocess.run([cmd, "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
  except FileNotFoundError:
    sys.exit(f"Missing required tool: {cmd}")

def run(cmd):
  p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  return p.returncode, p.stdout, p.stderr

def ts():
  return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def ensure_dir(p):
  os.makedirs(p, exist_ok=True)

def build_bundle_dir(outdir):
  d = os.path.join(outdir, f"bundle_{ts()}")
  ensure_dir(d)
  return d

def shorten_ip(ip):
  if not ip: return ""
  # Mask private ranges to non-identifying placeholders (timeline only)
  priv = [
    (re.compile(r"^10\."), "10.x.x.x"),
    (re.compile(r"^192\.168\."), "192.168.x.x"),
    (re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."), "172.16-31.x.x"),
    (re.compile(r"^fe80:"), "fe80::/64"),
  ]
  for rx, repl in priv:
    if rx.search(ip): return repl
  return ip

def tshark_json(pcap, display_filter):
  cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "json",
         "-e", "frame.number", "-e", "frame.time"] + sum([["-e", f] for f in FIELDS[2:]], [])
  rc, out, err = run(cmd)
  if rc != 0:
    raise RuntimeError(f"tshark failed: {err.strip()}")
  try:
    return json.loads(out) if out.strip() else []
  except json.JSONDecodeError:
    return []

def field(pkt, name):
  try:
    for d in pkt["_source"]["layers"][name]:
      return d
  except Exception:
    pass
  return ""

def b(v):  # bool-ish
  return v in ("1", 1, True, "True", "true")

def summarize_events(pcap):
  events = []
  data = tshark_json(pcap, MIN_FILTER)
  for pkt in data:
    layers = pkt.get("_source", {}).get("layers", {})
    fn = field(pkt, "frame.number")
    ts_ = field(pkt, "frame.time")
    src = field(pkt, "ip.src")
    dst = field(pkt, "ip.dst")
    syn = b(field(pkt, "tcp.flags.syn"))
    rst = b(field(pkt, "tcp.flags.reset"))
    rtx = b(field(pkt, "tcp.analysis.retransmission"))
    lost = b(field(pkt, "tcp.analysis.lost_segment"))
    dhcp = field(pkt, "bootp.option.dhcp")
    qname = field(pkt, "dns.qry.name")
    tls_alert = field(pkt, "tls.alert_message")
    hs_type = field(pkt, "tls.handshake.type")
    icmp_t = field(pkt, "icmp.type")
    icmp_c = field(pkt, "icmp.code")

    # Classify
    reason = None
    if dhcp:
      reason = f"DHCP {dhcp}"
    elif qname:
      reason = f"DNS query {qname}"
    elif syn and not rst:
      reason = "TCP SYN"
    elif rst:
      reason = "TCP RST"
    elif tls_alert:
      reason = f"TLS alert {tls_alert}"
    elif hs_type:
      reason = f"TLS handshake type {hs_type}"
    elif icmp_t:
      reason = f"ICMP type {icmp_t} code {icmp_c}"
    elif rtx or lost:
      reason = "TCP retransmission/loss"

    if reason:
      events.append({
        "frame": fn,
        "time": ts_,
        "src": shorten_ip(src),
        "dst": shorten_ip(dst),
        "reason": reason
      })
  return events

def write_timeline(events, case_desc, outpath):
  with open(outpath, "w") as f:
    f.write(f"# Packet Timeline — {ts()}\n\n")
    if case_desc:
      f.write(f"**Case:** {case_desc}\n\n")
    if not events:
      f.write("_No events captured with default filters. Consider widening filters or capturing longer._\n")
      return
    for e in events:
      f.write(f"- {e['time']} — [{e['frame']}] {e['reason']} ({e['src']} → {e['dst']})\n")

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

def write_manifest(bundle_dir, pcap, case_desc):
  with open(os.path.join(bundle_dir, "MANIFEST.txt"), "w") as f:
    f.write("Packet Trace Playbook — Escalation Bundle\n")
    f.write(f"Generated: {ts()}\n")
    f.write(f"Source PCAP: {pcap}\n")
    if case_desc:
      f.write(f"Case: {case_desc}\n")
    f.write("\nContents:\n")
    f.write("  timeline.md   — ordered DHCP/DNS/TCP/TLS/ICMP events with reasons\n")
    f.write("  filters.txt   — Wireshark display filters\n")
    f.write("  case_min.pcapng — trimmed pcap with only relevant flows\n")

def main():
  for c in REQ_CMDS: need(c)
  ap = argparse.ArgumentParser(description="Packet Trace Playbook — Escalation bundle generator")
  ap.add_argument("--pcap", required=True, help="Input pcap/pcapng")
  ap.add_argument("--case", default="", help="Short case description")
  ap.add_argument("--out", default="./out", help="Output directory (default: ./out)")
  args = ap.parse_args()

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

  write_manifest(bundle, pcap, args.case)

  print(f"Bundle written: {bundle}")
  sys.exit(0)

if __name__ == "__main__":
  main()
