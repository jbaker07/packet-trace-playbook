#!/usr/bin/env bash
# Rebuilds tests/sample.pcapng, the capture the test script runs against.
# It needs root on Linux (or a privileged container) with tshark, dnsmasq,
# dhclient, openssl, curl, dig, ping and python3 installed.
#
# Two network namespaces are joined by a veth pair. The server side runs
# dnsmasq for DHCP and DNS, openssl s_server for TLS and a small TCP sink.
# The client side does one of each thing the playbook looks for while
# tshark records the client interface.
#
# Usage: sudo ./tests/make_sample_capture.sh [output.pcapng]
set -euo pipefail

OUTPUT_FILE="${1:-$(dirname "$0")/sample.pcapng}"
SERVER_NS=pt_srv
CLIENT_NS=pt_cli
LAN_SERVER_IP=192.168.50.1
LAN_CLIENT_IP=192.168.50.100
#198.51.100.0/24 is a documentation range, so it stands in for a public server
PUBLIC_SERVER_IP=198.51.100.10
#unique local IPv6 addresses for the IPv6 part of the capture
LAN_SERVER_IP6=fd00:50::1
LAN_CLIENT_IP6=fd00:50::100
SERVER_NAME=api.playbook.test
WORK_DIR=$(mktemp -d)

cleanup() {
  #kill everything that runs inside the two namespaces, then delete them
  for NS in "$SERVER_NS" "$CLIENT_NS"; do
    if ip netns list | grep -qw "$NS"; then
      for PID in $(ip netns pids "$NS"); do kill "$PID" 2>/dev/null || true; done
    fi
  done
  sleep 1
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

for TOOL in ip tshark dnsmasq dhclient openssl curl dig ping python3; do
  command -v "$TOOL" >/dev/null || { echo "Missing $TOOL"; exit 1; }
done

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add pt_cli0 type veth peer name pt_srv0
ip link set pt_cli0 netns "$CLIENT_NS"
ip link set pt_srv0 netns "$SERVER_NS"

#no router solicitations, so the capture only holds IPv6 packets the script sends
ip netns exec "$SERVER_NS" sysctl -qw net.ipv6.conf.pt_srv0.router_solicitations=0
ip netns exec "$CLIENT_NS" sysctl -qw net.ipv6.conf.pt_cli0.router_solicitations=0

ip -n "$SERVER_NS" link set lo up
ip -n "$SERVER_NS" link set pt_srv0 up
ip -n "$SERVER_NS" addr add "$LAN_SERVER_IP/24" dev pt_srv0
ip -n "$SERVER_NS" addr add "$PUBLIC_SERVER_IP/32" dev lo
ip -n "$SERVER_NS" addr add "$LAN_SERVER_IP6/64" dev pt_srv0 nodad
ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" link set pt_cli0 up
ip -n "$CLIENT_NS" addr add "$LAN_CLIENT_IP6/64" dev pt_cli0 nodad

#self signed certificate for the TLS server
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$SERVER_NAME" \
  -addext "subjectAltName=DNS:$SERVER_NAME" \
  -keyout "$WORK_DIR/key.pem" -out "$WORK_DIR/cert.pem" 2>/dev/null

#dnsmasq hands out exactly one address and answers for one name
cat >"$WORK_DIR/dnsmasq.conf" <<CONF
interface=pt_srv0
bind-interfaces
no-resolv
no-hosts
local=/playbook.test/
address=/$SERVER_NAME/$PUBLIC_SERVER_IP
no-ping
dhcp-range=$LAN_CLIENT_IP,$LAN_CLIENT_IP,255.255.255.0,1h
dhcp-option=option:router,$LAN_SERVER_IP
dhcp-option=option:dns-server,$LAN_SERVER_IP
dhcp-leasefile=$WORK_DIR/dnsmasq.leases
pid-file=$WORK_DIR/dnsmasq.pid
CONF
ip netns exec "$SERVER_NS" dnsmasq --conf-file="$WORK_DIR/dnsmasq.conf"

#TLS server on 443 and a plain TCP sink on 8080 that reads and discards
ip netns exec "$SERVER_NS" openssl s_server -quiet -accept "$PUBLIC_SERVER_IP:443" \
  -cert "$WORK_DIR/cert.pem" -key "$WORK_DIR/key.pem" -www >/dev/null 2>&1 &
ip netns exec "$SERVER_NS" python3 -c '
import socket
LISTEN_SOCKET = socket.socket()
LISTEN_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
LISTEN_SOCKET.bind(("'"$PUBLIC_SERVER_IP"'", 8080))
LISTEN_SOCKET.listen(1)
CONNECTION, PEER = LISTEN_SOCKET.accept()
while CONNECTION.recv(4096):
    pass
' &
sleep 1

ip netns exec "$CLIENT_NS" tshark -q -i pt_cli0 -w "$WORK_DIR/raw.pcapng" 2>/dev/null &
TSHARK_PID=$!
sleep 2

echo "DHCP exchange"
ip netns exec "$CLIENT_NS" dhclient -1 -sf /bin/true -lf "$WORK_DIR/dhclient.leases" \
  -pf "$WORK_DIR/dhclient.pid" pt_cli0
ip -n "$CLIENT_NS" addr add "$LAN_CLIENT_IP/24" dev pt_cli0
ip -n "$CLIENT_NS" route add default via "$LAN_SERVER_IP"
ip netns exec "$CLIENT_NS" dhclient -r -sf /bin/true -lf "$WORK_DIR/dhclient.leases" \
  -pf "$WORK_DIR/dhclient.pid" pt_cli0

echo "DNS lookups"
ip netns exec "$CLIENT_NS" dig +short +tries=1 @"$LAN_SERVER_IP" "$SERVER_NAME" A
ip netns exec "$CLIENT_NS" dig +short +tries=1 @"$LAN_SERVER_IP" missing.playbook.test A || true

echo "ICMP echo and port unreachable"
ip netns exec "$CLIENT_NS" ping -c 2 -i 0.5 "$PUBLIC_SERVER_IP" >/dev/null
ip netns exec "$CLIENT_NS" bash -c "echo probe >/dev/udp/$PUBLIC_SERVER_IP/9" || true
sleep 0.5

echo "ICMPv6 echo"
ip netns exec "$CLIENT_NS" ping -6 -c 1 "$LAN_SERVER_IP6" >/dev/null

echo "TCP connect to a closed port"
ip netns exec "$CLIENT_NS" bash -c "</dev/tcp/$PUBLIC_SERVER_IP/8443" 2>/dev/null || true

echo "TLS handshake that succeeds"
ip netns exec "$CLIENT_NS" curl -sS -o /dev/null --cacert "$WORK_DIR/cert.pem" \
  --resolve "$SERVER_NAME:443:$PUBLIC_SERVER_IP" "https://$SERVER_NAME/"

echo "TLS 1.2 handshake that the client rejects with an alert"
#without the CA file the client cannot verify the server, so it sends a fatal unknown_ca alert
ip netns exec "$CLIENT_NS" openssl s_client -tls1_2 -verify_return_error \
  -connect "$PUBLIC_SERVER_IP:443" -servername "$SERVER_NAME" </dev/null >/dev/null 2>&1 || true

echo "TCP retransmission"
#the client connects to the sink, then its ARP entry for the gateway is pointed at a
#MAC address nobody owns, so the next segment leaves the client and is never answered
ip netns exec "$CLIENT_NS" python3 -c '
import socket, subprocess, time
CLIENT_SOCKET = socket.create_connection(("'"$PUBLIC_SERVER_IP"'", 8080))
CLIENT_SOCKET.sendall(b"first segment\n")
time.sleep(0.5)
subprocess.run(["ip", "neigh", "replace", "'"$LAN_SERVER_IP"'", "lladdr", "02:00:00:00:00:99", "dev", "pt_cli0", "nud", "permanent"], check=True)
CLIENT_SOCKET.sendall(b"second segment\n")
time.sleep(1.5)
subprocess.run(["ip", "neigh", "del", "'"$LAN_SERVER_IP"'", "dev", "pt_cli0"], check=True)
time.sleep(1.5)
CLIENT_SOCKET.close()
'
sleep 1

kill "$TSHARK_PID"
wait "$TSHARK_PID" 2>/dev/null || true
cp "$WORK_DIR/raw.pcapng" "$OUTPUT_FILE"
echo "Wrote $OUTPUT_FILE ($(tshark -r "$OUTPUT_FILE" 2>/dev/null | wc -l) packets)"
