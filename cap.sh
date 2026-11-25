#!/usr/bin/env bash
# Time-limited capture for reproductions. Usage: ./cap.sh [iface] [out.pcapng] [seconds]
set -euo pipefail
IFACE="${1:-eth0}"
OUT="${2:-capture.pcapng}"
DUR="${3:-60}"   # seconds

#capturing needs root, so use sudo unless the script already runs as root
SUDO=""
if [[ $EUID -ne 0 ]]; then
  SUDO=sudo
fi

echo "Capturing on $IFACE for $DUR s → $OUT"
$SUDO tshark -i "$IFACE" -a duration:"$DUR" -w "$OUT"
echo "Done."
