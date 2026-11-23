#!/usr/bin/env bash
# Time-limited capture for reproductions. Usage: ./cap.sh [iface] [out.pcapng] [seconds]
set -euo pipefail
IFACE="${1:-eth0}"
OUT="${2:-capture.pcapng}"
DUR="${3:-60}"   # seconds

echo "Capturing on $IFACE for $DUR s → $OUT"
sudo tshark -i "$IFACE" -a duration:"$DUR" -w "$OUT"
echo "Done."
