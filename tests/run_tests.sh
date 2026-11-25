#!/usr/bin/env bash
# Runs pktplay.py against tests/sample.pcapng and compares the bundle with the
# expected files in tests/. Needs python3 and tshark 3.0 or later. No root and
# no network access needed.
#
# Usage: ./tests/run_tests.sh
set -uo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$TEST_DIR")"
SAMPLE_PCAP="$TEST_DIR/sample.pcapng"
SCRATCH_DIR=$(mktemp -d)
trap 'rm -rf "$SCRATCH_DIR"' EXIT

PASSED_COUNT=0
FAILED_COUNT=0

pass() { echo "[PASS] $1"; PASSED_COUNT=$((PASSED_COUNT+1)); }
fail() { echo "[FAIL] $1"; FAILED_COUNT=$((FAILED_COUNT+1)); }

command -v tshark >/dev/null || { echo "tshark is not installed, cannot run the tests"; exit 2; }
echo "Using $(tshark --version 2>/dev/null | head -1)"

#1 a normal run writes a bundle with all four files
python3 "$REPO_DIR/pktplay.py" --pcap "$SAMPLE_PCAP" --case "TLS fails to api.playbook.test" \
  --out "$SCRATCH_DIR/out" >"$SCRATCH_DIR/run.log" 2>&1
RUN_EXIT_CODE=$?
BUNDLE_DIR=$(ls -d "$SCRATCH_DIR"/out/bundle_* 2>/dev/null | head -1)
if [[ $RUN_EXIT_CODE -eq 0 && -n "$BUNDLE_DIR" ]]; then
  pass "pktplay.py exits 0 and writes a bundle folder"
else
  fail "pktplay.py run failed (exit $RUN_EXIT_CODE)"
  cat "$SCRATCH_DIR/run.log"
  exit 1
fi
for BUNDLE_FILE in timeline.md filters.txt case_min.pcapng MANIFEST.txt; do
  if [[ -s "$BUNDLE_DIR/$BUNDLE_FILE" ]]; then
    pass "bundle has $BUNDLE_FILE"
  else
    fail "bundle is missing $BUNDLE_FILE"
  fi
done

#2 the timeline matches the expected one line for line (the first line holds the run time, so it is skipped)
tail -n +2 "$BUNDLE_DIR/timeline.md" >"$SCRATCH_DIR/timeline_body.md"
if diff -u "$TEST_DIR/expected_timeline.md" "$SCRATCH_DIR/timeline_body.md" >"$SCRATCH_DIR/timeline.diff"; then
  pass "timeline.md matches tests/expected_timeline.md"
else
  fail "timeline.md differs from tests/expected_timeline.md"
  cat "$SCRATCH_DIR/timeline.diff"
fi

#3 every timeline reason the README lists shows up at least once
for EXPECTED_REASON in "DHCP Discover" "DHCP ACK" "DNS query" "DNS response missing.playbook.test NXDOMAIN" \
  "TCP SYN" "TCP RST" "TLS alert fatal unknown_ca" "TLS handshake ClientHello" \
  "ICMP destination unreachable, port unreachable" "ICMPv6 echo request" "TCP retransmission"; do
  if grep -q "$EXPECTED_REASON" "$BUNDLE_DIR/timeline.md"; then
    pass "timeline has \"$EXPECTED_REASON\""
  else
    fail "timeline has no \"$EXPECTED_REASON\""
  fi
done

#4 private addresses are masked and the documentation range server is not
if grep -q "192\.168\.50\." "$BUNDLE_DIR/timeline.md" || grep -qi "fd00:50::" "$BUNDLE_DIR/timeline.md"; then
  fail "timeline leaks a private address"
else
  pass "private IPv4 and IPv6 addresses are masked"
fi
if grep -q "198\.51\.100\.10" "$BUNDLE_DIR/timeline.md"; then
  pass "public address is left readable"
else
  fail "public address 198.51.100.10 is missing from the timeline"
fi

#5 filters.txt matches, and each filter in it is valid and matches the expected packet count
if diff -u "$TEST_DIR/expected_filters.txt" "$BUNDLE_DIR/filters.txt" >"$SCRATCH_DIR/filters.diff"; then
  pass "filters.txt matches tests/expected_filters.txt"
else
  fail "filters.txt differs from tests/expected_filters.txt"
  cat "$SCRATCH_DIR/filters.diff"
fi
while IFS='|' read -r FILTER_NAME EXPECTED_COUNT; do
  [[ -z "$FILTER_NAME" || "$FILTER_NAME" == \#* ]] && continue
  FILTER_TEXT=$(awk -v WANTED="# $FILTER_NAME" 'FOUND { print; exit } $0 == WANTED { FOUND=1 }' "$BUNDLE_DIR/filters.txt")
  ACTUAL_COUNT=$(tshark -r "$SAMPLE_PCAP" -Y "$FILTER_TEXT" 2>"$SCRATCH_DIR/filter.err" | wc -l | tr -d ' ')
  if [[ -s "$SCRATCH_DIR/filter.err" ]] && grep -qv "Running as user" "$SCRATCH_DIR/filter.err"; then
    fail "filter $FILTER_NAME is rejected by tshark: $(grep -v 'Running as user' "$SCRATCH_DIR/filter.err" | head -1)"
  elif [[ "$ACTUAL_COUNT" == "$EXPECTED_COUNT" ]]; then
    pass "filter $FILTER_NAME matches $ACTUAL_COUNT packets"
  else
    fail "filter $FILTER_NAME matches $ACTUAL_COUNT packets, expected $EXPECTED_COUNT"
  fi
done <"$TEST_DIR/expected_filter_counts.txt"

#6 the trimmed pcap holds exactly the packets that match the union filter
UNION_EXPECTED=$(awk -F'|' '$1 == "minimal union" { print $2 }' "$TEST_DIR/expected_filter_counts.txt")
TRIMMED_COUNT=$(tshark -r "$BUNDLE_DIR/case_min.pcapng" 2>/dev/null | wc -l | tr -d ' ')
SAMPLE_COUNT=$(tshark -r "$SAMPLE_PCAP" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$TRIMMED_COUNT" == "$UNION_EXPECTED" && "$TRIMMED_COUNT" -lt "$SAMPLE_COUNT" ]]; then
  pass "case_min.pcapng keeps $TRIMMED_COUNT of $SAMPLE_COUNT packets"
else
  fail "case_min.pcapng has $TRIMMED_COUNT packets, expected $UNION_EXPECTED of $SAMPLE_COUNT"
fi

#7 the manifest names the case, the event count and every file
EXPECTED_EVENTS=$(grep -c '^- ' "$TEST_DIR/expected_timeline.md")
if grep -q "^Case: TLS fails to api.playbook.test$" "$BUNDLE_DIR/MANIFEST.txt" \
  && grep -q "^Timeline events: $EXPECTED_EVENTS$" "$BUNDLE_DIR/MANIFEST.txt" \
  && grep -q "timeline.md" "$BUNDLE_DIR/MANIFEST.txt" \
  && grep -q "filters.txt" "$BUNDLE_DIR/MANIFEST.txt" \
  && grep -q "case_min.pcapng" "$BUNDLE_DIR/MANIFEST.txt"; then
  pass "MANIFEST.txt lists the case, $EXPECTED_EVENTS events and the files"
else
  fail "MANIFEST.txt is missing the case, the event count or a file name"
fi

#8 a capture with nothing of interest gives the empty timeline message
tshark -r "$SAMPLE_PCAP" -Y "arp" -w "$SCRATCH_DIR/arp_only.pcapng" 2>/dev/null
python3 "$REPO_DIR/pktplay.py" --pcap "$SCRATCH_DIR/arp_only.pcapng" --out "$SCRATCH_DIR/empty" >/dev/null 2>&1
if grep -q "No events captured" "$SCRATCH_DIR"/empty/bundle_*/timeline.md 2>/dev/null; then
  pass "ARP only capture gives the empty timeline message"
else
  fail "ARP only capture did not give the empty timeline message"
fi

#9 a missing input file is an error, not an empty bundle
if python3 "$REPO_DIR/pktplay.py" --pcap "$SCRATCH_DIR/does_not_exist.pcapng" --out "$SCRATCH_DIR/missing" >/dev/null 2>&1; then
  fail "missing pcap should exit non-zero"
else
  pass "missing pcap exits non-zero"
fi

echo "Summary: $PASSED_COUNT passed, $FAILED_COUNT failed"
[[ $FAILED_COUNT -eq 0 ]]
