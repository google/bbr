#!/bin/bash
#
# Capture SYN and SYN/ACK packets from 127.0.0.1 to 127.0.0.1 and store
# their TS val in a file. Make sure the TS val is monotonically increasing.

declare -r PACKETS=5
declare -r OUT="/tmp/ts.out"

../common/defaults.sh

rm -f "$OUT"

tcpdump -i lo -n -c "$PACKETS" \
    "src 127.0.0.1 and dst 127.0.0.1 and (tcp[tcpflags] & tcp-syn != 0)" \
    2>/dev/null | \
    sed -e "s/.*TS val //" | \
    cut -d " " -f 1 > "$OUT" &
TCP_DUMP_PID=$!

# Give tcpdump a moment to startup and start catching packets
sleep 1

# Provide some packets for tcpdump to exit quickly.
# Give it one more than should be required.
for i in $(seq 0 "$PACKETS"); do
  echo aaa | telnet 127.0.0.1 22
done

wait $TCP_DUMP_PID

DIFFER=$(cmp /tmp/ts.out <(sort -n "$OUT"))
if [[ -n "$DIFFER" ]]; then
  cat "$OUT"
  echo "FAIL"
  exit 1
fi

echo "PASS"
exit 0
