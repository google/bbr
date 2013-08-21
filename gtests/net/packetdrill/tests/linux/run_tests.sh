#!/bin/bash
for f in `find . -name "*.pkt" | sort`; do
  echo "Running $f ..."
  ip tcp_metrics flush all > /dev/null 2>&1
  ../../packetdrill $f
done
