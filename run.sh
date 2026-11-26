#!/usr/bin/env bash
# Usage: ./run.sh <command> [arguments]     e.g.  ./run.sh dpi-mt sample/test_dpi.pcap out.pcap --block-app YouTube
cd "$(dirname "$0")"
[ -f out/packet-analyzer.jar ] || ./build.sh
exec java -jar out/packet-analyzer.jar "$@"
