#!/usr/bin/env bash
# Compiles the project and creates out/packet-analyzer.jar  (needs a JDK 17 or newer)
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out
mkdir -p out/classes
javac --release 17 -Xlint:all -d out/classes $(find src/main -name '*.java')
printf 'Main-Class: com.nishant.packetanalyzer.Main\n' > out/manifest.txt
jar cfm out/packet-analyzer.jar out/manifest.txt -C out/classes .
echo "Built out/packet-analyzer.jar"
