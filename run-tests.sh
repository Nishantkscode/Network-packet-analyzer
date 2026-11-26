#!/usr/bin/env bash
# Compiles main + test code and runs the self-tests.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out/test-classes
mkdir -p out/test-classes
javac --release 17 -d out/test-classes $(find src/main src/test -name '*.java')
java -cp out/test-classes com.nishant.packetanalyzer.SelfTest
