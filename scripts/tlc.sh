#!/usr/bin/env bash
set -euo pipefail
jar="${TLA_TOOLS_JAR:-/tools/tla2tools.jar}"
if command -v java >/dev/null 2>&1 && [ -f "$jar" ]; then
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -config specs/PinnedTools.cfg specs/PinnedTools.tla
else
  echo "SKIP TLC: java or tla2tools.jar not available"
fi
