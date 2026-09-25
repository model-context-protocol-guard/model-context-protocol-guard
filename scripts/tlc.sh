#!/usr/bin/env bash
set -euo pipefail
if command -v java >/dev/null 2>&1 && [ -f "C:/Parag/github/ztap/_tools/tla2tools.jar" ]; then
  java -XX:+UseParallelGC -cp "C:/Parag/github/ztap/_tools/tla2tools.jar" tlc2.TLC -workers auto -config specs/PinnedTools.cfg specs/PinnedTools.tla
elif command -v java >/dev/null 2>&1 && [ -f "/tools/tla2tools.jar" ]; then
  java -XX:+UseParallelGC -cp "/tools/tla2tools.jar" tlc2.TLC -workers auto -config specs/PinnedTools.cfg specs/PinnedTools.tla
else
  echo "SKIP TLC: java or tla2tools.jar not available"
fi
