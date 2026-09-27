#!/usr/bin/env bash
set -euo pipefail
if [ -d "/wheels" ]; then
  python -m pip install -q --no-index --find-links /wheels hatchling editables
else
  python -m pip install -q hatchling editables
fi
python -m pip install -q --no-build-isolation -e ".[dev]"
if [ -d "../zero-trust-agent-benchmark" ]; then
  python -m pip install -q --no-build-isolation --no-deps -e "../zero-trust-agent-benchmark"
elif [ -d "/zero-trust-agent-benchmark" ]; then
  python -m pip install -q --no-build-isolation --no-deps -e "/zero-trust-agent-benchmark"
elif [ "${CI:-}" = "true" ]; then
  python -m pip install -q "zero-trust-agent-benchmark @ git+https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark@v0.1.0"
fi
ruff check .
ruff format --check .
mypy src
pytest -q --cov=model_context_protocol_guard --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
