#!/usr/bin/env bash
set -euo pipefail
if [ -d "/wheels" ]; then
  python -m pip install -q --no-index --find-links /wheels hatchling editables
elif [ -d "C:/Parag/github/ztap/_wheelhouse" ]; then
  python -m pip install -q --no-index --find-links "C:/Parag/github/ztap/_wheelhouse" hatchling editables || python -m pip install -q hatchling editables
else
  python -m pip install -q hatchling editables
fi
python -m pip install -q --no-build-isolation -e ".[dev]"
if [ -d "../azt-bench" ]; then
  python -m pip install -q --no-build-isolation --no-deps -e "../azt-bench"
elif [ -d "/azt-bench" ]; then
  python -m pip install -q --no-build-isolation --no-deps -e "/azt-bench"
fi
ruff check .
ruff format --check .
mypy src
pytest -q --cov=mcp_guard --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
