from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


def _narrative_words() -> set[str]:
    from zero_trust_agent_benchmark.generator import narrative_words

    return set(narrative_words())


def _regex_literals() -> list[tuple[Path, int, str]]:
    regexes: list[tuple[Path, int, str]] = []
    for path in SRC_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else ""
            if name not in {"compile", "search", "match", "fullmatch"}:
                continue
            try:
                pattern = ast.literal_eval(node.args[0])
            except (TypeError, ValueError):
                continue
            if isinstance(pattern, str):
                regexes.append((path, node.lineno, pattern))
    return regexes


def test_no_high_signal_azt_generator_literals_in_src() -> None:
    try:
        from zero_trust_agent_benchmark.generator import literal_tokens
    except Exception as exc:  # pragma: no cover - dependency is installed for dev/bench checks
        pytest.skip(f"zero-trust-agent-benchmark literal token API unavailable: {exc}")

    source = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore").lower() for p in SRC_ROOT.rglob("*.py")
    )
    high_signal = {token for token in literal_tokens() if len(token) >= 12}
    assert sorted(token for token in high_signal if token in source) == []


def test_regex_alternations_do_not_match_benchmark_narrative_words() -> None:
    try:
        forbidden = _narrative_words()
    except Exception as exc:  # pragma: no cover - dependency is installed for dev/bench checks
        pytest.skip(f"zero-trust-agent-benchmark word API unavailable: {exc}")

    failures = []
    for path, line, pattern in _regex_literals():
        if "|" not in pattern:
            continue
        alternation_words = set(re.findall(r"[a-z]{3,}", pattern.lower()))
        overlap = sorted(alternation_words & forbidden)
        if overlap:
            rel = path.relative_to(SRC_ROOT)
            failures.append(f"{rel}:{line}: {', '.join(overlap)}")

    assert failures == []
