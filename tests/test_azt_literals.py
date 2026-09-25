from __future__ import annotations

import pytest


def test_no_high_signal_azt_generator_literals_in_src() -> None:
    try:
        from azt_bench.generator import literal_tokens
    except Exception as exc:  # pragma: no cover - dependency is installed for dev/bench checks
        pytest.skip(f"azt-bench literal token API unavailable: {exc}")
    from pathlib import Path

    source = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore").lower()
        for p in (Path(__file__).resolve().parents[1] / "src").rglob("*.py")
    )
    high_signal = {token for token in literal_tokens() if len(token) >= 12}
    assert sorted(token for token in high_signal if token in source) == []
