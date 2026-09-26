"""
Model Context Protocol Guard: deny-by-default security proxy for Model Context Protocol servers.
"""

from __future__ import annotations

from .pipeline import GuardConfig, GuardPipeline

__version__ = "0.1.0"

__all__ = ["GuardConfig", "GuardPipeline", "__version__"]
