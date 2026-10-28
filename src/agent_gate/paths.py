"""Project-root resolution. Overridable per run (evals use a temp dir)."""
from __future__ import annotations

import os
from pathlib import Path

_DEFAULT = Path(__file__).resolve().parent.parent.parent
_root: Path = Path(os.environ.get("AGENT_GATE_ROOT", _DEFAULT))


def set_root(path: str | Path) -> None:
    global _root
    _root = Path(path)


def get_root() -> Path:
    return _root


def sandbox_dir() -> Path:
    p = get_root() / "sandbox"
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    p = get_root() / "data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def audit_dir() -> Path:
    p = get_root() / "audit"
    p.mkdir(parents=True, exist_ok=True)
    return p


def memory_dir() -> Path:
    p = get_root() / "memory"
    p.mkdir(parents=True, exist_ok=True)
    return p


def metrics_dir() -> Path:
    p = get_root() / "metrics"
    p.mkdir(parents=True, exist_ok=True)
    return p
