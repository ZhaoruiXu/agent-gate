"""agent-gate: a safe tool-calling agent skeleton.

Risk-tiered tools + approval policy + hash-chained audit log + eval harness.
See README.md.
"""
from .agent import run_agent
from .audit import AuditLog
from .policy import ActorContext, PolicyEngine
from .tools import TOOLS

__version__ = "0.1.0"
__all__ = ["run_agent", "AuditLog", "PolicyEngine", "ActorContext", "TOOLS",
           "__version__"]
