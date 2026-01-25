"""
Claude Runtime Monitor SDK
Security monitoring and audit logging for Claude Code tool calls.

Includes an embedded LLM judge for blocking suspicious write operations.
"""

__version__ = "0.2.0"
__author__ = "Security Team"

from .monitor import RuntimeMonitor
from .taxonomy import TOOL_CLASSIFICATION, get_tool_classification

# Judge imports (optional, requires llama-cpp-python)
try:
    from .judge import WriteJudge, Verdict, JudgeResult, judge_write
    from .guarded_hook import GuardedMonitor
    _JUDGE_AVAILABLE = True
except ImportError:
    _JUDGE_AVAILABLE = False
    WriteJudge = None
    Verdict = None
    JudgeResult = None
    judge_write = None
    GuardedMonitor = None

__all__ = [
    "RuntimeMonitor",
    "TOOL_CLASSIFICATION",
    "get_tool_classification",
    # Judge exports (may be None if llama-cpp-python not installed)
    "WriteJudge",
    "Verdict",
    "JudgeResult",
    "judge_write",
    "GuardedMonitor",
    "_JUDGE_AVAILABLE",
]
