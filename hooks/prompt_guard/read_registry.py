"""
Read-external tool registry - tools that fetch external content for injection scanning.

List defined in: watched_tools.json (simple array)
"""

import json
from pathlib import Path

WATCHED_FILE = Path(__file__).parent / "watched_tools.json"


def _load_tools():
    """Load watched_tools.json list."""
    if WATCHED_FILE.exists():
        return json.loads(WATCHED_FILE.read_text())
    return []


def is_read_external(tool_name):
    """Check if a tool reads from external systems."""
    return tool_name in _load_tools()
