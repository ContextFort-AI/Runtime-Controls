"""
Session management for prompt tracking and state.
"""

import json
from pathlib import Path
from datetime import datetime

# Session data directory
SESSIONS_DIR = Path.home() / ".claude" / "runtime-monitor" / "sessions"


def get_session(session_id):
    """
    Load session data for a given session ID.

    Args:
        session_id: Unique session identifier

    Returns:
        Dict with session data (prompts, external_reads, pending_warning)
    """
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_file = SESSIONS_DIR / f"{session_id}.json"
    if session_file.exists():
        return json.loads(session_file.read_text())
    return {"prompts": [], "external_reads": [], "pending_warning": None}


def save_session(session_id, session_data):
    """
    Save session data.

    Args:
        session_id: Unique session identifier
        session_data: Dict with session data to save
    """
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_file = SESSIONS_DIR / f"{session_id}.json"
    session_file.write_text(json.dumps(session_data, indent=2))


def add_prompt(session_id, prompt):
    """
    Add a user prompt to the session.

    Args:
        session_id: Unique session identifier
        prompt: The user's prompt text
    """
    session = get_session(session_id)
    session["prompts"].append({
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt
    })
    save_session(session_id, session)


def get_recent_prompts(session_id, count=5):
    """
    Get the most recent user prompts.

    Args:
        session_id: Unique session identifier
        count: Number of recent prompts to return

    Returns:
        List of recent prompt dicts
    """
    session = get_session(session_id)
    return session.get("prompts", [])[-count:]


def add_external_read(session_id, tool_name, tool_input, content, injection_check):
    """
    Record an external read operation and its injection check result.

    Args:
        session_id: Unique session identifier
        tool_name: Name of the tool used
        tool_input: Input parameters to the tool
        content: Extracted attacker-controllable content
        injection_check: Result of injection check
    """
    session = get_session(session_id)
    session["external_reads"].append({
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "input": tool_input,
        "extracted_content": content,
        "injection_check": injection_check
    })
    save_session(session_id, session)


def set_pending_warning(session_id, warning_type, tool_name, message):
    """
    Set a pending warning that will block the next tool execution.

    Args:
        session_id: Unique session identifier
        warning_type: Type of warning (e.g., "injection")
        tool_name: Tool that triggered the warning
        message: Warning message
    """
    session = get_session(session_id)
    session["pending_warning"] = {
        "type": warning_type,
        "tool": tool_name,
        "message": message
    }
    save_session(session_id, session)


def clear_pending_warning(session_id):
    """
    Clear the pending warning.

    Args:
        session_id: Unique session identifier

    Returns:
        The warning that was cleared, or None
    """
    session = get_session(session_id)
    warning = session.get("pending_warning")
    session["pending_warning"] = None
    save_session(session_id, session)
    return warning
