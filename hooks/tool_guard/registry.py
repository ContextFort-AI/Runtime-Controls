import json
import re
import subprocess
import os
from pathlib import Path

WATCHED_FILE = Path(__file__).parent / "watched_tools.json"


def _load_config():
    """Load watched_tools.json config."""
    if WATCHED_FILE.exists():
        return json.loads(WATCHED_FILE.read_text())
    return {"mcp-write-external": [], "bash-write-external": {}}


def _save_config(config):
    """Save watched_tools.json config."""
    WATCHED_FILE.write_text(json.dumps(config, indent=2))


def is_mcp_write_external(tool_name):
    """Check if an MCP tool writes to external systems."""
    config = _load_config()
    return tool_name in config.get("mcp-write-external", [])


def get_bash_command_name(command):
    """Extract the base command name from a bash command string."""
    # Handle pipes - get first command
    first_part = command.split("|")[0].strip()

    # Handle env vars at start (VAR=val cmd)
    parts = first_part.split()
    for part in parts:
        if "=" in part:
            continue
        # Skip sudo, env, etc.
        base = part.rsplit("/", 1)[-1].lower()
        if base in ("sudo", "env", "nohup", "time", "nice"):
            continue
        return base

    return None


def get_bash_patterns(cmd_name):
    """Get write-external patterns for a bash command."""
    config = _load_config()
    return config.get("bash-write-external", {}).get(cmd_name, None)


def save_bash_patterns(cmd_name, patterns):
    """Save write-external patterns for a bash command."""
    config = _load_config()
    if "bash-write-external" not in config:
        config["bash-write-external"] = {}
    config["bash-write-external"][cmd_name] = patterns
    _save_config(config)


def check_bash_write_external(command):
    """
    Check if a bash command matches any write-external patterns.
    Returns (matches, pattern) if found, (False, None) otherwise.
    """
    cmd_name = get_bash_command_name(command)
    if not cmd_name:
        return False, None

    patterns = get_bash_patterns(cmd_name)
    if patterns is None:
        return None, None  # Unknown command, needs learning

    if not patterns:
        return False, None  # Known command, no write-external patterns

    # Check if command matches any pattern
    for pattern in patterns:
        try:
            if re.search(pattern, command, re.IGNORECASE):
                return True, pattern
        except re.error:
            continue

    return False, None


def fetch_command_help(cmd_name):
    """Fetch man page or --help for a command."""
    help_text = ""

    # Try man page first (summary only)
    try:
        result = subprocess.run(
            ["man", "-f", cmd_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            help_text += f"WHATIS:\n{result.stdout}\n\n"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Try --help
    try:
        result = subprocess.run(
            [cmd_name, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "LANG": "C"}
        )
        output = result.stdout or result.stderr
        # Truncate to first 2000 chars
        if output:
            help_text += f"HELP:\n{output[:2000]}\n"
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    # Try man page full (truncated)
    if not help_text:
        try:
            result = subprocess.run(
                ["man", cmd_name],
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "LANG": "C", "MANPAGER": "cat"}
            )
            if result.returncode == 0:
                help_text = result.stdout[:3000]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return help_text or f"No documentation found for {cmd_name}"


def learn_bash_patterns(cmd_name):
    """
    Learn write-external patterns for a command using LLM analysis.

    Args:
        cmd_name: The command name to analyze

    Returns:
        List of regex patterns for write-external operations
    """
    # Import here to avoid circular dependency
    from prompt_guard.llm import ask_haiku

    help_text = fetch_command_help(cmd_name)

    system = """You analyze command documentation to identify regex patterns for WRITE-EXTERNAL operations.

WRITE-EXTERNAL means: sending data OUT of the local machine (uploads, remote writes, API calls, network sends).
NOT write-external: reading, downloading, local file operations, displaying output.

Return ONLY a JSON array of regex patterns. If no write-external operations, return [].

Examples:
- scp: ["scp\\s+.*\\s+.*@.*:"]
- curl: ["curl\\s+.*(-X\\s*(POST|PUT|PATCH|DELETE)|--data|--upload|-F\\s)"]
- cat: []
- ls: []"""

    user = f"Command: {cmd_name}\n\nDocumentation:\n{help_text}"

    response = ask_haiku(system, user)

    # Parse JSON response
    try:
        # Extract JSON array from response
        match = re.search(r'\[.*\]', response, re.DOTALL)
        if match:
            patterns = json.loads(match.group())
            if isinstance(patterns, list):
                # Validate patterns are valid regex
                valid_patterns = []
                for p in patterns:
                    if isinstance(p, str):
                        try:
                            re.compile(p)
                            valid_patterns.append(p)
                        except re.error:
                            pass
                return valid_patterns
    except json.JSONDecodeError:
        pass

    return []  # Default to no patterns if parsing fails
