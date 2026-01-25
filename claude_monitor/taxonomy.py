"""
Tool Classification Taxonomy for Claude Code

Classification dimensions:
1. external_contact: Does this tool contact the external world?
2. direction: READ (data flows in), WRITE (data flows out), READ-WRITE (both)
3. injection_risk: Can external data influence Claude's behavior?
4. action_risk: Can this tool cause persistent changes?
"""

TOOL_CLASSIFICATION = {
    # =========================================================================
    # FILESYSTEM TOOLS
    # =========================================================================
    "Read": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "HIGH",      # File contents can contain prompt injection
        "action_risk": "NONE",
        "description": "Reads file contents from filesystem",
    },
    "Write": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "WRITE",
        "injection_risk": "NONE",
        "action_risk": "HIGH",         # Can create/overwrite any file
        "description": "Creates or overwrites files",
    },
    "Edit": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "WRITE",
        "injection_risk": "NONE",
        "action_risk": "HIGH",         # Can modify any file
        "description": "Modifies existing files with string replacement",
    },
    "Glob": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "LOW",       # Only returns file paths, not contents
        "action_risk": "NONE",
        "description": "Lists files matching glob patterns",
    },
    "Grep": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "MEDIUM",    # Returns file contents (matching lines)
        "action_risk": "NONE",
        "description": "Searches file contents with regex",
    },
    "NotebookEdit": {
        "category": "filesystem",
        "external_contact": True,
        "direction": "WRITE",
        "injection_risk": "NONE",
        "action_risk": "HIGH",
        "description": "Modifies Jupyter notebook cells",
    },

    # =========================================================================
    # NETWORK TOOLS
    # =========================================================================
    "WebFetch": {
        "category": "network",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "CRITICAL",  # Fetches arbitrary URLs - major injection vector
        "action_risk": "NONE",
        "description": "Fetches and processes web page content",
    },
    "WebSearch": {
        "category": "network",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "HIGH",      # Search results can contain injection
        "action_risk": "NONE",
        "description": "Performs web searches",
    },

    # =========================================================================
    # SHELL / PROCESS TOOLS
    # =========================================================================
    "Bash": {
        "category": "shell",
        "external_contact": True,
        "direction": "READ-WRITE",
        "injection_risk": "HIGH",      # Command output can contain injection
        "action_risk": "CRITICAL",     # Can execute any command
        "description": "Executes shell commands",
    },
    "KillShell": {
        "category": "shell",
        "external_contact": True,
        "direction": "WRITE",
        "injection_risk": "NONE",
        "action_risk": "MEDIUM",
        "description": "Terminates background shell processes",
    },

    # =========================================================================
    # SUBAGENT / TASK TOOLS
    # =========================================================================
    "Task": {
        "category": "subagent",
        "external_contact": True,
        "direction": "READ-WRITE",
        "injection_risk": "HIGH",      # Subagent output flows back to main agent
        "action_risk": "VARIABLE",
        "description": "Spawns subagent to handle complex tasks",
    },
    "TaskOutput": {
        "category": "subagent",
        "external_contact": False,
        "direction": "READ",
        "injection_risk": "MEDIUM",    # Task output could be tainted
        "action_risk": "NONE",
        "description": "Retrieves output from background task",
    },

    # =========================================================================
    # INTERNAL / UI TOOLS
    # =========================================================================
    "TodoWrite": {
        "category": "internal",
        "external_contact": False,
        "direction": "WRITE",
        "injection_risk": "NONE",
        "action_risk": "NONE",
        "description": "Manages internal task list",
    },
    "AskUserQuestion": {
        "category": "internal",
        "external_contact": False,
        "direction": "READ",
        "injection_risk": "LOW",
        "action_risk": "NONE",
        "description": "Prompts user for input",
    },
    "EnterPlanMode": {
        "category": "internal",
        "external_contact": False,
        "direction": "NONE",
        "injection_risk": "NONE",
        "action_risk": "NONE",
        "description": "Switches to planning mode",
    },
    "ExitPlanMode": {
        "category": "internal",
        "external_contact": False,
        "direction": "NONE",
        "injection_risk": "NONE",
        "action_risk": "NONE",
        "description": "Exits planning mode",
    },

    # =========================================================================
    # SKILL TOOLS
    # =========================================================================
    "Skill": {
        "category": "skill",
        "external_contact": True,
        "direction": "READ-WRITE",
        "injection_risk": "VARIABLE",
        "action_risk": "VARIABLE",
        "description": "Executes a registered skill",
    },

    # =========================================================================
    # MCP TOOLS
    # =========================================================================
    "mcp__ide__getDiagnostics": {
        "category": "mcp",
        "external_contact": True,
        "direction": "READ",
        "injection_risk": "LOW",
        "action_risk": "NONE",
        "description": "Gets language diagnostics from VS Code",
    },
    "mcp__ide__executeCode": {
        "category": "mcp",
        "external_contact": True,
        "direction": "READ-WRITE",
        "injection_risk": "HIGH",
        "action_risk": "CRITICAL",
        "description": "Executes code in Jupyter kernel",
    },
}

MCP_DEFAULT = {
    "category": "mcp",
    "external_contact": True,
    "direction": "READ-WRITE",
    "injection_risk": "MEDIUM",
    "action_risk": "MEDIUM",
    "description": "Unknown MCP tool",
}

UNKNOWN_DEFAULT = {
    "category": "unknown",
    "external_contact": True,
    "direction": "READ-WRITE",
    "injection_risk": "UNKNOWN",
    "action_risk": "UNKNOWN",
    "description": "Unknown tool",
}


def get_tool_classification(tool_name: str) -> dict:
    """Get classification for a tool, with fallbacks for unknown tools."""
    if tool_name in TOOL_CLASSIFICATION:
        return TOOL_CLASSIFICATION[tool_name]
    if tool_name and tool_name.startswith("mcp__"):
        return {**MCP_DEFAULT, "description": f"MCP tool: {tool_name}"}
    return {**UNKNOWN_DEFAULT, "description": f"Unknown tool: {tool_name}"}


def compute_risk_level(classification: dict, event_type: str) -> str:
    """Compute overall risk level from classification."""
    if event_type == "UserPromptSubmit":
        return "INPUT"

    injection = classification.get("injection_risk", "UNKNOWN")
    action = classification.get("action_risk", "UNKNOWN")
    external = classification.get("external_contact", True)
    direction = classification.get("direction", "UNKNOWN")

    if injection == "CRITICAL" or action == "CRITICAL":
        level = "CRITICAL"
    elif injection == "HIGH" or action == "HIGH":
        level = "HIGH"
    elif injection == "MEDIUM" or action == "MEDIUM":
        level = "MEDIUM"
    elif injection == "LOW" or action == "LOW":
        level = "LOW"
    elif injection == "NONE" and action == "NONE":
        level = "MINIMAL"
    else:
        level = "UNKNOWN"

    if external:
        if direction == "READ":
            return f"EXT-READ-{level}"
        elif direction == "WRITE":
            return f"EXT-WRITE-{level}"
        elif direction == "READ-WRITE":
            return f"EXT-RW-{level}"
        else:
            return f"EXT-{level}"
    else:
        return f"INT-{level}"
