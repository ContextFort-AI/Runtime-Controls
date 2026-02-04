#!/usr/bin/env python3
import json
import sys

from analytics import track_hook, track_block

from bash_guard import check_command
from tool_guard.registry import (
    check_bash_write_external,
    get_unknown_bash_commands,
    learn_bash_patterns,
    save_bash_patterns,
)

MCP_WRITE_KEYWORDS = {
    "create", "write", "update", "edit", "delete", "remove",
    "add", "post", "put", "send", "push", "insert", "modify",
    "publish", "upload", "submit", "transition", "comment",
}


def is_mcp_write_tool(tool_name):
    if not tool_name.startswith("mcp__"):
        return False
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in MCP_WRITE_KEYWORDS)


def handle_pre_tool_use(data):
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if is_mcp_write_tool(tool_name):
        track_block("mcp_write_external")
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    f"Write-external MCP tool: {tool_name}\n\n"
                    f"Params: {json.dumps(tool_input, indent=2)}"
                )
            }
        }

    elif tool_name == "Bash":
        command = tool_input.get("command", "")

        security_result = check_command(command)
        if security_result:
            rule_id, description = security_result
            track_block("tirith")
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        f"⚠️ TIRITH: {description}\n"
                        f"Rule: {rule_id}\n\n"
                        f"Command: {command}"
                    )
                }
            }

        is_write, pattern = check_bash_write_external(command)

        if is_write is None:
            for cmd_name in get_unknown_bash_commands(command):
                patterns = learn_bash_patterns(cmd_name)
                save_bash_patterns(cmd_name, patterns)
            is_write, pattern = check_bash_write_external(command)

        if is_write:
            track_block("write_external")
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        f"Write-external: {pattern}\n\n"
                        f"Command: {command}"
                    )
                }
            }

    return {}


def main():
    data = json.load(sys.stdin)
    event = data.get("hook_event_name", "")

    track_hook(event)

    if event == "PreToolUse":
        result = handle_pre_tool_use(data)
    else:
        result = {}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
