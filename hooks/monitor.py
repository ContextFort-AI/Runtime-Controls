#!/usr/bin/env python3
"""
Runtime Monitor - Main hook handler

Routes hook events to appropriate security modules:
- bash_guard: Tirith-inspired bash command security
- tool_guard: External tool registry and bash pattern learning
- prompt_guard: Prompt injection detection and intent verification
"""

import json
import sys

# Analytics (non-blocking, opt-out with CONTEXTFORT_NO_ANALYTICS=1)
from analytics import track_hook, track_block

# Import from security modules
from bash_guard import check_command
from tool_guard.registry import (
    is_mcp_write_external,
    check_bash_write_external,
    get_bash_command_name,
    learn_bash_patterns,
    save_bash_patterns,
)
from prompt_guard import (
    add_prompt,
    get_recent_prompts,
    check_prompt_injection,
    check_user_intent,
    is_read_external,
    extract_attacker_content,
)
from prompt_guard.session import (
    add_external_read,
    set_pending_warning,
    clear_pending_warning,
)


def handle_user_prompt_submit(data):
    """Handle UserPromptSubmit event - record user prompts."""
    session_id = data.get("session_id", "")
    prompt = data.get("prompt", "")

    add_prompt(session_id, prompt)
    return {}


def handle_post_tool_use(data):
    """Handle PostToolUse event - scan external content for injection."""
    session_id = data.get("session_id", "")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_response = data.get("tool_response", {})

    if not is_read_external(tool_name):
        return {}

    # Extract attacker-controllable content
    attacker_content = extract_attacker_content(tool_name, tool_response)

    # Skip if no content
    if not attacker_content.strip():
        return {}

    # Check for prompt injection
    injection_check = check_prompt_injection(attacker_content, tool_name)

    # Record the read
    add_external_read(session_id, tool_name, tool_input, attacker_content, injection_check)

    # Set pending warning if injection detected
    if injection_check.startswith("INJECTION"):
        set_pending_warning(session_id, "injection", tool_name, injection_check)
        track_block("injection_detected")

    return {}


def handle_pre_tool_use(data):
    """Handle PreToolUse event - security checks before execution."""
    session_id = data.get("session_id", "")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Check for pending injection warning
    warning = clear_pending_warning(session_id)
    if warning:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"INJECTION DETECTED in {warning['tool']}:\n"
                    f"{warning['message']}\n\n"
                    f"Next tool: {tool_name}\n\n"
                    f"Re-run tool to proceed."
                )
            }
        }

    should_ask = False
    reason = ""

    # Check MCP write-external tools
    if is_mcp_write_external(tool_name):
        track_block("mcp_write_external")
        user_prompts = get_recent_prompts(session_id, count=5)
        intent_check = check_user_intent(user_prompts, tool_name, tool_input)

        should_ask = True
        if intent_check.startswith("BLOCKED"):
            reason = f"Intent check: {intent_check}\n\nTool: {tool_name}\nParams: {json.dumps(tool_input, indent=2)}"
        else:
            reason = f"Tool: {tool_name}\nIntent: {intent_check}\nParams: {json.dumps(tool_input, indent=2)}"

    # Check bash commands
    elif tool_name == "Bash":
        command = tool_input.get("command", "")

        # First: Tirith security checks (always run)
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

        # Second: Check write-external patterns
        cmd_name = get_bash_command_name(command)
        if cmd_name:
            is_write, pattern = check_bash_write_external(command)

            # Unknown command - learn patterns
            if is_write is None:
                patterns = learn_bash_patterns(cmd_name)
                save_bash_patterns(cmd_name, patterns)
                # Re-check with new patterns
                is_write, pattern = check_bash_write_external(command)

            # Command matches write-external pattern
            if is_write:
                track_block("write_external")
                user_prompts = get_recent_prompts(session_id, count=5)
                intent_check = check_user_intent(user_prompts, "Bash", tool_input)

                should_ask = True
                if intent_check.startswith("BLOCKED"):
                    reason = f"Intent check: {intent_check}\n\nWrite-external: {pattern}\n\nCommand: {command}"
                else:
                    reason = f"Write-external: {pattern}\nIntent: {intent_check}\n\nCommand: {command}"

    if should_ask:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            }
        }

    return {}


def main():
    """Main entry point - route events to handlers."""
    data = json.load(sys.stdin)
    event = data.get("hook_event_name", "")

    # Track hook invocation (anonymous, non-blocking)
    track_hook(event)

    if event == "UserPromptSubmit":
        result = handle_user_prompt_submit(data)
    elif event == "PostToolUse":
        result = handle_post_tool_use(data)
    elif event == "PreToolUse":
        result = handle_pre_tool_use(data)
    else:
        result = {}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
