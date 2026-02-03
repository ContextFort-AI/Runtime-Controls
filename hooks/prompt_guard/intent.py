"""
User intent verification for external tool calls.

Ensures tool calls align with what the user actually asked for,
reducing decision fatigue by auto-approving aligned operations.
"""

import json
from .llm import ask_haiku


def check_user_intent(user_prompts, tool_name, tool_input):
    """
    Verify if a tool call matches the user's intent.

    Analyzes recent user prompts to determine if the proposed
    tool call aligns with what the user asked for.

    Args:
        user_prompts: List of recent user prompt dicts
        tool_name: Name of the tool being called
        tool_input: Parameters for the tool call

    Returns:
        String: "ALLOWED" if matches intent, "BLOCKED: <reason>" if not
    """
    system = """You verify if a tool call matches user intent.
Check if this tool call aligns with what the user asked for.

Respond ONLY with:
ALLOWED - if it matches user intent
BLOCKED: <brief reason> - if it does NOT match user intent"""

    prompts_str = "\n".join([p["prompt"] for p in user_prompts[-5:]])
    params_str = json.dumps(tool_input, indent=2)

    user = f"User prompts:\n{prompts_str}\n\nTool: {tool_name}\nParams:\n{params_str}"
    return ask_haiku(system, user)
