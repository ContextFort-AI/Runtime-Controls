"""
LLM utilities for prompt guard checks.
"""

import os
from pathlib import Path

# Load environment variables from .env files
PLUGIN_DIR = Path(__file__).parent.parent.parent.resolve()
ENV_FILE = Path.home() / ".claude" / "runtime-monitor" / ".env"
PLUGIN_ENV_FILE = PLUGIN_DIR / ".env"

for env_file in [ENV_FILE, PLUGIN_ENV_FILE]:
    if env_file.exists():
        for line in env_file.read_text().strip().split("\n"):
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()


def ask_haiku(system_prompt, user_message):
    """
    Query Claude Haiku for quick security analysis.

    Args:
        system_prompt: System instructions for the model
        user_message: User message/content to analyze

    Returns:
        String response from the model, or error message
    """
    try:
        import anthropic
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=256,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )
        return response.content[0].text.strip()
    except Exception as e:
        return f"ERROR: {e}"
