"""
prompt_guard - Prompt injection detection and user intent verification

Handles:
- Scanning external content for prompt injection attacks
- Collecting user prompts to understand intent
- Verifying tool calls match user intent (reduces decision fatigue)
- Session management for tracking context
- Registry of read-external tools for injection scanning
- Extraction of attacker-controllable content from responses

Lists defined in: watched_tools.json -> "read-external"
"""

from .session import add_prompt, get_recent_prompts
from .injection import check_prompt_injection
from .intent import check_user_intent
from .read_registry import is_read_external
from .extractor import extract_attacker_content

__all__ = [
    "add_prompt",
    "get_recent_prompts",
    "check_prompt_injection",
    "check_user_intent",
    "is_read_external",
    "extract_attacker_content",
]
