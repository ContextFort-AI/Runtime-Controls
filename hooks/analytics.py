"""
Anonymous usage analytics via PostHog.
Only tracks: plugin is being used, nothing about commands or content.

To opt-out: set CONTEXTFORT_NO_ANALYTICS=1
"""

import os
import uuid
import threading
from pathlib import Path

# Check opt-out first
ANALYTICS_DISABLED = os.environ.get("CONTEXTFORT_NO_ANALYTICS", "").lower() in ("1", "true", "yes")

# Anonymous installation ID (persisted locally)
ID_FILE = Path(__file__).parent / ".install_id"

def _get_install_id():
    """Get or create anonymous installation ID."""
    if ID_FILE.exists():
        return ID_FILE.read_text().strip()
    install_id = str(uuid.uuid4())
    try:
        ID_FILE.write_text(install_id)
    except:
        pass
    return install_id

INSTALL_ID = _get_install_id() if not ANALYTICS_DISABLED else None

# PostHog setup
POSTHOG_API_KEY = "phc_XXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # Replace with your key
POSTHOG_HOST = "https://us.i.posthog.com"

_posthog = None

def _init_posthog():
    """Lazy init PostHog client."""
    global _posthog
    if _posthog is None and not ANALYTICS_DISABLED:
        try:
            import posthog
            posthog.project_api_key = POSTHOG_API_KEY
            posthog.host = POSTHOG_HOST
            posthog.debug = False
            posthog.sync_mode = False  # Async by default
            _posthog = posthog
        except ImportError:
            pass
    return _posthog


def track(event: str, properties: dict = None):
    """
    Track an event asynchronously. Non-blocking.

    Events:
    - "hook_invoked": Plugin hook was called
    - "security_block": Tirith blocked a command
    - "write_external_detected": Write-external pattern matched
    - "injection_detected": Prompt injection detected
    """
    if ANALYTICS_DISABLED or not INSTALL_ID:
        return

    def _send():
        try:
            ph = _init_posthog()
            if ph:
                ph.capture(
                    distinct_id=INSTALL_ID,
                    event=event,
                    properties=properties or {}
                )
        except:
            pass  # Never fail the hook due to analytics

    # Fire and forget in background thread
    threading.Thread(target=_send, daemon=True).start()


def track_hook(hook_type: str):
    """Track that a hook was invoked."""
    track("hook_invoked", {"hook_type": hook_type})


def track_block(rule_type: str):
    """Track that something was blocked/flagged."""
    track("security_event", {"rule_type": rule_type})
