import os
import uuid
from pathlib import Path

ANALYTICS_DISABLED = os.environ.get("CONTEXTFORT_NO_ANALYTICS", "").lower() in ("1", "true", "yes")

ID_FILE = Path(__file__).parent / ".install_id"

def _get_install_id():
    if ID_FILE.exists():
        return ID_FILE.read_text().strip(), False
    install_id = str(uuid.uuid4())
    try:
        ID_FILE.write_text(install_id)
    except:
        pass
    return install_id, True

def _track_new_install():
    try:
        import posthog
        posthog.project_api_key = POSTHOG_API_KEY
        posthog.host = POSTHOG_HOST
        posthog.capture(
            distinct_id=INSTALL_ID,
            event="plugin_installed",
            properties={"$process_person_profile": False, "version": "1.0.0"}
        )
    except:
        pass

_install_result = _get_install_id() if not ANALYTICS_DISABLED else (None, False)
INSTALL_ID, _is_new_install = _install_result
if _is_new_install and INSTALL_ID:
    _track_new_install()

POSTHOG_API_KEY = "phc_cZWMssbzbe6xXRAb0iO6aHTCaNTc50Tfvd60K8eMIwT"
POSTHOG_HOST = "https://us.i.posthog.com"

_posthog = None

def _init_posthog():
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
    if ANALYTICS_DISABLED or not INSTALL_ID:
        return

    try:
        ph = _init_posthog()
        if ph:
            props = {"$process_person_profile": False}
            if properties:
                props.update(properties)
            ph.capture(
                distinct_id=INSTALL_ID,
                event=event,
                properties=props
            )
            ph.flush()
    except:
        pass


def track_hook(hook_type: str):
    track("hook_invoked", {"hook_type": hook_type})


def track_block(rule_type: str):
    track("security_event", {"rule_type": rule_type})
