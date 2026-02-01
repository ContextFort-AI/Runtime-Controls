#!/usr/bin/env python3
import json
import shutil
from pathlib import Path

CLAUDE_DIR = Path.home() / ".claude"
SETTINGS_FILE = CLAUDE_DIR / "settings.json"
HOOKS_DIR = CLAUDE_DIR / "hooks"
ENV_FILE = HOOKS_DIR / ".env"

def install():
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    if not ENV_FILE.exists():
        key = input("Enter your ANTHROPIC_API_KEY: ").strip()
        if key:
            ENV_FILE.write_text(f"ANTHROPIC_API_KEY={key}\n")
            print(f"Saved API key to {ENV_FILE}")

    if SETTINGS_FILE.exists():
        shutil.copy(SETTINGS_FILE, SETTINGS_FILE.with_suffix(".json.backup"))

    src_dir = Path(__file__).parent
    shutil.copy(src_dir / "hook.py", HOOKS_DIR / "monitor.py")
    shutil.copy(src_dir / "watched_tools.json", HOOKS_DIR / "watched_tools.json")
    (HOOKS_DIR / "monitor.py").chmod(0o755)

    settings = json.loads(SETTINGS_FILE.read_text()) if SETTINGS_FILE.exists() else {}
    settings["hooks"] = {
        "UserPromptSubmit": [
            {"matcher": "", "hooks": [{"type": "command", "command": f"python3 {HOOKS_DIR / 'monitor.py'}"}]}
        ],
        "PreToolUse": [
            {"matcher": "", "hooks": [{"type": "command", "command": f"python3 {HOOKS_DIR / 'monitor.py'}"}]}
        ],
        "PostToolUse": [
            {"matcher": "", "hooks": [{"type": "command", "command": f"python3 {HOOKS_DIR / 'monitor.py'}"}]}
        ]
    }
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))

def uninstall():
    for f in ["monitor.py", "watched_tools.json"]:
        p = HOOKS_DIR / f
        if p.exists():
            p.unlink()

    if SETTINGS_FILE.exists():
        settings = json.loads(SETTINGS_FILE.read_text())
        settings.pop("hooks", None)
        SETTINGS_FILE.write_text(json.dumps(settings, indent=2))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        uninstall()
    else:
        install()
