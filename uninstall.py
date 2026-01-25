#!/usr/bin/env python3
"""
Claude Runtime Monitor - Uninstaller

Removes the runtime monitoring hooks from Claude Code.
"""

import json
import sys
from pathlib import Path


CLAUDE_DIR = Path.home() / ".claude"
HOOKS_DIR = CLAUDE_DIR / "hooks"
SETTINGS_FILE = CLAUDE_DIR / "settings.json"
LOG_DIR = CLAUDE_DIR / "security-logs"


def remove_hook_script():
    """Remove the hook script."""
    hook_file = HOOKS_DIR / "claude-runtime-monitor.py"
    if hook_file.exists():
        hook_file.unlink()
        print(f"✓ Removed hook script: {hook_file}")
    else:
        print("⚠ Hook script not found")


def remove_hooks_config():
    """Remove hooks configuration from settings."""
    if not SETTINGS_FILE.exists():
        print("⚠ Settings file not found")
        return

    with open(SETTINGS_FILE, "r") as f:
        settings = json.load(f)

    if "hooks" not in settings:
        print("⚠ No hooks configuration found")
        return

    modified = False
    for event in list(settings["hooks"].keys()):
        hook_groups = settings["hooks"][event]
        new_groups = []

        for group in hook_groups:
            new_hooks = [
                h for h in group.get("hooks", [])
                if "claude-runtime-monitor.py" not in h.get("command", "")
            ]
            if new_hooks:
                group["hooks"] = new_hooks
                new_groups.append(group)
            else:
                modified = True

        if new_groups:
            settings["hooks"][event] = new_groups
        else:
            del settings["hooks"][event]
            modified = True

    if not settings["hooks"]:
        del settings["hooks"]

    if modified:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
        print("✓ Removed hooks configuration from settings")
    else:
        print("⚠ No monitor hooks found in configuration")


def remove_logs(keep_logs: bool):
    """Optionally remove log files."""
    if keep_logs:
        print(f"⚠ Keeping logs at {LOG_DIR}")
        return

    if LOG_DIR.exists():
        import shutil
        shutil.rmtree(LOG_DIR)
        print(f"✓ Removed logs directory: {LOG_DIR}")
    else:
        print("⚠ Logs directory not found")


def uninstall(keep_logs: bool = True):
    """Run full uninstallation."""
    print("=" * 60)
    print("Claude Runtime Monitor - Uninstallation")
    print("=" * 60)
    print()

    # Step 1: Remove hook script
    print("[1/3] Removing hook script...")
    remove_hook_script()

    # Step 2: Remove hooks config
    print("\n[2/3] Removing hooks configuration...")
    remove_hooks_config()

    # Step 3: Handle logs
    print("\n[3/3] Handling logs...")
    remove_logs(keep_logs)

    print()
    print("=" * 60)
    print("Uninstallation complete!")
    print("=" * 60)
    print()
    print("Restart Claude Code for changes to take effect.")
    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Uninstall Claude Runtime Monitor")
    parser.add_argument(
        "--remove-logs",
        action="store_true",
        help="Also remove log files (default: keep logs)"
    )
    args = parser.parse_args()

    try:
        uninstall(keep_logs=not args.remove_logs)
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Uninstallation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
