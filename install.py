#!/usr/bin/env python3
"""
Claude Runtime Monitor - Installer

Installs the runtime monitoring hooks into Claude Code.

Usage:
  python install.py              # Install basic monitoring (logging only)
  python install.py --guarded    # Install with LLM judge (blocks suspicious writes)
  python install.py --download-model  # Download the judge model
"""

import argparse
import json
import shutil
import sys
from pathlib import Path


CLAUDE_DIR = Path.home() / ".claude"
HOOKS_DIR = CLAUDE_DIR / "hooks"
SETTINGS_FILE = CLAUDE_DIR / "settings.json"
LOG_DIR = CLAUDE_DIR / "security-logs"
MODEL_DIR = CLAUDE_DIR / "security-models"

# Basic monitor hook (logging only)
HOOK_SCRIPT_BASIC = '''#!/usr/bin/env python3
"""Claude Runtime Monitor Hook - Auto-generated (logging only)"""
import sys
sys.path.insert(0, "{package_dir}")
from claude_monitor.monitor import main
main()
'''

# Guarded hook (logging + LLM judge for writes)
HOOK_SCRIPT_GUARDED = '''#!/usr/bin/env python3
"""Claude Runtime Monitor Hook - Auto-generated (with LLM judge)"""
import sys
sys.path.insert(0, "{package_dir}")
from claude_monitor.guarded_hook import main
main()
'''

HOOKS_CONFIG = {
    "UserPromptSubmit": [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 ~/.claude/hooks/claude-runtime-monitor.py"
                }
            ]
        }
    ],
    "PreToolUse": [
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 ~/.claude/hooks/claude-runtime-monitor.py"
                }
            ]
        }
    ],
    "PostToolUse": [
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 ~/.claude/hooks/claude-runtime-monitor.py"
                }
            ]
        }
    ],
    "SessionStart": [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 ~/.claude/hooks/claude-runtime-monitor.py"
                }
            ]
        }
    ],
    "SessionEnd": [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 ~/.claude/hooks/claude-runtime-monitor.py"
                }
            ]
        }
    ],
}


def backup_settings():
    """Backup existing settings file."""
    if SETTINGS_FILE.exists():
        backup = SETTINGS_FILE.with_suffix(".json.backup")
        shutil.copy(SETTINGS_FILE, backup)
        print(f"✓ Backed up existing settings to {backup}")
        return True
    return False


def load_settings():
    """Load existing settings or create new."""
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_settings(settings):
    """Save settings file."""
    CLAUDE_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def install_hook_script(package_dir: Path, guarded: bool = False):
    """Install the hook script."""
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    hook_file = HOOKS_DIR / "claude-runtime-monitor.py"

    template = HOOK_SCRIPT_GUARDED if guarded else HOOK_SCRIPT_BASIC
    script_content = template.format(package_dir=package_dir)
    with open(hook_file, "w") as f:
        f.write(script_content)

    hook_file.chmod(0o755)
    mode_str = "guarded (with LLM judge)" if guarded else "basic (logging only)"
    print(f"✓ Installed hook script to {hook_file} [{mode_str}]")


def install_hooks_config():
    """Add hooks configuration to settings."""
    settings = load_settings()

    # Merge hooks config
    if "hooks" not in settings:
        settings["hooks"] = {}

    for event, config in HOOKS_CONFIG.items():
        if event in settings["hooks"]:
            # Check if our hook is already there
            existing_commands = [
                h.get("command", "")
                for hook_group in settings["hooks"][event]
                for h in hook_group.get("hooks", [])
            ]
            if "claude-runtime-monitor.py" in str(existing_commands):
                print(f"⚠ Hook for {event} already exists, skipping")
                continue

            # Append our hooks
            settings["hooks"][event].extend(config)
        else:
            settings["hooks"][event] = config

    save_settings(settings)
    print("✓ Updated Claude Code settings with hooks configuration")


def create_log_directories():
    """Create log directories."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "state").mkdir(parents=True, exist_ok=True)
    print(f"✓ Created log directory at {LOG_DIR}")


def download_model(model_name: str = "qwen2.5-0.5b"):
    """Download the judge model."""
    print("=" * 60)
    print("Claude Runtime Monitor - Model Download")
    print("=" * 60)
    print()

    try:
        from claude_monitor.judge import WriteJudge
    except ImportError:
        print("❌ llama-cpp-python not installed.")
        print("   Install with: pip install claude-runtime-monitor[judge]")
        return False

    judge = WriteJudge(model_name=model_name, verbose=True)
    judge.download_model()
    print()
    print("✓ Model downloaded successfully")
    print(f"  Location: {judge.model_path}")
    return True


def install(guarded: bool = False):
    """Run full installation."""
    print("=" * 60)
    mode_str = "Guarded Mode (with LLM Judge)" if guarded else "Basic Mode (Logging Only)"
    print(f"Claude Runtime Monitor - Installation [{mode_str}]")
    print("=" * 60)
    print()

    # Get package directory
    package_dir = Path(__file__).parent.resolve()

    print(f"Package directory: {package_dir}")
    print()

    steps = 5 if guarded else 4

    # Step 1: Backup settings
    print(f"[1/{steps}] Backing up settings...")
    backup_settings()

    # Step 2: Install hook script
    print(f"\n[2/{steps}] Installing hook script...")
    install_hook_script(package_dir, guarded=guarded)

    # Step 3: Configure hooks
    print(f"\n[3/{steps}] Configuring hooks...")
    install_hooks_config()

    # Step 4: Create log directories
    print(f"\n[4/{steps}] Creating log directories...")
    create_log_directories()

    # Step 5 (guarded only): Download model
    if guarded:
        print(f"\n[5/{steps}] Downloading LLM judge model...")
        try:
            from claude_monitor.judge import WriteJudge
            judge = WriteJudge(verbose=True)
            if not judge.is_model_downloaded():
                judge.download_model()
            else:
                print("✓ Model already downloaded")
        except ImportError:
            print("⚠ llama-cpp-python not installed.")
            print("  Install with: pip install llama-cpp-python")
            print("  Then run: python install.py --download-model")

    print()
    print("=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Restart Claude Code for hooks to take effect")
    print("  2. Use 'claude-monitor' CLI to view logs:")
    print("     - claude-monitor watch     # Live tail")
    print("     - claude-monitor stats     # Statistics")
    print("     - claude-monitor high-risk # High-risk events")
    if guarded:
        print()
        print("Guarded mode enabled:")
        print("  - Write operations will be evaluated by LLM judge")
        print("  - Suspicious writes will be BLOCKED")
        print("  - Judge decisions logged to: judge-decisions.jsonl")
        print()
        print("Environment variables:")
        print("  CLAUDE_JUDGE_ENABLED=1      # Enable/disable judge (default: 1)")
        print("  CLAUDE_BLOCK_ON_REJECT=1    # Block rejected writes (default: 1)")
        print("  CLAUDE_BLOCK_ON_UNSURE=0    # Block unsure writes (default: 0)")
    print()
    print(f"Logs will be written to: {LOG_DIR}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Install Claude Runtime Monitor hooks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python install.py              # Install basic monitoring (logging only)
  python install.py --guarded    # Install with LLM judge (blocks suspicious writes)
  python install.py --download-model  # Download the judge model only
        """
    )
    parser.add_argument(
        "--guarded",
        action="store_true",
        help="Install guarded mode with LLM judge for write operations"
    )
    parser.add_argument(
        "--download-model",
        action="store_true",
        help="Download the judge model only (doesn't install hooks)"
    )
    parser.add_argument(
        "--model",
        default="qwen2.5-0.5b",
        help="Model to use for judge (default: qwen2.5-0.5b)"
    )

    args = parser.parse_args()

    try:
        if args.download_model:
            success = download_model(args.model)
            sys.exit(0 if success else 1)
        else:
            install(guarded=args.guarded)
            sys.exit(0)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
