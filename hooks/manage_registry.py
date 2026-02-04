#!/usr/bin/env python3
"""
Registry management tool for the Claude runtime monitor.
Usage:
    python manage_registry.py list                    # List all commands
    python manage_registry.py view <cmd>              # View patterns for a command
    python manage_registry.py add <cmd>               # Add command (auto-learn patterns)
    python manage_registry.py add <cmd> --safe        # Add as safe command (empty patterns)
    python manage_registry.py add <cmd> --patterns '["pattern1", "pattern2"]'
    python manage_registry.py remove <cmd>            # Remove command
    python manage_registry.py test <cmd> <test_str>   # Test if a command string matches
"""

import argparse
import json
import re
import sys
from pathlib import Path

WATCHED_FILE = Path(__file__).parent / "tool_guard" / "watched_tools.json"


def load_config():
    if WATCHED_FILE.exists():
        return json.loads(WATCHED_FILE.read_text())
    return {"bash-write-external": {}}


def save_config(config):
    WATCHED_FILE.write_text(json.dumps(config, indent=2) + "\n")


def list_commands():
    config = load_config()
    commands = config.get("bash-write-external", {})

    safe = []
    patterned = []

    for cmd, patterns in sorted(commands.items()):
        if patterns:
            patterned.append((cmd, len(patterns)))
        else:
            safe.append(cmd)

    print(f"Total commands: {len(commands)}\n")

    print(f"Safe commands ({len(safe)}) - always allowed:")
    for i, cmd in enumerate(safe):
        print(f"  {cmd}", end="")
        if (i + 1) % 8 == 0:
            print()
    print("\n")

    print(f"Patterned commands ({len(patterned)}) - blocked when patterns match:")
    for cmd, count in patterned:
        print(f"  {cmd}: {count} pattern(s)")


def view_command(cmd_name):
    config = load_config()
    patterns = config.get("bash-write-external", {}).get(cmd_name)

    if patterns is None:
        print(f"Command '{cmd_name}' is NOT in registry (unknown - will trigger LLM learning)")
    elif not patterns:
        print(f"Command '{cmd_name}' is marked as SAFE (no write-external patterns)")
    else:
        print(f"Command '{cmd_name}' has {len(patterns)} pattern(s):")
        for p in patterns:
            print(f"  - {p}")


def add_command(cmd_name, patterns=None, safe=False, auto_learn=False):
    config = load_config()

    if safe:
        patterns = []
        print(f"Adding '{cmd_name}' as safe command (empty patterns)")
    elif patterns:
        # Validate patterns
        valid = []
        for p in patterns:
            try:
                re.compile(p)
                valid.append(p)
            except re.error as e:
                print(f"Warning: Invalid regex '{p}': {e}")
        patterns = valid
        print(f"Adding '{cmd_name}' with {len(patterns)} pattern(s)")
    elif auto_learn:
        print(f"Auto-learning patterns for '{cmd_name}'...")
        try:
            from tool_guard.registry import learn_bash_patterns
            patterns = learn_bash_patterns(cmd_name)
            print(f"Learned {len(patterns)} pattern(s): {patterns}")
        except Exception as e:
            print(f"Error learning patterns: {e}")
            return
    else:
        print("Error: Must specify --safe, --patterns, or --learn")
        return

    if "bash-write-external" not in config:
        config["bash-write-external"] = {}

    config["bash-write-external"][cmd_name] = patterns
    save_config(config)
    print(f"Saved!")


def remove_command(cmd_name):
    config = load_config()

    if cmd_name not in config.get("bash-write-external", {}):
        print(f"Command '{cmd_name}' not found in registry")
        return

    del config["bash-write-external"][cmd_name]
    save_config(config)
    print(f"Removed '{cmd_name}' from registry")


def test_command(cmd_name, test_string):
    config = load_config()
    patterns = config.get("bash-write-external", {}).get(cmd_name)

    if patterns is None:
        print(f"Command '{cmd_name}' not in registry")
        return

    if not patterns:
        print(f"Command '{cmd_name}' is safe (no patterns) - would ALLOW")
        return

    for p in patterns:
        try:
            if re.search(p, test_string, re.IGNORECASE):
                print(f"MATCHED pattern: {p}")
                print(f"Result: would BLOCK (ask permission)")
                return
        except re.error:
            continue

    print(f"No patterns matched")
    print(f"Result: would ALLOW")


def main():
    parser = argparse.ArgumentParser(description="Manage the write-external registry")
    subparsers = parser.add_subparsers(dest="action", help="Action to perform")

    # list
    subparsers.add_parser("list", help="List all commands")

    # view
    view_parser = subparsers.add_parser("view", help="View patterns for a command")
    view_parser.add_argument("command", help="Command name")

    # add
    add_parser = subparsers.add_parser("add", help="Add a command")
    add_parser.add_argument("command", help="Command name")
    add_parser.add_argument("--safe", action="store_true", help="Mark as safe (empty patterns)")
    add_parser.add_argument("--patterns", help="JSON array of patterns")
    add_parser.add_argument("--learn", action="store_true", help="Auto-learn patterns using LLM")

    # remove
    remove_parser = subparsers.add_parser("remove", help="Remove a command")
    remove_parser.add_argument("command", help="Command name")

    # test
    test_parser = subparsers.add_parser("test", help="Test if a string matches")
    test_parser.add_argument("command", help="Command name")
    test_parser.add_argument("test_string", help="String to test")

    args = parser.parse_args()

    if args.action == "list":
        list_commands()
    elif args.action == "view":
        view_command(args.command)
    elif args.action == "add":
        patterns = json.loads(args.patterns) if args.patterns else None
        add_command(args.command, patterns=patterns, safe=args.safe, auto_learn=args.learn)
    elif args.action == "remove":
        remove_command(args.command)
    elif args.action == "test":
        test_command(args.command, args.test_string)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
