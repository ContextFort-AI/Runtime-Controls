#!/usr/bin/env python3
"""
Claude Runtime Monitor - CLI Tool

Commands:
  watch       - Live tail all events
  watch-high  - Live tail high-risk events
  stats       - Show event statistics
  high-risk   - Show high-risk events
  external    - Show external contact events
  prompts     - Show user prompts
  search      - Search logs
  clear       - Clear all logs
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from collections import Counter


LOG_DIR = Path.home() / ".claude" / "security-logs"


def format_event(event: dict, verbose: bool = False) -> str:
    """Format a log event for display."""
    ts = event.get("timestamp", "")[:19]
    ev = event.get("event", "?")
    tool = event.get("tool", "")
    risk = event.get("risk", "?")

    # Icons
    icons = {
        "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📡",
        "LOW": "📋", "MINIMAL": "✅", "UNKNOWN": "❓", "INPUT": "👤",
    }
    icon = next((v for k, v in icons.items() if k in risk), "❓")

    if ev == "UserPromptSubmit":
        prompt = event.get("prompt", "")[:60]
        return f"{ts} {icon} [INPUT] User: {prompt}..."

    classification = event.get("classification", {})
    external = classification.get("external_contact", False)
    direction = classification.get("direction", "?")

    ext = "🌐" if external else "🏠"
    dir_icon = {"READ": "📥", "WRITE": "📤", "READ-WRITE": "🔄"}.get(direction, "⚪")

    reason = event.get("reason", "")
    reason_str = f" | {reason[:40]}" if reason else ""

    prompt_ctx = event.get("triggering_prompt", {})
    prompt_str = ""
    if prompt_ctx and verbose:
        prompt_str = f"\n    └─ Prompt: {prompt_ctx.get('prompt', '')[:50]}..."

    return f"{ts} {icon} {ext}{dir_icon} [{risk:20}] {ev:12} {tool:20}{reason_str}{prompt_str}"


def cmd_watch(args):
    """Live tail all events."""
    log_file = LOG_DIR / "all-events.jsonl"
    if not log_file.exists():
        print("No logs yet. Start using Claude Code to generate logs.")
        return

    print(f"Watching {log_file} (Ctrl+C to stop)\n")
    try:
        proc = subprocess.Popen(
            ["tail", "-f", str(log_file)],
            stdout=subprocess.PIPE,
            text=True
        )
        for line in proc.stdout:
            try:
                event = json.loads(line.strip())
                print(format_event(event, args.verbose))
            except json.JSONDecodeError:
                print(line.strip())
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_watch_high(args):
    """Live tail high-risk events."""
    log_file = LOG_DIR / "high-risk.jsonl"
    if not log_file.exists():
        print("No high-risk events yet.")
        return

    print(f"Watching high-risk events (Ctrl+C to stop)\n")
    try:
        proc = subprocess.Popen(
            ["tail", "-f", str(log_file)],
            stdout=subprocess.PIPE,
            text=True
        )
        for line in proc.stdout:
            try:
                event = json.loads(line.strip())
                print(format_event(event, args.verbose))
            except json.JSONDecodeError:
                print(line.strip())
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_stats(args):
    """Show event statistics."""
    log_file = LOG_DIR / "all-events.jsonl"
    if not log_file.exists():
        print("No logs yet.")
        return

    events = []
    with open(log_file, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass

    if not events:
        print("No events found.")
        return

    tools = Counter(e.get("tool", "prompt") or "prompt" for e in events)
    risks = Counter(e.get("risk", "UNKNOWN") for e in events)
    categories = Counter(
        e.get("classification", {}).get("category", "unknown")
        for e in events if e.get("event") != "UserPromptSubmit"
    )

    print("=" * 60)
    print("Claude Runtime Monitor - Statistics")
    print("=" * 60)
    print(f"\nTotal events: {len(events)}")

    print("\n📊 By Tool:")
    for tool, count in tools.most_common(15):
        print(f"  {tool:25} {count:5}")

    print("\n⚠️  By Risk Level:")
    for risk, count in risks.most_common():
        print(f"  {risk:25} {count:5}")

    print("\n📁 By Category:")
    for cat, count in categories.most_common():
        print(f"  {cat:25} {count:5}")

    # Time range
    timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    if timestamps:
        print(f"\n🕐 Time range: {min(timestamps)[:19]} to {max(timestamps)[:19]}")


def cmd_high_risk(args):
    """Show high-risk events."""
    log_file = LOG_DIR / "high-risk.jsonl"
    if not log_file.exists():
        print("No high-risk events yet.")
        return

    with open(log_file, "r") as f:
        lines = f.readlines()

    if args.limit:
        lines = lines[-args.limit:]

    print(f"High-risk events (last {len(lines)}):\n")
    for line in lines:
        try:
            event = json.loads(line.strip())
            print(format_event(event, args.verbose))
        except json.JSONDecodeError:
            pass


def cmd_external(args):
    """Show external contact events."""
    log_file = LOG_DIR / "external-contact.jsonl"
    if not log_file.exists():
        print("No external contact events yet.")
        return

    with open(log_file, "r") as f:
        lines = f.readlines()

    if args.limit:
        lines = lines[-args.limit:]

    print(f"External contact events (last {len(lines)}):\n")
    for line in lines:
        try:
            event = json.loads(line.strip())
            print(format_event(event, args.verbose))
        except json.JSONDecodeError:
            pass


def cmd_prompts(args):
    """Show user prompts."""
    log_file = LOG_DIR / "all-events.jsonl"
    if not log_file.exists():
        print("No logs yet.")
        return

    with open(log_file, "r") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event") == "UserPromptSubmit":
                    ts = event.get("timestamp", "")[:19]
                    prompt = event.get("prompt", "")
                    print(f"{ts} 👤 {prompt}")
            except json.JSONDecodeError:
                pass


def cmd_search(args):
    """Search logs."""
    log_file = LOG_DIR / "all-events.jsonl"
    if not log_file.exists():
        print("No logs yet.")
        return

    query = args.query.lower()
    matches = 0

    with open(log_file, "r") as f:
        for line in f:
            if query in line.lower():
                try:
                    event = json.loads(line.strip())
                    print(format_event(event, args.verbose))
                    matches += 1
                except json.JSONDecodeError:
                    pass

    print(f"\n{matches} matches found.")


def cmd_clear(args):
    """Clear all logs."""
    if not args.yes:
        response = input("Are you sure you want to clear all logs? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return

    for log_file in LOG_DIR.glob("*.jsonl"):
        log_file.unlink()
        print(f"Deleted {log_file}")

    for state_file in (LOG_DIR / "state").glob("*.json"):
        state_file.unlink()
        print(f"Deleted {state_file}")

    print("Logs cleared.")


def cmd_export(args):
    """Export logs to a file."""
    log_file = LOG_DIR / "all-events.jsonl"
    if not log_file.exists():
        print("No logs yet.")
        return

    output = Path(args.output)
    if output.suffix == ".json":
        # Export as JSON array
        events = []
        with open(log_file, "r") as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
        with open(output, "w") as f:
            json.dump(events, f, indent=2)
    else:
        # Copy as JSONL
        import shutil
        shutil.copy(log_file, output)

    print(f"Exported to {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Claude Runtime Monitor - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # watch
    p_watch = subparsers.add_parser("watch", help="Live tail all events")
    p_watch.set_defaults(func=cmd_watch)

    # watch-high
    p_watch_high = subparsers.add_parser("watch-high", help="Live tail high-risk events")
    p_watch_high.set_defaults(func=cmd_watch_high)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show statistics")
    p_stats.set_defaults(func=cmd_stats)

    # high-risk
    p_high = subparsers.add_parser("high-risk", help="Show high-risk events")
    p_high.add_argument("-n", "--limit", type=int, default=50, help="Number of events")
    p_high.set_defaults(func=cmd_high_risk)

    # external
    p_ext = subparsers.add_parser("external", help="Show external contact events")
    p_ext.add_argument("-n", "--limit", type=int, default=50, help="Number of events")
    p_ext.set_defaults(func=cmd_external)

    # prompts
    p_prompts = subparsers.add_parser("prompts", help="Show user prompts")
    p_prompts.set_defaults(func=cmd_prompts)

    # search
    p_search = subparsers.add_parser("search", help="Search logs")
    p_search.add_argument("query", help="Search query")
    p_search.set_defaults(func=cmd_search)

    # clear
    p_clear = subparsers.add_parser("clear", help="Clear all logs")
    p_clear.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    p_clear.set_defaults(func=cmd_clear)

    # export
    p_export = subparsers.add_parser("export", help="Export logs")
    p_export.add_argument("output", help="Output file (.json or .jsonl)")
    p_export.set_defaults(func=cmd_export)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
