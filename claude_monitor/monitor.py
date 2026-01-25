#!/usr/bin/env python3
"""
Claude Runtime Monitor - Core Module
Logs all Claude Code tool calls with full context for security auditing.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from .taxonomy import get_tool_classification, compute_risk_level


class RuntimeMonitor:
    """
    Runtime monitor for Claude Code tool calls.

    Captures:
    - User prompts that trigger actions
    - Full parameters passed to tools
    - Tool outputs/responses
    - Classification and risk levels
    """

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        max_param_length: int = 2000,
        max_output_length: int = 5000,
        max_prompt_length: int = 2000,
    ):
        self.log_dir = log_dir or Path.home() / ".claude" / "security-logs"
        self.state_dir = self.log_dir / "state"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.max_param_length = max_param_length
        self.max_output_length = max_output_length
        self.max_prompt_length = max_prompt_length

    def truncate(self, value: Any, max_length: int) -> str:
        """Truncate a value to max_length, adding indicator if truncated."""
        if max_length == -1:
            return str(value)
        s = str(value)
        if len(s) <= max_length:
            return s
        return s[:max_length] + f"... [TRUNCATED, total {len(s)} chars]"

    def get_state_file(self, session_id: str) -> Path:
        """Get path to session state file."""
        return self.state_dir / f"session-{session_id[:8]}.json"

    def save_user_prompt(self, session_id: str, prompt_data: str) -> None:
        """Save user prompt for linking to subsequent tool calls."""
        state_file = self.get_state_file(session_id)
        state = {
            "last_prompt": self.truncate(prompt_data, self.max_prompt_length),
            "last_prompt_time": datetime.now().isoformat(),
            "tool_call_count": 0,
        }
        with open(state_file, "w") as f:
            json.dump(state, f)

    def get_last_prompt(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get the last user prompt for this session."""
        state_file = self.get_state_file(session_id)
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
            state["tool_call_count"] = state.get("tool_call_count", 0) + 1
            with open(state_file, "w") as fw:
                json.dump(state, fw)
            return {
                "prompt": state.get("last_prompt"),
                "prompt_time": state.get("last_prompt_time"),
                "tool_call_index": state.get("tool_call_count"),
            }
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def extract_reason(self, tool_name: str, tool_input: Dict[str, Any]) -> Optional[str]:
        """Extract the reason/description for why this tool was called."""
        if not tool_input:
            return None

        reason_fields = {
            "Bash": "description",
            "Task": "description",
            "WebFetch": "prompt",
            "WebSearch": "query",
            "Read": "file_path",
            "Write": "file_path",
            "Edit": "file_path",
            "Grep": "pattern",
            "Glob": "pattern",
        }

        field = reason_fields.get(tool_name)
        if field and field in tool_input:
            return tool_input[field]
        return None

    def sanitize_params(self, tool_input: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Sanitize and structure tool parameters for logging."""
        if not tool_input:
            return {"full": {}, "summary": {}}

        full_params = {}
        summary = {}

        for key, value in tool_input.items():
            if isinstance(value, str):
                full_params[key] = self.truncate(value, self.max_param_length)
                if len(value) > 200:
                    summary[key] = self.truncate(value, 200)
                else:
                    summary[key] = value
            else:
                full_params[key] = value
                summary[key] = value

        return {"full": full_params, "summary": summary}

    def log_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log the event with full context. Returns the log entry."""
        timestamp = datetime.now()
        event_type = data.get("hook_event_name", "Unknown")
        tool_name = data.get("tool_name", "")
        session_id = data.get("session_id", "unknown")
        cwd = data.get("cwd", "")
        tool_input = data.get("tool_input", {})
        tool_output = data.get("tool_output")

        # Handle UserPromptSubmit specially
        if event_type == "UserPromptSubmit":
            prompt_content = (
                data.get("prompt") or
                tool_input.get("prompt") or
                tool_input.get("content") or
                str(tool_input)
            )
            self.save_user_prompt(session_id, prompt_content)

            log_entry = {
                "timestamp": timestamp.isoformat(),
                "session_id": session_id[:8],
                "event": event_type,
                "risk": "INPUT",
                "cwd": cwd,
                "prompt": self.truncate(prompt_content, self.max_prompt_length),
            }
        else:
            classification = get_tool_classification(tool_name)
            risk_level = compute_risk_level(classification, event_type)
            prompt_context = self.get_last_prompt(session_id)
            reason = self.extract_reason(tool_name, tool_input)
            params = self.sanitize_params(tool_input)

            log_entry = {
                "timestamp": timestamp.isoformat(),
                "session_id": session_id[:8],
                "event": event_type,
                "tool": tool_name,
                "risk": risk_level,
                "classification": {
                    "category": classification.get("category"),
                    "external_contact": classification.get("external_contact"),
                    "direction": classification.get("direction"),
                    "injection_risk": classification.get("injection_risk"),
                    "action_risk": classification.get("action_risk"),
                },
                "reason": reason,
                "triggering_prompt": prompt_context,
                "parameters": params["full"],
                "parameters_summary": params["summary"],
                "cwd": cwd,
            }

            if event_type == "PostToolUse" and tool_output is not None:
                output_str = str(tool_output)
                log_entry["output"] = {
                    "length": len(output_str),
                    "content": self.truncate(output_str, self.max_output_length),
                    "truncated": len(output_str) > self.max_output_length,
                }

        # Write to log files
        self._write_logs(log_entry, event_type, tool_name)

        return log_entry

    def _write_logs(self, log_entry: Dict[str, Any], event_type: str, tool_name: str) -> None:
        """Write log entry to appropriate log files."""
        # Main log
        main_log = self.log_dir / "all-events.jsonl"
        with open(main_log, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

        if event_type != "UserPromptSubmit" and tool_name:
            classification = get_tool_classification(tool_name)

            # External contact log
            if classification.get("external_contact", False):
                external_log = self.log_dir / "external-contact.jsonl"
                with open(external_log, "a") as f:
                    f.write(json.dumps(log_entry) + "\n")

            # High-risk log
            risk_level = log_entry.get("risk", "")
            if "CRITICAL" in risk_level or "HIGH" in risk_level:
                high_risk_log = self.log_dir / "high-risk.jsonl"
                with open(high_risk_log, "a") as f:
                    f.write(json.dumps(log_entry) + "\n")


def main():
    """Entry point for hook script."""
    monitor = RuntimeMonitor()

    try:
        input_data = json.load(sys.stdin)
        log_entry = monitor.log_event(input_data)

        # Print summary to stderr for verbose mode
        event_type = log_entry.get("event", "Unknown")
        tool_name = log_entry.get("tool", "")
        risk = log_entry.get("risk", "UNKNOWN")

        icons = {
            "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📡",
            "LOW": "📋", "MINIMAL": "✅", "UNKNOWN": "❓", "INPUT": "👤",
        }

        icon = next((v for k, v in icons.items() if k in risk), "❓")

        if event_type == "UserPromptSubmit":
            prompt_preview = log_entry.get("prompt", "")[:60]
            print(f"{icon} [INPUT] User: {prompt_preview}...", file=sys.stderr)
        else:
            classification = log_entry.get("classification", {})
            external = classification.get("external_contact", False)
            direction = classification.get("direction", "?")

            ext = "🌐" if external else "🏠"
            dir_icon = {"READ": "📥", "WRITE": "📤", "READ-WRITE": "🔄"}.get(direction, "⚪")

            reason = log_entry.get("reason", "")
            reason_str = f" | {reason[:50]}" if reason else ""

            prompt_ctx = log_entry.get("triggering_prompt", {})
            call_idx = f" [#{prompt_ctx.get('tool_call_index', '?')}]" if prompt_ctx else ""

            print(f"{icon} {ext}{dir_icon} [{risk}] {event_type}: {tool_name}{call_idx}{reason_str}", file=sys.stderr)

        sys.exit(0)

    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Monitor error: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
