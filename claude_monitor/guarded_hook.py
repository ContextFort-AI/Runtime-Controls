#!/usr/bin/env python3
"""
Guarded Hook - PreToolUse hook with LLM Security Judge

This hook:
1. Logs all tool calls with full context
2. Runs the LLM judge on operations that need security review
3. Shows security warnings to users via Claude Code's permission system

NO HEURISTICS - all security decisions made by LLM with full context.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from .monitor import RuntimeMonitor
from .taxonomy import get_tool_classification


class GuardedMonitor(RuntimeMonitor):
    """
    Monitor with LLM-based security judgment.
    Tracks full context (user prompt, tool history with results) for the judge.
    """

    def __init__(
        self,
        enable_judge: bool = True,
        judge_model: str = "llama-3.2-3b",
        block_on_reject: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.enable_judge = enable_judge
        self.judge_model = judge_model
        self.block_on_reject = block_on_reject
        self._judge = None
        self._tool_history: List[Dict] = []
        self._user_prompt: str = ""
        self._last_tool_result: Dict = {}

    def _get_judge(self):
        """Lazy load the judge."""
        if self._judge is None and self.enable_judge:
            try:
                from .judge import WriteJudge
                self._judge = WriteJudge(
                    model_name=self.judge_model,
                    verbose=os.environ.get("CLAUDE_JUDGE_VERBOSE", "0") == "1",
                )
            except ImportError:
                print(
                    "Warning: llama-cpp-python not installed. "
                    "Install with: pip install claude-runtime-monitor[judge]",
                    file=sys.stderr
                )
                self.enable_judge = False
        return self._judge

    def _should_judge(self, tool_name: str, params: dict) -> bool:
        """
        Determine if this tool needs security judgment.
        We judge all operations that can write/modify data or access external resources.
        """
        # File operations
        if tool_name in {"Write", "Edit", "NotebookEdit"}:
            return True

        # Shell commands
        if tool_name == "Bash":
            return True

        # Network operations
        if tool_name in {"WebFetch", "WebSearch"}:
            return True

        # MCP operations (especially writes)
        if tool_name.startswith("mcp__"):
            return True

        # Code execution
        if "execute" in tool_name.lower() or "run" in tool_name.lower():
            return True

        return False

    def judge_operation(
        self,
        tool_name: str,
        params: dict,
        session_id: str,
    ) -> Dict[str, Any]:
        """
        Run the LLM judge on an operation with full context.
        """
        judge = self._get_judge()
        if not judge:
            return {
                "allow": True,
                "verdict": "SKIP",
                "reason": "Judge not available",
                "confidence": 0.0,
            }

        try:
            result = judge.judge(
                user_prompt=self._user_prompt,
                tool_name=tool_name,
                params=params,
                tool_history=self._tool_history,
            )

            allow = result.verdict.value != "REJECT"
            if result.verdict.value == "REJECT" and not self.block_on_reject:
                allow = True

            return {
                "allow": allow,
                "verdict": result.verdict.value,
                "reason": result.reason,
                "confidence": result.confidence,
                "raw_response": result.raw_response,
            }

        except Exception as e:
            print(f"Judge error: {e}", file=sys.stderr)
            return {
                "allow": True,
                "verdict": "ERROR",
                "reason": f"Judge error: {str(e)[:100]}",
                "confidence": 0.0,
            }

    def log_event_guarded(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log event and run judge for operations that need review.
        """
        # Normal logging first
        log_entry = self.log_event(data)

        event_type = data.get("hook_event_name", "")
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        tool_response = data.get("tool_response", {})
        session_id = data.get("session_id", "unknown")

        # Capture user prompt
        if event_type == "UserPromptSubmit":
            self._user_prompt = data.get("prompt", "")

        # Update tool history with results from PostToolUse
        if event_type == "PostToolUse" and tool_name:
            # Find the matching PreToolUse entry and add result
            for entry in reversed(self._tool_history):
                if entry.get("tool") == tool_name and "result" not in entry:
                    # Capture result (truncate if large)
                    result_str = str(tool_response)
                    if len(result_str) > 500:
                        result_str = result_str[:500] + "..."
                    entry["result"] = result_str
                    break

        # For PreToolUse, add to history and run judge if needed
        if event_type == "PreToolUse" and tool_name:
            # Add to history
            self._tool_history.append({
                "tool": tool_name,
                "parameters": tool_input,
                "timestamp": datetime.now().isoformat(),
            })
            # Keep last 15 entries
            self._tool_history = self._tool_history[-15:]

            # Run judge if this tool needs review
            if self._should_judge(tool_name, tool_input):
                decision = self.judge_operation(tool_name, tool_input, session_id)
                log_entry["judge_decision"] = decision

                # Log to separate judge log
                judge_log = self.log_dir / "judge-decisions.jsonl"
                with open(judge_log, "a") as f:
                    judge_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "session_id": session_id,
                        "tool": tool_name,
                        "user_prompt": self._user_prompt[:200] if self._user_prompt else None,
                        "tool_history_count": len(self._tool_history),
                        "decision": decision,
                        "parameters_summary": {
                            k: str(v)[:100] + "..." if len(str(v)) > 100 else v
                            for k, v in tool_input.items()
                        },
                    }
                    f.write(json.dumps(judge_entry) + "\n")

        return log_entry


def main():
    """Entry point for guarded hook."""
    # Configuration from environment
    enable_judge = os.environ.get("CLAUDE_JUDGE_ENABLED", "1") == "1"
    judge_model = os.environ.get("CLAUDE_JUDGE_MODEL", "llama-3.2-3b")
    block_on_reject = os.environ.get("CLAUDE_BLOCK_ON_REJECT", "1") == "1"
    interactive_mode = os.environ.get("CLAUDE_INTERACTIVE", "1") == "1"

    monitor = GuardedMonitor(
        enable_judge=enable_judge,
        judge_model=judge_model,
        block_on_reject=block_on_reject,
    )

    try:
        input_data = json.load(sys.stdin)
        log_entry = monitor.log_event_guarded(input_data)

        event_type = log_entry.get("event", "Unknown")
        tool_name = log_entry.get("tool", "")
        risk = log_entry.get("risk", "UNKNOWN")

        # Check judge decision
        judge_decision = log_entry.get("judge_decision", {})
        if judge_decision:
            verdict = judge_decision.get("verdict", "")
            reason = judge_decision.get("reason", "")
            allow = judge_decision.get("allow", True)
            confidence = judge_decision.get("confidence", 0)

            # Get target for display
            tool_input = input_data.get("tool_input", {})
            target = tool_input.get("file_path", tool_input.get("command", tool_input.get("issueIdOrKey", str(tool_input)[:50])))

            if not allow:
                if interactive_mode:
                    # Use Claude Code's permission prompt with our warning
                    # For file operations, deny with message
                    # For other tools, ask with warning
                    if tool_name in {"Write", "Edit", "NotebookEdit"}:
                        print(f"🚫 BLOCKED: {reason}", file=sys.stderr)
                        output = {
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": f"⚠️ {reason}",
                            }
                        }
                    else:
                        # For MCP, Bash, etc - ask with warning
                        output = {
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "ask",
                                "permissionDecisionReason": f"⚠️ {reason}",
                            }
                        }
                    print(json.dumps(output))
                    sys.exit(0)
                else:
                    # Non-interactive: auto-block
                    print(f"🚫 BLOCKED: {verdict} ({confidence:.0%})", file=sys.stderr)
                    print(f"   Reason: {reason}", file=sys.stderr)
                    output = {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": f"Security: {reason}",
                        }
                    }
                    print(json.dumps(output))
                    sys.exit(0)
            else:
                # Allowed - show info if verbose
                if os.environ.get("CLAUDE_JUDGE_VERBOSE", "0") == "1":
                    print(f"✅ {verdict}: {reason[:60]}", file=sys.stderr)

        # Normal logging output
        icons = {
            "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📡",
            "LOW": "📋", "MINIMAL": "✅", "UNKNOWN": "❓", "INPUT": "👤",
        }
        icon = next((v for k, v in icons.items() if k in risk), "❓")

        if event_type == "UserPromptSubmit":
            prompt_preview = log_entry.get("prompt", "")[:60]
            print(f"{icon} [INPUT] User: {prompt_preview}...", file=sys.stderr)
        elif os.environ.get("CLAUDE_VERBOSE", "0") == "1":
            print(f"{icon} [{risk}] {event_type}: {tool_name}", file=sys.stderr)

        sys.exit(0)

    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Monitor error: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
