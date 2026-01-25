#!/usr/bin/env python3
"""
Guarded Hook - PreToolUse hook that uses the embedded LLM judge
to block suspicious write operations.

This hook:
1. Logs all tool calls (like the regular monitor)
2. For WRITE operations, runs the LLM judge
3. Blocks writes that the judge deems suspicious

Usage in ~/.claude/settings.json:
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "hooks": [{
        "type": "command",
        "command": "python3 -m claude_monitor.guarded_hook"
      }]
    }]
  }
}
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from .monitor import RuntimeMonitor
from .taxonomy import get_tool_classification

# Tools that need security judgment
# Write tools - can modify filesystem
WRITE_TOOLS = {"Write", "Edit", "Bash", "NotebookEdit"}

# MCP tools with critical risk
CRITICAL_MCP_TOOLS = {"mcp__ide__executeCode"}  # Arbitrary code execution

# Network tools - can fetch malicious content or exfiltrate data
NETWORK_TOOLS = {"WebFetch", "WebSearch"}

# Tools where we should check for write operations
MAYBE_WRITE_TOOLS = {"Bash"}  # Bash can both read and write

# All tools that need judgment
GUARDED_TOOLS = WRITE_TOOLS | CRITICAL_MCP_TOOLS | NETWORK_TOOLS


class GuardedMonitor(RuntimeMonitor):
    """
    Extended monitor that includes LLM-based judgment for write operations.
    """

    def __init__(
        self,
        enable_judge: bool = True,
        judge_model: str = "qwen2.5-0.5b",
        block_on_reject: bool = True,
        block_on_unsure: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.enable_judge = enable_judge
        self.judge_model = judge_model
        self.block_on_reject = block_on_reject
        self.block_on_unsure = block_on_unsure
        self._judge = None
        self._tool_history = []  # Track tool calls for context

    def _get_judge(self):
        """Lazy load the judge to avoid slow startup."""
        if self._judge is None and self.enable_judge:
            try:
                from .judge import WriteJudge
                self._judge = WriteJudge(
                    model_name=self.judge_model,
                    verbose=False,
                )
            except ImportError:
                print(
                    "Warning: llama-cpp-python not installed. "
                    "Install with: pip install claude-runtime-monitor[judge]",
                    file=sys.stderr
                )
                self.enable_judge = False
        return self._judge

    def _is_guarded_tool(self, tool_name: str, params: dict) -> bool:
        """Check if this tool call needs security judgment."""
        # File write tools
        if tool_name in {"Write", "Edit", "NotebookEdit"}:
            return True

        # Critical MCP tools
        if tool_name in CRITICAL_MCP_TOOLS:
            return True

        # Unknown MCP tools - treat with caution
        if tool_name.startswith("mcp__") and tool_name not in {"mcp__ide__getDiagnostics"}:
            return True

        # Network tools
        if tool_name in NETWORK_TOOLS:
            return True

        # Bash with write/dangerous indicators
        if tool_name == "Bash":
            cmd = params.get("command", "")
            write_indicators = [
                ">", ">>", "tee ", "mv ", "cp ", "rm ", "mkdir ", "touch ",
                "chmod ", "chown ", "curl", "wget ", "git push", "git commit",
                "npm publish", "pip install", "nc ", "netcat", "/dev/tcp",
            ]
            for indicator in write_indicators:
                if indicator in cmd:
                    return True

        return False

    def _should_judge(self, tool_name: str, params: dict) -> bool:
        """Determine if this operation needs judgment."""
        if not self._is_guarded_tool(tool_name, params):
            return False

        # Use quick heuristic check
        judge = self._get_judge()
        if judge:
            is_suspicious, _ = judge.quick_check(tool_name, params)
            return is_suspicious

        # If no judge, use basic heuristics
        return self._basic_suspicious_check(tool_name, params)

    def _basic_suspicious_check(self, tool_name: str, params: dict) -> bool:
        """Basic heuristic check without LLM."""
        suspicious_paths = [
            ".ssh", ".gnupg", ".aws", ".config", ".env",
            "credentials", "secrets", "token", "password",
            "/etc/", "/usr/", "/bin/", "/sbin/",
        ]

        # Extract target
        target = ""
        if tool_name in {"Write", "Edit"}:
            target = params.get("file_path", "").lower()
        elif tool_name == "Bash":
            target = params.get("command", "").lower()

        for pattern in suspicious_paths:
            if pattern in target:
                return True

        return False

    def _get_user_prompt(self, session_id: str) -> str:
        """Get the user prompt that triggered this action."""
        prompt_ctx = self.get_last_prompt(session_id)
        if prompt_ctx:
            return prompt_ctx.get("prompt", "")
        return ""

    def judge_and_decide(
        self,
        tool_name: str,
        params: dict,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Judge a write operation and return decision.

        Returns:
            {
                "allow": bool,
                "verdict": str,
                "reason": str,
                "confidence": float,
            }
        """
        user_prompt = self._get_user_prompt(session_id)
        judge = self._get_judge()

        if not judge:
            # No judge available, use basic heuristics
            is_suspicious = self._basic_suspicious_check(tool_name, params)
            return {
                "allow": not is_suspicious,
                "verdict": "REJECT" if is_suspicious else "ALLOW",
                "reason": "Basic heuristic check (judge module not loaded)",
                "confidence": 0.5,
                "method": "basic_heuristic",
            }

        # Run the judge (uses heuristics by default, LLM optional)
        try:
            # Use heuristic-only for speed, set use_llm=True for more context
            result = judge.judge(
                user_prompt=user_prompt,
                tool_name=tool_name,
                params=params,
                reason=reason,
                tool_history=self._tool_history[-10:],
                use_llm=False,  # Heuristic-only for speed
            )

            # Decide based on verdict and settings
            if result.verdict.value == "REJECT":
                allow = not self.block_on_reject
            elif result.verdict.value == "UNSURE":
                allow = not self.block_on_unsure
            else:
                allow = True

            return {
                "allow": allow,
                "verdict": result.verdict.value,
                "reason": result.reason,
                "confidence": result.confidence,
                "method": "heuristic_judge",
                "raw_response": result.raw_response,
            }

        except Exception as e:
            # Judge failed, default to allow with warning
            print(f"Warning: Judge failed: {e}", file=sys.stderr)
            return {
                "allow": True,
                "verdict": "ERROR",
                "reason": f"Judge error: {str(e)[:100]}",
                "confidence": 0.0,
                "method": "error_fallback",
            }

    def log_event_guarded(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log event and run judge for write operations.

        Returns the log entry with judge decision if applicable.
        """
        # First, do normal logging
        log_entry = self.log_event(data)

        event_type = data.get("hook_event_name", "")
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        session_id = data.get("session_id", "unknown")

        # Track tool history for context
        if event_type == "PreToolUse" and tool_name:
            self._tool_history.append({
                "tool": tool_name,
                "parameters": tool_input,
                "reason": self.extract_reason(tool_name, tool_input),
                "timestamp": datetime.now().isoformat(),
            })
            # Keep only last 20
            self._tool_history = self._tool_history[-20:]

        # For PreToolUse on write tools, run the judge
        if event_type == "PreToolUse" and self._should_judge(tool_name, tool_input):
            reason = self.extract_reason(tool_name, tool_input)
            decision = self.judge_and_decide(tool_name, tool_input, session_id, reason)

            log_entry["judge_decision"] = decision

            # Log to separate judge log
            judge_log = self.log_dir / "judge-decisions.jsonl"
            with open(judge_log, "a") as f:
                judge_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "session_id": session_id[:8],
                    "tool": tool_name,
                    "decision": decision,
                    "parameters_summary": log_entry.get("parameters_summary", {}),
                }
                f.write(json.dumps(judge_entry) + "\n")

        return log_entry


def prompt_user_confirmation(tool_name: str, target: str, reason: str, verdict: str, confidence: float) -> bool:
    """
    Prompt user for confirmation on suspicious operations.

    Reads from /dev/tty to get user input (since stdin has JSON from Claude Code).
    Returns True if user allows, False if user blocks.
    """
    try:
        # Open the terminal directly for input
        tty = open('/dev/tty', 'r')
    except (OSError, FileNotFoundError):
        # No TTY available (non-interactive), default to block
        print("⚠️  No TTY available for confirmation, blocking by default", file=sys.stderr)
        return False

    try:
        # Display the warning box
        print("\n", file=sys.stderr)
        print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓", file=sys.stderr)
        print("┃  ⚠️  SUSPICIOUS OPERATION DETECTED                        ┃", file=sys.stderr)
        print("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫", file=sys.stderr)
        print(f"┃  Tool:   {tool_name:<48} ┃", file=sys.stderr)
        print(f"┃  Target: {target[:48]:<48} ┃", file=sys.stderr)
        print(f"┃  Verdict: {verdict} ({confidence:.0%} confidence){' '*(35-len(verdict))} ┃", file=sys.stderr)
        print("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫", file=sys.stderr)
        # Word wrap reason
        reason_lines = [reason[i:i+55] for i in range(0, len(reason), 55)]
        for line in reason_lines[:3]:  # Max 3 lines
            print(f"┃  {line:<57} ┃", file=sys.stderr)
        print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛", file=sys.stderr)
        print("", file=sys.stderr)

        # Prompt for input
        print("Allow this operation? [y/N]: ", end="", file=sys.stderr, flush=True)

        # Read user input with timeout
        import select
        # Wait up to 30 seconds for input
        ready, _, _ = select.select([tty], [], [], 30.0)

        if ready:
            response = tty.readline().strip().lower()
            allowed = response in ('y', 'yes')

            if allowed:
                print("✅ User ALLOWED the operation", file=sys.stderr)
            else:
                print("🚫 User BLOCKED the operation", file=sys.stderr)

            return allowed
        else:
            # Timeout - default to block
            print("\n⏰ Timeout waiting for response, blocking by default", file=sys.stderr)
            return False

    finally:
        tty.close()


def main():
    """Entry point for guarded hook."""
    # Configuration from environment
    enable_judge = os.environ.get("CLAUDE_JUDGE_ENABLED", "1") == "1"
    judge_model = os.environ.get("CLAUDE_JUDGE_MODEL", "llama-3.2-3b")
    block_on_reject = os.environ.get("CLAUDE_BLOCK_ON_REJECT", "1") == "1"
    block_on_unsure = os.environ.get("CLAUDE_BLOCK_ON_UNSURE", "0") == "1"
    interactive_mode = os.environ.get("CLAUDE_INTERACTIVE", "1") == "1"

    monitor = GuardedMonitor(
        enable_judge=enable_judge,
        judge_model=judge_model,
        block_on_reject=block_on_reject,
        block_on_unsure=block_on_unsure,
    )

    try:
        input_data = json.load(sys.stdin)
        log_entry = monitor.log_event_guarded(input_data)

        event_type = log_entry.get("event", "Unknown")
        tool_name = log_entry.get("tool", "")
        risk = log_entry.get("risk", "UNKNOWN")

        # Check if judge flagged this
        judge_decision = log_entry.get("judge_decision", {})
        if judge_decision:
            verdict = judge_decision.get("verdict", "")
            reason = judge_decision.get("reason", "")
            allow = judge_decision.get("allow", True)
            confidence = judge_decision.get("confidence", 0)

            # Get target for display
            tool_input = input_data.get("tool_input", {})
            target = tool_input.get("file_path", tool_input.get("command", str(tool_input)[:50]))

            if not allow:
                if interactive_mode:
                    # INTERACTIVE MODE: Show warning with permission prompt
                    # Write/Edit use VS Code diff which doesn't show permissionDecisionReason
                    # So for those, use "deny" with helpful message; for Bash use "ask"
                    if tool_name in {"Write", "Edit", "NotebookEdit"}:
                        # For file edits, deny with clear message (VS Code diff doesn't show reason)
                        print(f"🚫 BLOCKED: {reason}", file=sys.stderr)
                        print(f"   Target: {target}", file=sys.stderr)
                        print(f"   To allow: Re-run and approve, or add path to allowlist", file=sys.stderr)
                        output = {
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": f"⚠️ {reason} | Target: {target[:40]}",
                            }
                        }
                    else:
                        # For Bash, use "ask" - the reason shows in the prompt
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
                    # NON-INTERACTIVE MODE: Auto-block
                    print(f"🚫 BLOCKED: {verdict} ({confidence:.0%})", file=sys.stderr)
                    print(f"   Reason: {reason}", file=sys.stderr)
                    print(f"   Target: {target}", file=sys.stderr)

                    output = {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": f"Security judge: {reason}",
                        }
                    }
                    print(json.dumps(output))
                    sys.exit(0)  # Exit 0 with deny permission
            else:
                # Allowed but logged
                icon = {"ALLOW": "✅", "UNSURE": "⚠️", "REJECT": "🚫"}.get(verdict, "❓")
                print(f"{icon} Judge: {verdict} - {reason[:60]}", file=sys.stderr)

        # Normal logging output
        icons = {
            "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📡",
            "LOW": "📋", "MINIMAL": "✅", "UNKNOWN": "❓", "INPUT": "👤",
        }
        icon = next((v for k, v in icons.items() if k in risk), "❓")

        if event_type == "UserPromptSubmit":
            prompt_preview = log_entry.get("prompt", "")[:60]
            print(f"{icon} [INPUT] User: {prompt_preview}...", file=sys.stderr)
        else:
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
