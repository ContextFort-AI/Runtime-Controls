# Claude Runtime Monitor - Hooks

This directory contains the Claude Code runtime security hooks.

## Available Skills

### /registry - Manage Write-External Registry

Use `/registry` to manage which commands are flagged as write-external.

**Quick commands:**
```bash
python3 manage_registry.py list              # List all commands
python3 manage_registry.py view <cmd>        # View patterns
python3 manage_registry.py add <cmd> --safe  # Add safe command
python3 manage_registry.py add <cmd> --learn # Auto-learn patterns
python3 manage_registry.py remove <cmd>      # Remove command
python3 manage_registry.py test <cmd> "..."  # Test a string
```

## Files

- `monitor.py` - Main hook handler (PreToolUse)
- `tool_guard/` - Write-external pattern detection
  - `watched_tools.json` - Command patterns registry
  - `registry.py` - Pattern matching and LLM learning
- `bash_guard/` - Tirith security rules
- `prompt_guard/` - LLM utilities
- `analytics.py` - PostHog tracking
- `manage_registry.py` - CLI tool for registry management
