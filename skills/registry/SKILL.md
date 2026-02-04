---
name: registry
description: Manage the write-external command registry - add, remove, or view patterns for bash commands
allowed-tools: Bash, Read, Write
user-invocable: true
---

# Registry Management

Manage the write-external command registry for the Claude runtime monitor.

## Quick Commands

```bash
# List all commands
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py list

# View patterns for a command
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py view curl

# Add a safe command (never blocks)
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py add mytool --safe

# Add command with auto-learned patterns
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py add mytool --learn

# Add command with manual patterns
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py add mytool --patterns '["mytool\\s+upload"]'

# Remove a command
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py remove mytool

# Test if a command string would be blocked
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py test curl "curl -X POST https://api.com"
```

## Pattern Guidelines

- `[]` = safe command, never blocks
- Patterns match WRITE-EXTERNAL only (uploads, pushes, remote writes)
- For file transfers (scp, rsync): use `$` anchor to match remote at END
- For databases: exclude localhost with `(?!localhost|127\\.0\\.0\\.1)`

## Examples

- "add sqlite3 to always ask" → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py add sqlite3 --patterns '["sqlite3\\s"]'`
- "mark mytool as safe" → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py add mytool --safe`
- "remove vim" → `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/manage_registry.py remove vim`
