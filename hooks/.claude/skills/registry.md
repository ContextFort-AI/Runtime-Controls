# Registry Management Skill

Manage the write-external command registry for the Claude runtime monitor.

## Quick Commands

Use the helper script at `/Users/ashwin/runtime-attacks/claude-runtime-monitor/hooks/manage_registry.py`:

```bash
# List all commands
python3 manage_registry.py list

# View patterns for a command
python3 manage_registry.py view curl

# Add a safe command (never blocks)
python3 manage_registry.py add mytool --safe

# Add command with auto-learned patterns
python3 manage_registry.py add mytool --learn

# Add command with manual patterns
python3 manage_registry.py add mytool --patterns '["mytool\\s+upload"]'

# Remove a command
python3 manage_registry.py remove mytool

# Test if a command string would be blocked
python3 manage_registry.py test curl "curl -X POST https://api.com"
```

## Manual Editing

You can also directly edit `/Users/ashwin/runtime-attacks/claude-runtime-monitor/hooks/tool_guard/watched_tools.json`.

## Actions

### Add a command
If user wants to ADD a command:
1. Ask what command they want to add
2. Ask if they want to:
   - Provide patterns manually, OR
   - Auto-learn patterns using the LLM

For auto-learning, run:
```python
from tool_guard.registry import learn_bash_patterns, save_bash_patterns
patterns = learn_bash_patterns("command_name")
save_bash_patterns("command_name", patterns)
print(f"Learned patterns: {patterns}")
```

For manual patterns, directly edit watched_tools.json.

### Remove a command
If user wants to REMOVE a command:
1. Read watched_tools.json
2. Delete the command entry
3. Write back the file

### View patterns
If user wants to VIEW patterns for a command:
```python
from tool_guard.registry import get_bash_patterns
patterns = get_bash_patterns("command_name")
print(f"Patterns for command: {patterns}")
# None = unknown command (will trigger learning)
# [] = safe command (no write-external patterns)
# [...] = has write-external patterns
```

### List all commands
Read and display all commands from watched_tools.json with their pattern counts.

## Pattern Guidelines

When helping users write patterns:
- `[]` = safe command, never blocks (local operations like ls, cat, mkdir)
- Patterns should match WRITE-EXTERNAL operations only:
  - Uploads, pushes, remote writes
  - NOT downloads, pulls, local operations
- For file transfers (scp, rsync): use `$` anchor to match remote at END (push)
- For database clients: exclude localhost with `(?!localhost|127\\.0\\.0\\.1)`
- Always test patterns before saving

## Examples

User: "add rclone to registry"
-> Ask if they want auto-learn or manual, then add patterns

User: "remove vim from registry"
-> Delete vim entry from watched_tools.json

User: "what patterns does curl have?"
-> Show curl patterns from registry

User: "mark mytool as safe"
-> Add `"mytool": []` to registry
