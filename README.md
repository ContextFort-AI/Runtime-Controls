# ContextFort - Runtime Security for Claude Code

Runtime security plugin that protects against:
- **Write-external operations** - Blocks uploads, pushes, remote database connections
- **Dangerous bash patterns** - Tirith-inspired security rules

## Installation

### Step 1: Add the marketplace

```bash
/plugin marketplace add ContextFort-AI/Runtime-Controls
```

### Step 2: Install the plugin

```bash
/plugin install contextfort@contextfort-marketplace
```

Or use the interactive UI:
1. Run `/plugin`
2. Go to **Discover** tab
3. Find "contextfort" and click Install

### Step 3: Set your Anthropic API key (for auto-learning)

The plugin uses Claude Haiku to learn patterns for unknown commands.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Or create `~/.claude/runtime-monitor/.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

## What it does

When Claude Code tries to run a bash command, the plugin checks:

1. **Tirith security rules** - Blocks dangerous patterns like:
   - Curl to webhook URLs
   - Git clone from typosquatted repos
   - Environment variable exfiltration
   - And 30+ other security rules

2. **Write-external detection** - Asks permission for:
   - `curl -X POST`, `curl -d` (HTTP uploads)
   - `scp file user@host:/path` (file push)
   - `git push` (code push)
   - `npm publish` (package publish)
   - `psql -h remote.server.com` (remote DB)
   - `ssh`, `telnet`, `nc` (remote sessions)
   - And 100+ other write-external patterns

3. **MCP write tools** - Asks permission for MCP tools that modify external state

## Managing the Registry

Use the CLI tool to add/remove commands:

```bash
cd hooks/

# List all commands
python3 manage_registry.py list

# View patterns for a command
python3 manage_registry.py view curl

# Add a safe command (never blocks)
python3 manage_registry.py add mytool --safe

# Auto-learn patterns for unknown command
python3 manage_registry.py add mytool --learn

# Add with manual patterns
python3 manage_registry.py add mytool --patterns '["mytool\\s+upload"]'

# Remove a command
python3 manage_registry.py remove mytool

# Test if a command would be blocked
python3 manage_registry.py test curl "curl -X POST https://api.com"
```

## Disabling Analytics

The plugin sends anonymous usage stats (hook invocations, blocks) to help improve the product.

To disable:
```bash
export CONTEXTFORT_NO_ANALYTICS=1
```

## License

MIT
