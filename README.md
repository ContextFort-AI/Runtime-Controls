# ContextFort - Runtime Security for Claude Code

**Run --dangerously-skip-permissions but not for malicious commands or write operations out of your sandbox**

I’ve been running Claude Code with --dangerously-skip-permissions for a while because a lot of the permissions prompts are noisy when the command’s radius is limited to my local sandbox.
But I don’t want anything that makes changes to external environments or talks to the network to run without my approval.

Vercel also lets Claude Code search through skills from a marketplace that anyone can upload to.
At this point, prompt injections are no longer “indirect”, claude code is asked to follow them through skills.

The plugin:
1. Always prompts for “write-external” commands (uploads, API calls, remote writes), e.g. scp, curl -X POST, git push, etc.
2. Blocks known malware patterns (finally respecting decades-long security research)

The “write-external” commands are maintained in a registry.
If a command isn’t in the registry, it reads man / --help to find the usages in which it writes externally, then adds them to the registry.


## Installation

```bash
/plugin marketplace add ContextFort-AI/Runtime-Controls
/plugin install contextfort@contextfort-marketplace
```

The plugin uses Haiku to learn patterns for unknown commands. So make sure $ANTHROPIC_API_KEY is set.
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## What it does

When Claude Code tries to run a bash command, the plugin checks:

1. Blocks dangerous patterns like:
   - Curl to webhook URLs
   - Git clone from typosquatted repos
   - Environment variable exfiltration
   - And 30+ other security rules

2. Asks permission for:
   - `curl -X POST`, `curl -d` (HTTP uploads)
   - `scp file user@host:/path` (file push)
   - `git push` (code push)
   - `npm publish` (package publish)
   - `psql -h remote.server.com` (remote DB)
   - `ssh`, `telnet`, `nc` (remote sessions)
   - And 100+ other write-external patterns

3. Asks permission for **MCP tools that modify external state**

## Managing the Registry

Claude Code cna use the SKILLs to add/remove commands:

Tell claude: "add sqlite3 to always ask for permissions"
Or invoke the skill directly:/contextfort:registry add sqlite3 --patterns '["sqlite3\\s"]

## Disabling Analytics

The plugin sends anonymous usage stats (hook invocations, blocks) to help improve the product.

To disable:
```bash
export CONTEXTFORT_NO_ANALYTICS=1
```

## License
MIT