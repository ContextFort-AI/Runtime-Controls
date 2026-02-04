import json
import re
import subprocess
import os
from pathlib import Path
from bash_guard.checks.utils import split_commands

WATCHED_FILE = Path(__file__).parent / "watched_tools.json"


def _load_config():
    if WATCHED_FILE.exists():
        return json.loads(WATCHED_FILE.read_text())
    return {"bash-write-external": {}}


def _save_config(config):
    WATCHED_FILE.write_text(json.dumps(config, indent=2))


def get_bash_command_name(command):
    first_part = command.split("|")[0].strip()

    parts = first_part.split()
    for part in parts:
        if "=" in part:
            continue
        base = part.rsplit("/", 1)[-1].lower()
        if base in ("sudo", "env", "nohup", "time", "nice"):
            continue
        return base

    return None


def get_bash_patterns(cmd_name):
    config = _load_config()
    return config.get("bash-write-external", {}).get(cmd_name, None)


def save_bash_patterns(cmd_name, patterns):
    config = _load_config()
    if "bash-write-external" not in config:
        config["bash-write-external"] = {}
    config["bash-write-external"][cmd_name] = patterns
    _save_config(config)


def _check_single_command_write_external(subcmd):
    cmd_name = get_bash_command_name(subcmd)
    if not cmd_name:
        return False, None, None

    patterns = get_bash_patterns(cmd_name)
    if patterns is None:
        return None, None, cmd_name

    if not patterns:
        return False, None, None

    for pattern in patterns:
        try:
            if re.search(pattern, subcmd, re.IGNORECASE):
                return True, pattern, None
        except re.error:
            continue

    return False, None, None


def check_bash_write_external(command):
    unknown_cmds = []

    for subcmd in split_commands(command):
        is_write, pattern, unknown_cmd = _check_single_command_write_external(subcmd)

        if is_write:
            return True, pattern
        if unknown_cmd:
            unknown_cmds.append(unknown_cmd)

    if unknown_cmds:
        return None, None

    return False, None


def get_unknown_bash_commands(command):
    unknown = []
    for subcmd in split_commands(command):
        cmd_name = get_bash_command_name(subcmd)
        if cmd_name:
            patterns = get_bash_patterns(cmd_name)
            if patterns is None:
                unknown.append(cmd_name)
    return unknown


def fetch_command_help(cmd_name):
    help_text = ""

    try:
        result = subprocess.run(
            ["man", "-f", cmd_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            help_text += f"WHATIS:\n{result.stdout}\n\n"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        result = subprocess.run(
            [cmd_name, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "LANG": "C"}
        )
        output = result.stdout or result.stderr
        if output:
            help_text += f"HELP:\n{output[:2000]}\n"
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    if not help_text:
        try:
            result = subprocess.run(
                ["man", cmd_name],
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "LANG": "C", "MANPAGER": "cat"}
            )
            if result.returncode == 0:
                help_text = result.stdout[:3000]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return help_text or f"No documentation found for {cmd_name}"


def learn_bash_patterns(cmd_name):
    from prompt_guard.llm import ask_haiku

    help_text = fetch_command_help(cmd_name)

    system = """Return regex patterns matching WRITE-EXTERNAL command usage (sending data to remote systems).

WRITE-EXTERNAL:
- HTTP uploads: curl -d, curl -F, curl -T, curl -X POST/PUT/PATCH/DELETE
- File transfer TO remote: scp/rsync where user@host: is at END of command
- Remote shells: ssh, telnet (any connection)
- Email: mail, sendmail (any usage)
- Git push: git push, git send-email
- Publishing: npm publish, cargo publish, gem push, twine upload
- Remote DB: mysql/psql/redis-cli/mongo with -h pointing to non-localhost
- Cloud uploads: aws s3 cp TO s3://, gsutil cp TO gs://, az storage upload
- K8s writes: kubectl apply/create/delete/patch, helm install/upgrade
- Infrastructure: terraform apply, ansible-playbook (remote execution)
- Network tools: nc/netcat connections, ftp, sftp, telnet

NOT write-external: downloads, local ops, localhost connections, package installs (pip/npm/apt install)

CORRECT PATTERN EXAMPLES:
- curl POST/data: ["curl\\s+.*-d\\s", "curl\\s+.*--data", "curl\\s+.*-X\\s+(POST|PUT)"]
- scp push: ["scp\\s+.*\\s+\\S+@\\S+:\\S*$"]  (remote at END with $ anchor)
- mysql remote: ["mysql\\s+.*-h\\s+(?!localhost|127\\.0\\.0\\.1)\\S+"]
- ssh: ["ssh\\s+\\S+@\\S+", "ssh\\s+-"]
- nc: ["nc\\s+\\S+\\s+\\d+", "nc\\s+-"]

Return JSON array. Empty [] if no write-external capability."""

    user = f"Command: {cmd_name}\n\nDocumentation:\n{help_text}"

    response = ask_haiku(system, user)

    try:
        match = re.search(r'\[.*\]', response, re.DOTALL)
        if match:
            patterns = json.loads(match.group())
            if isinstance(patterns, list):
                valid_patterns = []
                for p in patterns:
                    if isinstance(p, str):
                        try:
                            re.compile(p)
                            valid_patterns.append(p)
                        except re.error:
                            pass
                return valid_patterns
    except json.JSONDecodeError:
        pass

    return []
