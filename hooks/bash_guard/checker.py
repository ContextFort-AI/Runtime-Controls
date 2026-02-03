import re
import regex  # For Unicode script detection
from .data import get_known_domains, skeleton, is_known_domain
from .patterns import (
    SOURCE_COMMANDS,
    INTERPRETERS,
    INSECURE_TLS_FLAGS,
    URL_SHORTENERS,
    LOOKALIKE_TLDS,
    TRUSTED_DOCKER_REGISTRIES,
    TRUSTED_PIP_HOSTS,
    TRUSTED_NPM_HOSTS,
    WEB3_INDICATORS,
    PROXY_ENV_VARS,
    KNOWN_SENSITIVE_PATHS,
    POPULAR_REPOS,
    BIDI_CONTROL_CHARS,
    ZERO_WIDTH_CHARS,
    ARCHIVE_COMMANDS,
    ARCHIVE_SENSITIVE_TARGETS,
    DOTFILE_OVERWRITE_PATTERNS,
    HIDDEN_COMMAND_INDICATORS,
    INVALID_HOST_CHARS,
    UNICODE_DOTS,
)


def check_command(command):
    """
    Check a bash command for security issues.
    Returns tuple of (rule_id, description) if threat found, None otherwise.

    Implements checks from Tirith's rule modules.
    """
    # Command shape rules (command.rs)
    result = check_pipe_to_interpreter(command)
    if result:
        return result

    result = check_dotfile_overwrite(command)
    if result:
        return result

    result = check_archive_extract(command)
    if result:
        return result

    # Terminal rules (terminal.rs, extract.rs)
    result = check_terminal_injection(command)
    if result:
        return result

    result = check_hidden_multiline(command)
    if result:
        return result

    # Transport rules (transport.rs)
    result = check_insecure_tls_flags(command)
    if result:
        return result

    result = check_shortened_url(command)
    if result:
        return result

    result = check_plain_http_to_sink(command)
    if result:
        return result

    result = check_schemeless_to_sink(command)
    if result:
        return result

    # Ecosystem rules (ecosystem.rs)
    result = check_docker_untrusted_registry(command)
    if result:
        return result

    result = check_pip_url_install(command)
    if result:
        return result

    result = check_npm_url_install(command)
    if result:
        return result

    result = check_web3_rpc(command)
    if result:
        return result

    result = check_web3_address(command)
    if result:
        return result

    result = check_git_typosquat(command)
    if result:
        return result

    # Environment rules (environment.rs)
    result = check_proxy_env_set(command)
    if result:
        return result

    # Path rules (path.rs)
    result = check_non_ascii_path(command)
    if result:
        return result

    result = check_homoglyph_in_path(command)
    if result:
        return result

    result = check_double_encoding(command)
    if result:
        return result

    # Hostname rules (hostname.rs)
    result = check_non_ascii_hostname(command)
    if result:
        return result

    result = check_mixed_script_in_label(command)
    if result:
        return result

    result = check_userinfo_trick(command)
    if result:
        return result

    result = check_confusable_domain(command)
    if result:
        return result

    result = check_invalid_host_chars(command)
    if result:
        return result

    result = check_trailing_dot_whitespace(command)
    if result:
        return result

    result = check_non_standard_port(command)
    if result:
        return result

    result = check_lookalike_tld(command)
    if result:
        return result

    result = check_punycode_domain(command)
    if result:
        return result

    result = check_raw_ip_url(command)
    if result:
        return result

    return None


# =============================================================================
# Command shape checks (from command.rs)
# =============================================================================

def check_pipe_to_interpreter(command):
    """
    From command.rs: check_pipe_to_interpreter()
    Detects: curl | bash, wget | sh, etc.
    """
    if "|" not in command:
        return None

    parts = command.split("|")
    for i, part in enumerate(parts[1:], 1):
        part_stripped = part.strip()
        # Get first word (the command)
        words = part_stripped.split()
        if not words:
            continue

        cmd = words[0].lower()
        # Handle absolute paths
        cmd = cmd.rsplit("/", 1)[-1]

        # Check if it's an interpreter (directly or through sudo/env)
        if cmd in INTERPRETERS:
            source_part = parts[i-1].strip().split()[0] if parts[i-1].strip() else "unknown"
            source_cmd = source_part.rsplit("/", 1)[-1].lower()

            # Validate source is a source command for specific rule IDs
            if source_cmd == "curl":
                return ("curl_pipe_shell", f"curl output piped to {cmd}")
            elif source_cmd == "wget":
                return ("wget_pipe_shell", f"wget output piped to {cmd}")
            elif source_cmd in SOURCE_COMMANDS:
                return ("pipe_to_interpreter", f"{source_cmd} output piped to interpreter: {cmd}")
            else:
                return ("pipe_to_interpreter", f"Output piped to interpreter: {cmd}")

        # Check for sudo/env wrapping interpreter
        if cmd in ("sudo", "env"):
            for word in words[1:]:
                word_lower = word.lower().rsplit("/", 1)[-1]
                if word_lower in INTERPRETERS:
                    return ("pipe_to_interpreter", f"Output piped to {cmd} {word_lower}")
                if not word.startswith("-") and "=" not in word:
                    break

    return None


def check_dotfile_overwrite(command):
    """
    From command.rs: check_dotfile_overwrite()
    Detects: echo foo > ~/.bashrc, curl x >> ~/.profile, etc.
    """
    # Skip /dev/null redirects
    if "> /dev/null" in command:
        return None

    for pattern in DOTFILE_OVERWRITE_PATTERNS:
        if pattern in command:
            return ("dotfile_overwrite", f"Redirect to dotfile detected: {pattern}")

    return None


def check_archive_extract(command):
    """
    From command.rs: check_archive_extract()
    Detects: tar -C /, unzip -d ~/, etc.
    """
    words = command.split()
    if not words:
        return None

    cmd = words[0].lower().rsplit("/", 1)[-1]
    if cmd not in ARCHIVE_COMMANDS:
        return None

    for target in ARCHIVE_SENSITIVE_TARGETS:
        if target in command:
            return ("archive_extract", f"Archive extraction to sensitive path: {target}")

    return None


# =============================================================================
# Terminal checks (from terminal.rs and extract.rs)
# =============================================================================

def check_terminal_injection(command):
    """
    From extract.rs: scan_bytes()
    Detects ANSI escapes, control chars, bidi controls, zero-width chars.
    """
    # ANSI escape sequences (CSI, OSC, APC, DCS)
    if '\x1b[' in command or '\x1b]' in command or '\x1b_' in command or '\x1bP' in command:
        return ("ansi_escapes", "ANSI escape sequences detected")

    # Control characters (< 0x20 except \n, \t)
    for char in command:
        code = ord(char)
        if code < 0x20 and char not in ('\n', '\t', '\x1b'):
            return ("control_chars", f"Control character detected: 0x{code:02x}")
        if code == 0x7f:  # DEL
            return ("control_chars", "DEL control character detected")

    # Bidi controls
    for char in command:
        if char in BIDI_CONTROL_CHARS:
            return ("bidi_controls", f"Bidirectional control character: U+{ord(char):04X}")

    # Zero-width characters
    for char in command:
        if char in ZERO_WIDTH_CHARS:
            return ("zero_width_chars", f"Zero-width character: U+{ord(char):04X}")

    return None


def check_hidden_multiline(command):
    """
    From terminal.rs: check_hidden_multiline() and looks_like_hidden_command()
    Detects hidden commands on non-first lines.
    """
    lines = command.split('\n')
    if len(lines) <= 1:
        return None

    for i, line in enumerate(lines[1:], 1):
        trimmed = line.strip()
        if not trimmed:
            continue

        for indicator in HIDDEN_COMMAND_INDICATORS:
            if indicator in trimmed:
                return ("hidden_multiline", f"Hidden command on line {i+1}: {trimmed[:60]}")

    return None


# =============================================================================
# Transport checks (from transport.rs)
# =============================================================================

def check_insecure_tls_flags(command):
    """
    From transport.rs: check_insecure_flags()
    Detects: curl -k, wget --no-check-certificate, etc.
    """
    words = command.split()
    for word in words:
        # Strip quotes
        clean = word.strip("'\"")
        if clean in INSECURE_TLS_FLAGS:
            return ("insecure_tls_flags", f"Insecure TLS flag: {clean}")

    return None


def check_shortened_url(command):
    """
    From transport.rs: check_shortened_url()
    Detects shortened URLs that hide destination.
    """
    command_lower = command.lower()
    for shortener in URL_SHORTENERS:
        if shortener in command_lower:
            return ("shortened_url", f"Shortened URL detected: {shortener}")

    return None


def check_plain_http_to_sink(command):
    """
    From transport.rs: check_plain_http_to_sink()
    Detects plain HTTP URLs piped to interpreters.
    """
    if "http://" not in command.lower():
        return None

    if "|" not in command:
        return None

    # Check if piped to interpreter
    parts = command.split("|")
    for part in parts[1:]:
        words = part.strip().split()
        if words:
            cmd = words[0].lower().rsplit("/", 1)[-1]
            if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                return ("plain_http_to_sink", "Plain HTTP URL piped to interpreter")

    return None


def check_schemeless_to_sink(command):
    """
    From transport.rs: check() - SchemelessToSink
    Detects URLs without scheme passed to download/execute commands.
    """
    if "|" not in command:
        return None

    # Look for schemeless URLs (domain.com/path without http://)
    # Pattern: word with dot followed by slash, but no scheme
    schemeless_pattern = r'(?<!\w://)(?<!\w://www\.)([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/\S+'

    parts = command.split("|")
    first_part = parts[0]

    # Check if first part has a schemeless URL
    if re.search(schemeless_pattern, first_part):
        # Check if piped to interpreter
        for part in parts[1:]:
            words = part.strip().split()
            if words:
                cmd = words[0].lower().rsplit("/", 1)[-1]
                if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                    return ("schemeless_to_sink", "Schemeless URL piped to interpreter")

    return None


# =============================================================================
# Ecosystem checks (from ecosystem.rs)
# =============================================================================

def check_docker_untrusted_registry(command):
    """
    From ecosystem.rs: check_docker_untrusted_registry()
    Detects docker pull/run from untrusted registries.
    """
    words = command.split()
    if len(words) < 3:
        return None

    cmd = words[0].lower()
    if cmd not in ("docker", "podman", "nerdctl"):
        return None

    subcmd = words[1].lower()
    if subcmd not in ("pull", "run", "create"):
        return None

    # Find the image argument (skip flags)
    for word in words[2:]:
        if word.startswith("-"):
            continue

        # Check if it has a registry prefix
        if "/" in word and ":" not in word.split("/")[0]:
            # Could be registry/image
            registry = word.split("/")[0].lower()
            if registry not in TRUSTED_DOCKER_REGISTRIES:
                # Check if it ends with a trusted registry domain
                trusted = any(registry.endswith(f".{r}") for r in TRUSTED_DOCKER_REGISTRIES)
                if not trusted and "." in registry:
                    return ("docker_untrusted_registry", f"Docker image from untrusted registry: {registry}")
        break

    return None


def check_pip_url_install(command):
    """
    From ecosystem.rs: check_pip_url_install()
    Detects pip install from non-PyPI sources.
    """
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd not in ("pip", "pip3"):
        return None

    if "install" not in [w.lower() for w in words]:
        return None

    # Check for URLs in the command
    urls = re.findall(r'https?://([^/\s]+)', command)
    for host in urls:
        host_lower = host.lower()
        if host_lower not in TRUSTED_PIP_HOSTS and not host_lower.endswith(".pypi.org"):
            return ("pip_url_install", f"pip install from non-PyPI source: {host}")

    # Check for --index-url or -i with non-PyPI host
    for i, word in enumerate(words):
        if word in ("--index-url", "-i", "--extra-index-url"):
            if i + 1 < len(words):
                url = words[i + 1]
                match = re.search(r'https?://([^/\s]+)', url)
                if match:
                    host = match.group(1).lower()
                    if host not in TRUSTED_PIP_HOSTS and not host.endswith(".pypi.org"):
                        return ("pip_url_install", f"pip using non-PyPI index: {host}")

    return None


def check_npm_url_install(command):
    """
    From ecosystem.rs: check_npm_url_install()
    Detects npm install from non-registry sources.
    """
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd not in ("npm", "npx", "yarn", "pnpm"):
        return None

    if "install" not in [w.lower() for w in words] and "add" not in [w.lower() for w in words]:
        return None

    # Check for URLs ending in .tgz or containing /npm/
    for word in words:
        if ".tgz" in word or "/npm/" in word:
            match = re.search(r'https?://([^/\s]+)', word)
            if match:
                host = match.group(1).lower()
                if host not in TRUSTED_NPM_HOSTS and not host.endswith(".npmjs.org"):
                    return ("npm_url_install", f"npm install from non-registry source: {host}")

    # Check for --registry with non-npm host
    for i, word in enumerate(words):
        if word == "--registry":
            if i + 1 < len(words):
                url = words[i + 1]
                match = re.search(r'https?://([^/\s]+)', url)
                if match:
                    host = match.group(1).lower()
                    if host not in TRUSTED_NPM_HOSTS and not host.endswith(".npmjs.org"):
                        return ("npm_url_install", f"npm using non-registry source: {host}")

    return None


def check_web3_rpc(command):
    """
    From ecosystem.rs: check_web3_rpc()
    Detects Web3 RPC endpoint URLs.
    """
    # Check for RPC path indicators
    if not any(ind in command for ind in ["/v1/", "/rpc", "/jsonrpc"]):
        return None

    # Check for Web3 provider hosts
    command_lower = command.lower()
    for indicator in WEB3_INDICATORS:
        if indicator in command_lower:
            return ("web3_rpc_endpoint", f"Web3 RPC endpoint detected: {indicator}")

    return None


def check_web3_address(command):
    """
    From ecosystem.rs: check_web3_address_in_url()
    Detects Ethereum addresses in URLs.
    """
    # Ethereum address pattern: 0x followed by 40 hex chars
    if re.search(r'0x[0-9a-fA-F]{40}', command):
        return ("web3_address_in_url", "Ethereum address detected in command")

    return None


def check_git_typosquat(command):
    """
    From ecosystem.rs: check_git_typosquat()
    Detects potential typosquatted git repositories.
    """
    # Check if this is a git clone command
    words = command.split()
    if len(words) < 2:
        return None

    cmd = words[0].lower()
    if cmd != "git":
        return None

    if "clone" not in [w.lower() for w in words]:
        return None

    # Extract URL from command
    urls = re.findall(r'(?:https?://|git@)([^/\s:]+)[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?(?:\s|$)', command)
    for host, owner, repo in urls:
        host_lower = host.lower()
        # Only check known git hosting platforms
        if host_lower not in ("github.com", "gitlab.com", "bitbucket.org"):
            continue

        owner_lower = owner.lower()
        repo_lower = repo.lower().rstrip('.git')

        # Check against popular repos
        for pop_owner, pop_repo in POPULAR_REPOS:
            po = pop_owner.lower()
            pr = pop_repo.lower()

            # Check if either owner or repo is within edit distance 1
            if owner_lower == po and _levenshtein(repo_lower, pr) == 1:
                return ("git_typosquat", f"Possible typosquat: {owner}/{repo} is 1 edit from {pop_owner}/{pop_repo}")
            if repo_lower == pr and _levenshtein(owner_lower, po) == 1:
                return ("git_typosquat", f"Possible typosquat: {owner}/{repo} is 1 edit from {pop_owner}/{pop_repo}")

    return None


def _levenshtein(a, b):
    """
    From ecosystem.rs: levenshtein()
    Calculate Levenshtein distance between two strings.
    """
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,
                dp[i][j-1] + 1,
                dp[i-1][j-1] + cost
            )

    return dp[m][n]


# =============================================================================
# Environment checks (from environment.rs)
# =============================================================================

def check_proxy_env_set(command):
    """
    From environment.rs: check()
    Detects proxy environment variable manipulation in commands.
    """
    # Check for export/set of proxy vars
    for var in PROXY_ENV_VARS:
        # export HTTP_PROXY=..., HTTP_PROXY=... command, env HTTP_PROXY=...
        patterns = [
            f"export {var}=",
            f"{var}=",
            f"set {var}=",
        ]
        for pattern in patterns:
            if pattern in command:
                return ("proxy_env_set", f"Proxy environment variable being set: {var}")

    return None


# =============================================================================
# Path checks (from path.rs)
# =============================================================================

def check_non_ascii_path(command):
    """
    From path.rs: check_non_ascii_path()
    Detects non-ASCII characters in URL paths.
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        # Get path part
        try:
            parts = url.split("://")[1].split("/", 1)
            if len(parts) < 2:
                continue
            path = "/" + parts[1]
        except IndexError:
            continue

        # Check for non-ASCII bytes
        if any(ord(c) > 127 for c in path):
            return ("non_ascii_path", "Non-ASCII characters in URL path")

    return None


def check_homoglyph_in_path(command):
    """
    From path.rs: check_homoglyph_in_path()
    Detects potential homoglyphs in URL paths near sensitive keywords.
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        # Get path part
        try:
            path = url.split("://")[1].split("/", 1)
            if len(path) < 2:
                continue
            path = "/" + path[1]
        except IndexError:
            continue

        # Check each path segment
        for segment in path.split("/"):
            if not segment:
                continue

            # Check if segment has mixed ASCII and non-ASCII
            has_ascii = any(c.isascii() and c.isalpha() for c in segment)
            has_non_ascii = any(ord(c) > 127 for c in segment)

            if has_ascii and has_non_ascii:
                # Check proximity to known sensitive paths
                segment_lower = segment.lower()
                for known in KNOWN_SENSITIVE_PATHS:
                    if _levenshtein(segment_lower, known) <= 2:
                        return ("homoglyph_in_path", f"Potential homoglyph in path: '{segment}' looks like '{known}'")

    return None


def check_double_encoding(command):
    """
    From path.rs: check_double_encoding()
    Detects double-encoded URL paths (%25XX patterns).
    """
    # %25 is percent-encoded percent sign, indicating double encoding
    if "%25" in command:
        # Verify it's followed by hex digits (proper double encoding)
        if re.search(r'%25[0-9a-fA-F]{2}', command):
            return ("double_encoding", "Double-encoded URL path detected (%25XX)")

    return None


# =============================================================================
# Hostname checks (from hostname.rs)
# =============================================================================

def _extract_host_from_url(url):
    """Extract hostname from a URL string."""
    try:
        # Remove scheme
        if "://" in url:
            rest = url.split("://")[1]
        else:
            rest = url

        # Handle userinfo (user:pass@host)
        if "@" in rest.split("/")[0]:
            rest = rest.split("@")[-1]

        # Get host:port part
        host_part = rest.split("/")[0]

        # Remove port
        if ":" in host_part:
            host_part = host_part.rsplit(":", 1)[0]

        return host_part
    except (IndexError, ValueError):
        return None


def check_non_ascii_hostname(command):
    """
    From hostname.rs: check_non_ascii_hostname()
    Detects non-ASCII characters in hostname (potential homograph).
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = _extract_host_from_url(url)
        if host and any(ord(c) > 127 for c in host):
            return ("non_ascii_hostname", f"Non-ASCII characters in hostname: {host}")

    return None


def check_mixed_script_in_label(command):
    """
    From hostname.rs: check_mixed_script_in_label()
    Detects hostname labels that mix multiple Unicode scripts (e.g., Latin + Cyrillic).
    Uses the `regex` library for Unicode script detection.
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = _extract_host_from_url(url)
        if not host:
            continue

        # Check each label (part between dots)
        for label in host.split("."):
            if not label:
                continue

            scripts = set()
            for char in label:
                # Skip hyphens and digits
                if char == "-" or char.isdigit():
                    continue

                # Detect script using regex Unicode properties
                if regex.match(r'\p{Script=Latin}', char):
                    scripts.add('Latin')
                elif regex.match(r'\p{Script=Cyrillic}', char):
                    scripts.add('Cyrillic')
                elif regex.match(r'\p{Script=Greek}', char):
                    scripts.add('Greek')
                elif regex.match(r'\p{Script=Han}', char):
                    scripts.add('Han')
                elif regex.match(r'\p{Script=Hiragana}', char):
                    scripts.add('Hiragana')
                elif regex.match(r'\p{Script=Katakana}', char):
                    scripts.add('Katakana')
                elif regex.match(r'\p{Script=Arabic}', char):
                    scripts.add('Arabic')
                elif regex.match(r'\p{Script=Hebrew}', char):
                    scripts.add('Hebrew')
                # Skip Common and Inherited scripts

            if len(scripts) > 1:
                return ("mixed_script_in_label", f"Mixed scripts in hostname label '{label}': {scripts}")

    return None


def check_userinfo_trick(command):
    """
    From hostname.rs: check_userinfo_trick()
    Detects URLs with domain-like userinfo (e.g., http://github.com@evil.com/).
    """
    # Look for URLs with userinfo containing dots
    urls = re.findall(r'https?://([^@/\s]+)@[^\s]+', command)

    for userinfo in urls:
        if "." in userinfo:
            return ("userinfo_trick", f"Domain-like userinfo in URL: {userinfo}@...")

    return None


def check_confusable_domain(command):
    """
    From hostname.rs: check_confusable_domain()
    Detects domains that are visually similar to known domains (homograph attack).
    """
    known_domains = get_known_domains()
    if not known_domains:
        return None

    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = _extract_host_from_url(url)
        if not host:
            continue

        host_lower = host.lower()

        # Skip if it's exactly a known domain
        if host_lower in known_domains:
            continue

        # Get skeleton form (replace confusables with ASCII)
        host_skeleton = skeleton(host_lower)

        # Check if skeleton matches a known domain
        for known in known_domains:
            if host_skeleton == known and host_lower != known:
                return ("confusable_domain", f"Domain '{host}' is visually similar to known domain '{known}'")

            # Also check Levenshtein distance for typosquatting
            # Only for domains >= 8 chars to avoid false positives
            if len(known) >= 8:
                len_diff = abs(len(host_lower) - len(known))
                if len_diff <= 3 and _levenshtein(host_lower, known) == 1:
                    return ("confusable_domain", f"Domain '{host}' is 1 edit from known domain '{known}'")

    return None


def check_invalid_host_chars(command):
    """
    From hostname.rs: check_invalid_host_chars()
    Detects invalid characters in hostname (%, \\, unicode dots, control chars).
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = _extract_host_from_url(url)
        if not host:
            continue

        # Check for invalid chars
        for char in host:
            if char in INVALID_HOST_CHARS:
                return ("invalid_host_chars", f"Invalid character '{char}' in hostname")
            if char in UNICODE_DOTS:
                return ("invalid_host_chars", f"Unicode dot character in hostname: U+{ord(char):04X}")
            if ord(char) < 0x20 or char.isspace():
                return ("invalid_host_chars", "Control character or whitespace in hostname")

    return None


def check_trailing_dot_whitespace(command):
    """
    From hostname.rs: check_trailing_dot_whitespace()
    Detects trailing dot or whitespace in hostname.
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)

    for url in urls:
        host = _extract_host_from_url(url)
        if not host:
            continue

        if host.endswith("."):
            return ("trailing_dot_whitespace", "Trailing dot in hostname")
        if host[-1:].isspace():
            return ("trailing_dot_whitespace", "Trailing whitespace in hostname")

    return None


def check_non_standard_port(command):
    """
    From hostname.rs: check_non_standard_port()
    Detects non-standard ports on known domains.
    """
    # Standard ports
    standard_ports = {80, 443, 22, 9418}

    # Extract URLs with ports
    url_port_pattern = r'https?://([^:/\s]+):(\d+)'
    matches = re.findall(url_port_pattern, command)

    for host, port_str in matches:
        try:
            port = int(port_str)
        except ValueError:
            continue

        if port in standard_ports:
            continue

        # Check if it's a known domain
        if is_known_domain(host.lower()):
            return ("non_standard_port", f"Non-standard port {port} on known domain '{host}'")

    return None


def check_lookalike_tld(command):
    """
    From hostname.rs: check_lookalike_tld()
    Detects TLDs that look like file extensions.
    """
    # Extract URLs
    urls = re.findall(r'https?://[^\s]+', command)
    for url in urls:
        # Get host part
        host = url.split("://")[1].split("/")[0].split(":")[0].lower()
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in LOOKALIKE_TLDS:
            return ("lookalike_tld", f"Lookalike TLD detected: .{tld}")

    return None


def check_punycode_domain(command):
    """
    From hostname.rs: check_punycode_domain()
    Detects punycode (xn--) domains.
    """
    if "xn--" in command.lower():
        return ("punycode_domain", "Punycode domain detected (potential homograph)")

    return None


def check_raw_ip_url(command):
    """
    From hostname.rs: check_raw_ip()
    Detects URLs using IP addresses instead of domains.
    """
    # IPv4 in URL
    ipv4_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ipv4_pattern, command):
        return ("raw_ip_url", "URL uses raw IP address instead of domain")

    return None
