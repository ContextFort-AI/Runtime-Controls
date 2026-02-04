import re
from ..patterns import (
    INTERPRETERS,
    INSECURE_TLS_FLAGS,
    URL_SHORTENERS,
)
from .utils import split_commands


def check_insecure_tls_flags(command):
    words = command.split()
    for word in words:
        clean = word.strip("'\"")
        if clean in INSECURE_TLS_FLAGS:
            return ("insecure_tls_flags", f"Insecure TLS flag: {clean}")

    return None


def check_shortened_url(command):
    command_lower = command.lower()
    for shortener in URL_SHORTENERS:
        if shortener in command_lower:
            return ("shortened_url", f"Shortened URL detected: {shortener}")

    return None


def _check_plain_http_to_sink_single(command):
    """Check a single command for plain HTTP piped to sink."""
    if "http://" not in command.lower():
        return None

    if "|" not in command:
        return None

    parts = command.split("|")
    for part in parts[1:]:
        words = part.strip().split()
        if words:
            cmd = words[0].lower().rsplit("/", 1)[-1]
            if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                return ("plain_http_to_sink", "Plain HTTP URL piped to interpreter")

    return None


def check_plain_http_to_sink(command):
    """Check for plain HTTP to sink, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_plain_http_to_sink_single(subcmd)
        if result:
            return result
    return None


def _check_schemeless_to_sink_single(command):
    """Check a single command for schemeless URL piped to sink."""
    if "|" not in command:
        return None

    schemeless_pattern = r'(?<!\w://)(?<!\w://www\.)([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/\S+'

    parts = command.split("|")
    first_part = parts[0]

    if re.search(schemeless_pattern, first_part):
        for part in parts[1:]:
            words = part.strip().split()
            if words:
                cmd = words[0].lower().rsplit("/", 1)[-1]
                if cmd in INTERPRETERS or cmd in ("sudo", "env"):
                    return ("schemeless_to_sink", "Schemeless URL piped to interpreter")

    return None


def check_schemeless_to_sink(command):
    """Check for schemeless URL to sink, handling && and ; separators."""
    for subcmd in split_commands(command):
        result = _check_schemeless_to_sink_single(subcmd)
        if result:
            return result
    return None
