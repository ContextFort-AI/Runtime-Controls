from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def load_known_domains():
    """Load known_domains.csv into a set of domain names."""
    domains = set()
    path = DATA_DIR / "known_domains.csv"
    if not path.exists():
        return domains

    for line in path.read_text().splitlines()[1:]:  # Skip header
        if line.strip():
            domain = line.split(",")[0].strip()
            if domain:
                domains.add(domain.lower())

    return domains


def load_confusables():
    """
    Load confusables.txt into a mapping of confusable -> target character.
    Returns dict mapping confusable codepoint to ASCII equivalent.
    """
    confusables = {}
    path = DATA_DIR / "confusables.txt"
    if not path.exists():
        return confusables

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("#")[0].strip().split()
        if len(parts) >= 2:
            try:
                confusable_cp = int(parts[0], 16)
                target_cp = int(parts[1], 16)
                confusables[chr(confusable_cp)] = chr(target_cp)
            except (ValueError, IndexError):
                continue

    return confusables


# Cached data
_known_domains = None
_confusables = None


def get_known_domains():
    """Get cached known domains set."""
    global _known_domains
    if _known_domains is None:
        _known_domains = load_known_domains()
    return _known_domains


def get_confusables():
    """Get cached confusables mapping."""
    global _confusables
    if _confusables is None:
        _confusables = load_confusables()
    return _confusables


def skeleton(s):
    """
    From confusables.rs: skeleton()
    Convert a string to its "skeleton" form by replacing confusables with targets.
    """
    confusables = get_confusables()
    result = []
    for char in s:
        result.append(confusables.get(char, char))
    return "".join(result)


def is_known_domain(domain):
    """Check if a domain is in the known domains list."""
    return domain.lower() in get_known_domains()
