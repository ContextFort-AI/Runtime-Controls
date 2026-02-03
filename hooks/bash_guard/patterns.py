# From command.rs: is_source_command()
SOURCE_COMMANDS = {
    "curl", "wget", "fetch", "scp", "rsync",
    "iwr", "irm", "invoke-webrequest", "invoke-restmethod"
}

# From command.rs and extract.rs: is_interpreter()
INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh",
    "python", "python3", "node", "perl", "ruby", "php",
    "iex", "invoke-expression"
}

# From transport.rs: check_insecure_flags()
INSECURE_TLS_FLAGS = {"-k", "--insecure", "--no-check-certificate"}

# From transport.rs: check_shortened_url()
URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "v.gd", "goo.gl", "ow.ly"
}

# From hostname.rs: check_lookalike_tld()
LOOKALIKE_TLDS = {"zip", "mov", "app", "dev", "run"}

# From ecosystem.rs: check_docker_untrusted_registry()
TRUSTED_DOCKER_REGISTRIES = {
    "docker.io", "ghcr.io", "gcr.io", "quay.io",
    "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws"
}

# From ecosystem.rs: check_pip_url_install()
TRUSTED_PIP_HOSTS = {"pypi.org", "files.pythonhosted.org"}

# From ecosystem.rs: check_npm_url_install()
TRUSTED_NPM_HOSTS = {"registry.npmjs.org", "npmjs.com"}

# From ecosystem.rs: check_web3_rpc()
WEB3_INDICATORS = {
    "infura.io", "alchemy.com", "moralis.io", "chainstack.com", "getblock.io"
}

# From environment.rs: check()
PROXY_ENV_VARS = {
    "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy"
}

# From path.rs: check_homoglyph_in_path()
KNOWN_SENSITIVE_PATHS = {
    "install", "setup", "init", "config", "login", "auth",
    "admin", "api", "token", "key", "secret", "password"
}

# From data/popular_repos.csv: for check_git_typosquat()
POPULAR_REPOS = [
    ("torvalds", "linux"),
    ("microsoft", "vscode"),
    ("facebook", "react"),
    ("vuejs", "vue"),
    ("angular", "angular"),
    ("tensorflow", "tensorflow"),
    ("kubernetes", "kubernetes"),
    ("golang", "go"),
    ("rust-lang", "rust"),
    ("python", "cpython"),
    ("nodejs", "node"),
    ("docker", "docker-ce"),
    ("moby", "moby"),
    ("homebrew", "brew"),
    ("ohmyzsh", "ohmyzsh"),
    ("nvm-sh", "nvm"),
    ("git", "git"),
    ("apache", "httpd"),
    ("nginx", "nginx"),
    ("redis", "redis"),
    ("postgres", "postgres"),
    ("mysql", "mysql-server"),
    ("elastic", "elasticsearch"),
    ("grafana", "grafana"),
    ("prometheus", "prometheus"),
    ("hashicorp", "terraform"),
    ("hashicorp", "vault"),
    ("ansible", "ansible"),
    ("chef", "chef"),
    ("puppet", "puppet"),
]

# From terminal.rs: looks_like_hidden_command()
HIDDEN_COMMAND_INDICATORS = [
    "curl ", "wget ", "bash", "/bin/", "sudo ", "rm ", "chmod ",
    "eval ", "exec ", "> /", ">> /", "| sh"
]

# From extract.rs: is_bidi_control()
BIDI_CONTROL_CHARS = {
    '\u200e',  # LRM
    '\u200f',  # RLM
    '\u202a',  # LRE
    '\u202b',  # RLE
    '\u202c',  # PDF
    '\u202d',  # LRO
    '\u202e',  # RLO
    '\u2066',  # LRI
    '\u2067',  # RLI
    '\u2068',  # FSI
    '\u2069',  # PDI
}

# From extract.rs: is_zero_width()
ZERO_WIDTH_CHARS = {
    '\u200b',  # ZWSP
    '\u200c',  # ZWNJ
    '\u200d',  # ZWJ
    '\ufeff',  # BOM / ZWNBSP
}

# From command.rs: check_archive_extract()
ARCHIVE_COMMANDS = {"tar", "unzip", "7z"}
ARCHIVE_SENSITIVE_TARGETS = [
    "-C /", "-C ~/", "-C $HOME/",
    "-d /", "-d ~/", "-d $HOME/",
    "> ~/.", ">> ~/."
]

# From command.rs: check_dotfile_overwrite()
DOTFILE_OVERWRITE_PATTERNS = [
    "> ~/.", ">> ~/.",
    "> $HOME/.", ">> $HOME/."
]

# From hostname.rs: check_invalid_host_chars()
INVALID_HOST_CHARS = {'%', '\\'}
UNICODE_DOTS = {'\uff0e', '\u3002', '\uff61'}  # Fullwidth/ideographic dots
