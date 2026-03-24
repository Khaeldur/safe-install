"""
Configuration system for safe-install.

Loads from (in priority order):
1. CLI flags
2. Project-local ./safe-install.toml
3. User-global ~/.config/safe-install/config.toml
4. Built-in defaults

Zero external dependencies — uses tomllib (Python 3.11+) or fallback parser.
"""

import os
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

DEFAULTS = {
    "mode": {
        "default": "auto",  # "docker-first", "local-fallback", "analysis-only", "auto"
        "warn_on_fallback": True,
    },
    "sandbox": {
        "enabled": True,
        "memory_limit": "2g",
        "cpu_limit": "2",
        "timeout": 600,
    },
    "vault": {
        "extra_paths": [],
        "extra_env_vars": [],
    },
    "network": {
        "allowed_hosts": [
            "pypi.org", "files.pythonhosted.org",
            "registry.npmjs.org",
            "crates.io", "static.crates.io",
            "proxy.golang.org", "sum.golang.org",
            "rubygems.org",
            "github.com", "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "gitlab.com",
        ],
        "block_all": False,
    },
    "scan": {
        "skip_tests": True,
        "max_findings_display": 15,
    },
    "ecosystems": {
        "pip": {"enabled": True},
        "npm": {"enabled": True},
        "cargo": {"enabled": True},
        "go": {"enabled": True},
        "gem": {"enabled": True},
        "docker": {"enabled": True},
    },
    "typosquat": {
        "enabled": True,
        "max_distance": 2,
        "check_homoglyphs": True,
    },
    "intelligence": {
        "enabled": True,
        "flag_new_maintainer_days": 30,
        "flag_release_age_hours": 24,
        "flag_package_age_days": 30,
        "check_sigstore": True,
    },
    "registries": {
        "private": [],
        "internal_packages": [],
        "internal_prefixes": [],
    },
    "binary_analysis": {
        "enabled": True,
        "entropy_threshold": 7.5,
        "known_native_packages": [],
    },
    "dns": {
        "restrict_in_sandbox": True,
        "allowed_domains": [],
    },
    "filesystem_monitor": {
        "enabled": True,
        "extra_watch_paths": [],
    },
    "vault_hardening": {
        "cooldown": 5,
        "kill_suspicious": False,
    },
    "ci": {
        "auto_detect": True,
        "fail_on_critical": True,
        "report_formats": ["json"],
    },
    "import_guard": {
        "mode": "monitor",
        "whitelist_path": None,
    },
    "runtime": {
        "mode": "monitor",
        "use_strace": True,
    },
    "coordination": {
        "findings_log": "~/.config/safe-install/findings.jsonl",
        "dedup_window_seconds": 300,
        "max_log_size_mb": 50,
    },
    "wrapper": {
        "enabled": True,
        "auto_confirm_clean": True,
        "shim_dir": "~/.config/safe-install/shims",
    },
    "patterns": {
        "custom_dirs": [],
        "auto_update": False,
    },
    "tray": {
        "enabled": True,
        "poll_interval_seconds": 2,
        "notification_level": "MEDIUM",
    },
    "vscode": {
        "scan_on_save": True,
        "hover_intelligence": True,
        "terminal_interception": True,
    },
}

SENSITIVE_PATHS = [
    # SSH
    "~/.ssh",
    # Cloud providers
    "~/.aws", "~/.azure", "~/.config/gcloud", "~/.kube",
    # GPG / signing
    "~/.gnupg",
    # Git credentials
    "~/.git-credentials", "~/.gitconfig", "~/.netrc",
    # Container / package registries
    "~/.docker/config.json", "~/.npmrc", "~/.pypirc",
    # Shell history
    "~/.bash_history", "~/.zsh_history", "~/.python_history",
    "~/.node_repl_history",
    # GitHub / GitLab CLI
    "~/.config/gh", "~/.config/hub",
    # Keyring / password stores
    "~/.local/share/keyrings", "~/.password-store",
    # Crypto wallets
    "~/.bitcoin/wallet.dat", "~/.ethereum/keystore", "~/.solana/id.json",
    # Infrastructure tools
    "~/.cargo/credentials.toml",
    "~/.terraform.d/credentials.tfrc.json",
    "~/.vault-token",
    "~/.config/op",
    "~/.config/stripe", "~/.stripe",
    # CI/CD tokens
    "~/.circleci/cli.yml",
    "~/.config/netlify",
    "~/.vercel",
    # Browser credential stores
    "~/.config/google-chrome/Default/Login Data",
    "~/.config/google-chrome/Default/Cookies",
    "~/.mozilla/firefox",
    # Windows-specific
    "~/AppData/Local/Google/Chrome/User Data/Default/Login Data",
    "~/AppData/Roaming/Mozilla/Firefox/Profiles",
    # Env files (common patterns)
    "~/.env",
]

SENSITIVE_ENV_VARS = [
    # Cloud
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
    "GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_SERVICE_KEY",
    # VCS
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
    # AI
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
    "HUGGINGFACE_TOKEN", "HF_TOKEN",
    # Database
    "DATABASE_URL", "DB_PASSWORD", "REDIS_URL",
    # Payment
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    # Email
    "SENDGRID_API_KEY", "MAILGUN_API_KEY",
    # Messaging
    "SLACK_TOKEN", "SLACK_WEBHOOK_URL",
    "DISCORD_TOKEN", "TELEGRAM_BOT_TOKEN",
    # Package registries
    "NPM_TOKEN", "PYPI_TOKEN", "CARGO_REGISTRY_TOKEN",
    # Container
    "DOCKER_PASSWORD", "DOCKER_AUTH_CONFIG",
    # Secrets management
    "VAULT_TOKEN", "VAULT_ADDR",
    # SSH
    "SSH_AUTH_SOCK",
    # Kubernetes
    "KUBECONFIG",
    # CI/CD
    "CI_JOB_TOKEN", "CIRCLE_TOKEN", "TRAVIS_TOKEN",
    # Monitoring
    "SENTRY_DSN", "DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY",
    # Hosting
    "DIGITALOCEAN_ACCESS_TOKEN", "HEROKU_API_KEY",
    "NETLIFY_AUTH_TOKEN", "VERCEL_TOKEN",
    "CLOUDFLARE_API_KEY",
    # Communication
    "TWILIO_AUTH_TOKEN", "PAGERDUTY_API_KEY",
]


def _deep_merge(base, override):
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _parse_toml_fallback(text):
    """Minimal TOML parser for when tomllib isn't available (Python < 3.11)."""
    result = {}
    current_section = result
    current_key = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Section header
        if line.startswith('['):
            key = line.strip('[]').strip().strip('"')
            parts = key.split('.')
            current_section = result
            current_key = parts
            for part in parts:
                if part not in current_section:
                    current_section[part] = {}
                current_section = current_section[part]
            continue

        # Key = value
        if '=' in line:
            k, v = line.split('=', 1)
            k = k.strip().strip('"')
            v = v.strip()

            if v.lower() == 'true':
                v = True
            elif v.lower() == 'false':
                v = False
            elif v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            elif v.startswith('[') and v.endswith(']'):
                # Simple array parsing
                inner = v[1:-1].strip()
                if inner:
                    v = [x.strip().strip('"') for x in inner.split(',')]
                else:
                    v = []
            else:
                try:
                    v = int(v)
                except ValueError:
                    try:
                        v = float(v)
                    except ValueError:
                        pass

            current_section[k] = v

    return result


def load_config():
    """Load config from files, merging with defaults."""
    config = DEFAULTS.copy()

    # User-global config
    global_path = Path.home() / ".config" / "safe-install" / "config.toml"
    for path in [global_path, Path("safe-install.toml")]:
        if path.exists():
            text = path.read_text()
            if tomllib:
                parsed = tomllib.loads(text)
            else:
                parsed = _parse_toml_fallback(text)
            config = _deep_merge(config, parsed)

    return config


def get_sensitive_paths(config):
    """Get all sensitive paths, including user-configured extras."""
    paths = list(SENSITIVE_PATHS)
    paths.extend(config.get("vault", {}).get("extra_paths", []))
    return paths


def get_sensitive_env_vars(config):
    """Get all sensitive env var names, including user-configured extras."""
    vars_ = list(SENSITIVE_ENV_VARS)
    vars_.extend(config.get("vault", {}).get("extra_env_vars", []))
    return vars_
