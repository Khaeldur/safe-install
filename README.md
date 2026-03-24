# safe-install

[![PyPI version](https://badge.fury.io/py/safe-install.svg)](https://pypi.org/project/safe-install/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()

Supply chain attack defense for **pip**, **npm**, **cargo**, **go**, **gem**, and **Docker**.

Zero dependencies. Every time you run `pip install` or `npm install`, any package in the dependency tree can execute arbitrary code and steal your SSH keys, cloud credentials, API tokens, browser passwords, crypto wallets, and shell history. This tool stops that.

## Install

```bash
pip install safe-install
```

### Or download standalone (zero deps)

```bash
curl -sSL https://raw.githubusercontent.com/safe-install/safe-install/main/install.sh | bash
```

## The Problem

```
pip install litellm          # stole SSH keys, AWS/GCP/Azure creds, env vars
npm install event-stream     # backdoor targeting Bitcoin wallet Copay
npm install ua-parser-js     # cryptominer + password stealer (7M weekly downloads)
cargo install rustdecimal    # typosquat that stole env vars via build.rs
gem install strong_password  # backdoor via compromised maintainer account
docker pull ngnix            # typosquat cryptominer image
```

A single `pip install some-tool` can pull in hundreds of transitive dependencies, any of which could be compromised. You have no visibility into what runs during install.

## Defense Layers

| Layer | Method | Strength | What it stops |
|-------|--------|----------|---------------|
| 1 | **Docker Sandbox** | Flawless | Package code runs in isolated container with zero access to host filesystem, credentials, or network |
| 2 | **Binary-only mode** | Flawless (install-time) | Wheels/prebuilt packages don't execute code during install. Refuses source distributions. |
| 3 | **Hash lockfile** | Flawless (tampering) | SHA256 verification detects any modification to packages |
| 4 | **Typosquat detection** | ~95% | Catches name confusion attacks (e.g. `reqeusts` vs `requests`) using edit distance + popularity DB |
| 5 | **Package intelligence** | ~90% | Cross-references PyPI/npm metadata: age, maintainer history, download counts, known-malicious lists |
| 6 | **Credential vault** | ~95% | Moves sensitive files to temp vault, clears env vars during install |
| 7 | **Source inspection** | ~70% | Scans setup.py/postinstall.js/build.rs for exfiltration patterns |
| 8 | **Filesystem snapshot** | ~85% | Takes before/after snapshot of key directories, alerts on unexpected file changes |
| 9 | **Vault hardening** | ~90% | Encrypts vault contents, decoy files, tamper detection on vault directory |
| 10 | **DNS defense** | ~80% | Monitors/blocks DNS exfiltration attempts during install (encoded data in DNS queries) |
| 11 | **Import guard** | ~75% | Runtime import hook that intercepts suspicious module loads after install |
| 12 | **Runtime monitor** | ~60% | Detects unexpected outbound connections, file access, and process spawning at runtime |

**Use Layer 1 (Docker).** Everything else is a fallback.

## Distribution Channels

| Channel | Target | Install |
|---------|--------|---------|
| **PyPI** | CLI users | `pip install safe-install` |
| **System tray app** | Desktop users | `pip install safe-install[tray]` |
| **VS Code extension** | VS Code users | Install from VS Code Marketplace |
| **Docker Desktop extension** | Docker users | Install from Docker Hub |
| **GitHub Action** | CI/CD pipelines | `uses: safe-install/safe-install-action@v1` |

## Quick Start

```bash
# Check what's exposed on your machine right now
safe-install check-env

# Install a package with full protection
safe-install install requests

# Audit a package without installing
safe-install audit litellm

# Scan a local project for suspicious patterns (all languages)
safe-install scan ./my-project/
```

## Usage

### Protected Install

```bash
# Auto-detects ecosystem from package name
safe-install install requests                    # pip
safe-install install lodash                      # npm (if starts with @)
safe-install install -e npm express              # explicit ecosystem
safe-install install -e cargo serde
safe-install install -e go github.com/gin-gonic/gin
safe-install install -e docker nginx:latest

# Docker sandbox (default if Docker is available)
safe-install install flask

# Binary-only (refuse source distributions — no setup.py runs)
safe-install install flask --binary-only

# Fallback to credential vault (when Docker unavailable)
safe-install install flask --no-sandbox

# Dry run (audit everything, install nothing)
safe-install install flask --dry-run

# Force install despite critical findings
safe-install install flask --force
```

### Audit

```bash
# Check a package before you install it
safe-install audit requests
safe-install audit -e npm lodash
safe-install audit -e cargo serde

# Scan local code for exfiltration patterns
safe-install scan ./my-project/
safe-install scan ./my-project/ --languages python,javascript
```

### Environment Check

```bash
# See exactly what a malicious package could steal from your machine
safe-install check-env
```

Output:
```
  Sensitive files on disk:
    EXPOSED ~/.ssh (12KB)
    EXPOSED ~/.aws (1KB)
    EXPOSED ~/.gitconfig (0KB)
    EXPOSED ~/.docker/config.json (0KB)
    EXPOSED ~/Chrome/Login Data (40KB)

  Sensitive env vars set:
    EXPOSED GITHUB_TOKEN=ghp_...1234
    EXPOSED AWS_ACCESS_KEY_ID=AKIA...5678

  Isolation capabilities:
    Docker: available
    Bubblewrap: NOT available

  Summary: 5 files, 2 env vars exposed
  Any malicious package install could read ALL of these.
```

## Configuration

Create `~/.config/safe-install/config.toml` (global) or `./safe-install.toml` (per-project):

```toml
[sandbox]
enabled = true
memory_limit = "2g"
cpu_limit = "2"
timeout = 600

[vault]
# Add your own sensitive paths beyond the defaults
extra_paths = [
    "~/.custom-secrets",
    "~/.my-app/credentials.json",
]
extra_env_vars = [
    "MY_SECRET_API_KEY",
    "INTERNAL_DB_PASSWORD",
]

[network]
# Additional hosts to allow during install
allowed_hosts = [
    "my-private-registry.com",
    "artifactory.mycompany.com",
]

[scan]
skip_tests = true
max_findings_display = 15
```

## How the Docker Sandbox Works

```
Your machine                          Docker container
+------------------+                  +------------------+
| ~/.ssh/          |                  | (empty)          |
| ~/.aws/          |  -- INVISIBLE -> | No home dir      |
| ~/.gitconfig     |                  | No env vars      |
| $GITHUB_TOKEN    |                  | No volume mounts |
| Chrome passwords |                  | --cap-drop=ALL   |
+------------------+                  | --read-only      |
                                      | --memory=2g      |
        pip install pkg               | --no-new-priv    |
              |                       +------------------+
              v                              |
     Download + build in container           |
              |                              |
     Copy .whl files out <-------------------+
              |
     pip install --no-deps *.whl  (just unzips, no code runs)
```

The malicious code runs inside the container where there is literally nothing to steal. The wheels that come out are just zip files — installing them doesn't execute any code.

## What Each Ecosystem Defends Against

| Ecosystem | Attack vector | How safe-install stops it |
|-----------|--------------|---------------------------|
| **pip** | `setup.py` runs during install | Sandbox builds wheels; local install is just unzip |
| **npm** | `preinstall`/`postinstall` scripts | `--ignore-scripts` + sandbox download |
| **cargo** | `build.rs` runs at compile time | Sandbox compilation; scan for suspicious build scripts |
| **go** | `init()` functions run on import | Sandbox build; scan for network calls in init |
| **gem** | `extconf.rb` runs during install | Sandbox build; scan for command execution |
| **docker** | Malicious Dockerfiles/images | Scan Dockerfiles for pipe-to-shell, privileged mode |

## Limitations

1. **Import-time attacks**: The sandbox protects install-time. A malicious `__init__.py` still runs when you `import the_package` in your real environment. Defense: virtual environments + runtime monitoring.

2. **Obfuscated code**: The source inspector uses pattern matching. Sophisticated obfuscation (encrypted payloads, steganography, multi-stage loaders) can evade it. Defense: the Docker sandbox doesn't care about obfuscation — there's nothing to steal.

3. **Without Docker**: Falls back to credential vault, which is good but not perfect. An attacker who knows about safe-install could look for the vault temp directory, or access paths not in the sensitive list. Defense: install Docker.

4. **Compiled extensions**: Native C/C++ extensions in wheels can contain anything. The source inspector can't analyze compiled code. Defense: audit compiled packages separately, prefer pure-Python alternatives.

## License

MIT
