# safe-install

[![PyPI version](https://badge.fury.io/py/safe-install.svg)](https://pypi.org/project/safe-install/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()

Install-time hardening for package managers. Reduces credential exposure during `pip install`, `npm install`, and other package operations by isolating builds in Docker containers and scanning source for exfiltration patterns.

**Status: Alpha (v0.1.x).** pip and npm ecosystems are the most mature. Cargo, Go, Gem, and Docker adapters are experimental. See the [maturity table](#ecosystem-maturity) below.

## The Problem

Every time you run `pip install` or `npm install`, any package in the dependency tree can execute arbitrary code during the build/install phase. That code runs with your full user permissions and can read SSH keys, cloud credentials, API tokens, browser passwords, and anything else accessible to your account.

This is not theoretical. Real-world attacks exploiting install-time code execution include compromised maintainer accounts, typosquatting campaigns, and dependency confusion attacks across pip, npm, cargo, and gem ecosystems.

### Case Study: LiteLLM Supply Chain Attack (March 2026)

On March 24, 2026, attackers published malicious versions of [litellm](https://pypi.org/project/litellm/) (v1.82.7 and v1.82.8) after compromising PyPI publishing credentials through a poisoned Trivy security scanner in LiteLLM's CI/CD pipeline. The malicious versions were live for approximately three hours — on a package with ~3.4 million daily downloads.

The payload operated in three stages:
1. **Credential harvesting** — collected SSH keys, cloud tokens, and Kubernetes configs
2. **Encrypted exfiltration** — sent stolen data to attacker infrastructure using AES-256 + RSA
3. **Persistence** — deployed systemd services and Kubernetes pods for lateral movement

Because the attacker used legitimate PyPI credentials, hash verification and signature checks would not have caught this. However, safe-install's defenses directly address multiple layers of this attack:

| Defense Layer | Would it help? | Why |
|---|:---:|---|
| **Docker Sandbox** | **Yes** | Credentials, SSH keys, and cloud tokens are invisible inside the container — nothing to steal |
| **Source Inspection** | **Yes** | The payload contained detectable patterns: HTTP exfiltration, env var access, file reads targeting `~/.ssh/` and `~/.aws/` |
| **Credential Vault** | **Yes** | Sensitive files and env vars would have been temporarily hidden during install |
| **`.pth` file detection** | **Yes** | v0.1.1 specifically detects `.pth` file injection, the persistence technique used in v1.82.8 |

The one gap: the `.pth` persistence technique is an **import-time attack** — it executes on every Python startup, not just during install. The Docker sandbox protects install-time only. See [Limitations](#limitations) for more on this boundary.

This incident directly motivated the detection patterns added in safe-install v0.1.1.

## What safe-install Does

safe-install interposes between you and your package manager. Its primary defense is **Docker-based build isolation**: packages are downloaded and built inside a locked-down container with no access to your filesystem, credentials, or environment variables. The resulting artifacts (wheels, tarballs) are copied out and installed locally without executing any code.

When Docker is unavailable, safe-install falls back to a **credential vault** that temporarily hides sensitive files and clears sensitive environment variables during the install.

Additionally, safe-install runs **heuristic source inspection** that scans package source code for patterns commonly associated with exfiltration (HTTP requests in setup.py, environment variable access in build scripts, etc.).

## What This Does NOT Protect You From

- **Import-time attacks**: The sandbox protects install-time only. A malicious `__init__.py` still runs when you `import the_package` in your real environment.
- **Obfuscated payloads**: Source inspection uses pattern matching. Encrypted payloads, steganography, and multi-stage loaders can evade it.
- **Compiled native extensions**: Binary code in wheels (`.so`, `.dll`) can contain anything. Source inspection cannot analyze compiled code.
- **Build tool compromise**: If pip, npm, or cargo themselves are compromised, safe-install cannot help.
- **Registry infrastructure attacks**: If PyPI or npm registry infrastructure is compromised at the server level.
- **Complete protection**: This tool reduces exposure and adds friction to attacks. It is not a guarantee.

## Why Docker-First Matters

The Docker sandbox is the only defense layer that does not depend on detecting malicious behavior. It works by **removing the attack surface entirely**: the container has nothing to steal, regardless of how sophisticated or obfuscated the malicious code is.

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

Docker isolation is strong but not absolute. Theoretical risks include container escapes (mitigated by `--cap-drop=ALL` and `--security-opt=no-new-privileges`), DNS-based exfiltration from within the container, and resource exhaustion despite limits.

## Security Philosophy

- **Reduce exposure**: Minimize what malicious code can access during install.
- **Contain risk**: Isolate builds so that even successful exploitation has limited impact.
- **Add friction and visibility**: Make attacks harder and more detectable, not impossible.
- **Defense in depth**: Multiple independent layers, each with known limitations.
- **Not a guarantee**: No security tool can promise complete protection. safe-install shifts the odds.

## Install

```bash
pip install safe-install
```

### Or via the installer script

```bash
curl -sSL https://raw.githubusercontent.com/Khaeldur/safe-install/main/install.sh | bash
```

Note: piping curl to bash has its own supply chain risks. Consider cloning the repo and reviewing the script first.

## Ecosystem Maturity

| Ecosystem | Dep Resolution | Source Scan | Docker Sandbox | Local Install | Overall |
|-----------|:---:|:---:|:---:|:---:|:---:|
| **pip** | Full tree via `--dry-run --report` | Python patterns (comprehensive) | Builds wheels in container | `pip install --no-deps *.whl` | **Strong** |
| **npm** | Direct deps via `npm view` | JS patterns (comprehensive) | `npm pack` in container | `npm install --ignore-scripts` | **Strong** |
| **cargo** | Top-level only (no transitive) | Rust patterns (basic) | `cargo fetch` in container | Manual (prints instructions) | **Experimental** |
| **go** | Top-level module only | Go patterns (basic) | `go mod download` in container | Manual (prints instructions) | **Experimental** |
| **gem** | Direct deps only | Ruby patterns (basic) | `gem fetch` in container | `gem install --local` (still runs extconf.rb) | **Experimental** |
| **docker** | Image layers only | Dockerfile patterns (not wired in) | N/A (is Docker) | `docker load` | **Experimental** |

"Experimental" means: code exists and may provide some protection, but has not been tested against adversarial inputs, has incomplete dependency resolution, and may have non-functional code paths.

## Threat Model

### What safe-install reduces (install-time)

| Threat | Docker Sandbox | Credential Vault | Source Scan |
|--------|:---:|:---:|:---:|
| Credential theft in setup.py/postinstall | Isolated | Hidden | Detected (if not obfuscated) |
| Cryptominer during build | Isolated (resource-limited) | N/A | Detected (heuristic) |
| RAM/CPU bomb | Limited (--memory, --cpus) | N/A | N/A |
| Environment variable exfiltration | Isolated (no env vars in container) | Cleared | Detected (heuristic) |

### What safe-install detects heuristically

- Typosquatting via edit-distance comparison against popular package names
- Suspicious patterns in build scripts (HTTP requests, env access, file reads)
- Unexpected network connections during install
- Young packages, recent maintainer changes, low download counts

### What remains possible despite safe-install

- Import-time code execution (`__init__.py`, `conftest.py`)
- Compiled native extensions with embedded payloads
- Obfuscated or encrypted malicious code that evades pattern matching
- Time-delayed payloads that activate long after install
- Attacks through the package manager itself

## Defense Layers

| Layer | Method | Confidence | Notes |
|-------|--------|------------|-------|
| Docker Sandbox | OS-level container isolation | High | Primary defense. No host access. |
| Binary-only mode | Wheels only, no setup.py | High (pip) | Some packages lack wheels. |
| Hash lockfile | SHA256 verification | High (when lockfile exists) | Lockfile generation not yet implemented. |
| Typosquat detection | Edit distance + popularity DB | Moderate | Unvalidated accuracy. |
| Package intelligence | Registry metadata analysis | Moderate | Queries real APIs. No malicious-package DB. |
| Source inspection | Regex pattern matching | Low-Moderate | Bypassable via obfuscation. Useful as early warning. |
| Credential vault | Temporarily hide files/env vars | Moderate | Fallback when Docker unavailable. Known bypasses exist. |
| Network monitor | Connection polling during install | Low-Moderate | 1s polling interval. Fast exfil can slip through. |

## Quick Start

```bash
# Check what's exposed on your machine right now
safe-install check-env

# Install a package with full protection
safe-install install requests

# Audit a package without installing
safe-install audit litellm

# Scan a local project for suspicious patterns
safe-install scan ./my-project/
```

## Usage

```bash
# Auto-detects ecosystem from package name
safe-install install requests                    # pip
safe-install install -e npm express              # explicit ecosystem
safe-install install -e cargo serde              # experimental
safe-install install -e go github.com/gin-gonic/gin  # experimental

# Docker sandbox (default if Docker is available)
safe-install install flask

# Binary-only (refuse source distributions)
safe-install install flask --binary-only

# Fallback to credential vault (when Docker unavailable)
safe-install install flask --no-sandbox

# Dry run (audit everything, install nothing)
safe-install install flask --dry-run

# Audit
safe-install audit requests
safe-install audit -e npm lodash
safe-install audit flask --deep  # includes intelligence + binary analysis
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
extra_paths = [
    "~/.custom-secrets",
]
extra_env_vars = [
    "MY_SECRET_API_KEY",
]

[network]
allowed_hosts = [
    "my-private-registry.com",
]
```

## Limitations

1. **Import-time attacks**: The sandbox protects install-time. A malicious `__init__.py` still runs when you `import the_package`. Mitigation: use virtual environments, consider the `safe-install guard` command (experimental).

2. **Obfuscated code**: Source inspection uses pattern matching. Sophisticated obfuscation evades it. The Docker sandbox does not care about obfuscation, but it only protects install-time.

3. **Without Docker**: The credential vault fallback is imperfect. An attacker who knows about safe-install could look for the vault temp directory, or access paths not in the sensitive list.

4. **Compiled extensions**: Native C/C++ extensions in wheels can contain anything. Source inspection cannot analyze compiled code.

5. **Experimental ecosystems**: cargo, go, gem, and docker adapters have incomplete dependency resolution and may have non-functional code paths. Do not rely on them for security-critical workflows.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Policy

See [SECURITY.md](SECURITY.md).

## License

MIT
