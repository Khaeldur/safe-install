# Architecture

## Design Principles

1. **Zero dependencies** — A security tool that depends on packages is a supply chain attack waiting to happen. safe-install uses only Python stdlib.

2. **Defense in depth** — Six layers, each independent. If one fails, others still protect you.

3. **Fail closed** — Critical findings abort the install by default. You must explicitly --force to override.

4. **Universal** — Same defense model across pip, npm, cargo, go, gem, and Docker. The attack pattern is identical; only the package manager details differ.

## System Overview

```
User runs: safe-install install flask
                    |
                    v
            +---------------+
            |   CLI Router  |  Detects ecosystem, loads config
            +---------------+
                    |
                    v
            +---------------+
            | Ecosystem     |  pip_eco / npm_eco / cargo_eco / ...
            | Adapter       |  Knows how to resolve, download, install
            +---------------+
                    |
    +---------------+---------------+
    |               |               |
    v               v               v
+--------+   +-----------+   +----------+
| Dep    |   | Source    |   | Binary   |
| Tree   |   | Inspector |   | Check    |
| Audit  |   | (Layer 5) |   | (Layer 2)|
+--------+   +-----------+   +----------+
                    |
                    v
    Docker available? ----YES----> Docker Sandbox (Layer 1)
         |                              |
         NO                       Download + build in container
         |                              |
         v                        Copy wheels/artifacts out
    Credential Vault (Layer 4)          |
         |                              v
         v                        Local install (--no-deps)
    Direct install                      |
         |                              |
         +----------+------------------+
                    |
                    v
            +---------------+
            | Network       |  Runs throughout install
            | Monitor       |  (Layer 6)
            | (background)  |
            +---------------+
                    |
                    v
            +---------------+
            | Final Report  |
            +---------------+
```

## Layer Details

### Layer 1: Docker Sandbox

**Goal**: Complete OS-level isolation. Malicious code physically cannot reach your credentials.

**How it works**:
```
docker run --rm \
  --memory=2g --memory-swap=2g \     # Prevent RAM bomb (litellm attack)
  --cpus=2 \                          # Prevent CPU DoS
  --cap-drop=ALL \                    # No Linux capabilities
  --read-only \                       # Read-only root filesystem
  --tmpfs /tmp:rw,noexec,nosuid \    # Temp space (no execute)
  --tmpfs /install:rw,noexec,nosuid \ # Install space (no execute)
  --security-opt=no-new-privileges \  # Cannot escalate
  --dns 1.1.1.1 \                    # Restricted DNS
  python:3.12-slim \
  pip download + pip wheel            # Download and build inside
```

**No volume mounts** = no access to host filesystem.
**No env vars** = no access to credentials.
**Memory limit** = prevents the exact RAM bomb that revealed the litellm attack.

After building, only `.whl` files are copied out via `docker cp`.
Local install with `pip install --no-deps *.whl` just unzips — zero code execution.

**Why it's flawless**: The container is an empty sandbox. Even if the malicious code is perfectly obfuscated and undetectable, there's nothing for it to steal.

### Layer 2: Binary-Only Mode

**Goal**: Eliminate code execution during install entirely.

**How it works**:
- pip: `--only-binary :all:` (wheels only, no setup.py)
- npm: `--ignore-scripts` (no pre/postinstall hooks)
- cargo: Build in sandbox (build.rs runs there, not locally)

**Trade-off**: Some packages don't publish pre-built binaries. With binary-only mode, those packages can't be installed without the sandbox.

### Layer 3: Hash Lockfile

**Goal**: Detect any tampering between when you vet a package and when you install it.

**How it works**:
```
# Generate lockfile (one-time, after auditing)
safe-install lock requirements.txt

# Output: requirements.lock
flask==3.0.0 --hash=sha256:abc123...
werkzeug==3.0.1 --hash=sha256:def456...

# Future installs verify hashes
safe-install install -r requirements.lock
```

SHA256 is computationally infeasible to forge. If a package is modified (even one byte), the hash changes and install aborts.

### Layer 4: Credential Vault

**Goal**: Remove credentials from the filesystem during install. Fallback when Docker is unavailable.

**How it works**:
1. Enumerate all known sensitive paths (~/.ssh, ~/.aws, ~/.kube, etc.)
2. Move them to a temp directory with restrictive permissions
3. Clear all known sensitive env vars
4. Run pip install
5. Restore everything

**Limitations**:
- Race condition: attacker could detect the move and look for the vault
- Incomplete coverage: can't anticipate every possible credential location
- Browser credential stores may not be movable while browser is running
- `/proc/self/environ` on Linux still shows cleared env vars until process restarts

### Layer 5: Source Inspection

**Goal**: Detect known exfiltration patterns in package source code.

**Pattern categories**:
| Pattern | Risk | Example |
|---------|------|---------|
| HTTP requests in setup files | Critical | `urllib.request.urlopen()` in setup.py |
| Environment variable access in setup files | Critical | `os.environ` in setup.py |
| Sensitive file access | Critical | `open(expanduser('~/.ssh/id_rsa'))` |
| Command execution in setup files | High | `subprocess.run()` in setup.py |
| Dynamic code execution | High | `exec()`, `eval()` in setup.py |
| Base64 encoding | Medium | Potential obfuscation |
| Socket creation | Medium | Raw network access |

**Language support**:
- Python: setup.py, __init__.py, conftest.py patterns
- JavaScript: preinstall.js, postinstall.js, index.js patterns
- Rust: build.rs patterns
- Go: main.go, init() patterns
- Ruby: extconf.rb, Rakefile patterns

**Limitations**: Pattern matching is inherently bypassable. Obfuscation defeats it. This layer is a speed bump, not a wall.

### Layer 6: Network Monitor

**Goal**: Detect unexpected outbound connections during install.

**How it works**:
1. Snapshot current connections (baseline)
2. Poll every 1 second during install
3. Alert on any new connection to hosts not in the allowlist

**Allowlist** (configurable):
- PyPI / npmjs / crates.io / rubygems.org / golang proxy
- GitHub / GitLab
- Private registries (user-configured)

**Limitations**: 1-second polling interval means very fast exfiltration could slip through. DNS-based exfiltration may not be caught. Tunneling through allowed hosts (e.g., GitHub API) would not trigger an alert.

## Ecosystem Adapters

Each ecosystem adapter implements:

```python
class BaseEcosystem:
    def resolve_deps(package)           # Resolve full dependency tree
    def sandbox_install_script(package)  # Shell script for Docker
    def local_install(artifact_dir)      # Install pre-built artifacts
    def check_binary_available(package)  # Check if binary exists
    def download_source(package, dir)    # Download source for inspection
```

| Ecosystem | Docker Image | Install Script Behavior | Local Install |
|-----------|-------------|------------------------|---------------|
| pip | python:3.x-slim | pip download + pip wheel | pip install --no-deps *.whl |
| npm | node:20-slim | npm pack | npm install --ignore-scripts *.tgz |
| cargo | rust:slim | cargo fetch | Copy to local registry cache |
| go | golang:1.22-alpine | go mod download | Copy to module cache |
| gem | ruby:3.2-slim | gem fetch | gem install --local *.gem |
| docker | docker:cli | docker pull + save | docker load |

## Configuration

```
Priority (highest first):
1. CLI flags (--no-sandbox, --binary-only, --force)
2. Project config: ./safe-install.toml
3. User config: ~/.config/safe-install/config.toml
4. Built-in defaults
```

Config uses TOML format. Parsed with `tomllib` (Python 3.11+) or a minimal fallback parser for older versions.

## File Structure

```
safe-install/
  pyproject.toml              # Package metadata + entry points
  README.md                   # User-facing docs
  docs/
    ARCHITECTURE.md           # This file
    THREAT_MODEL.md           # Attack vectors and defenses
  src/safe_install/
    __init__.py
    cli.py                    # CLI entry points and command routing
    config.py                 # Config loading, sensitive paths/vars lists
    core.py                   # Shared defense layers (sandbox, vault, monitor, inspector)
    ecosystems/
      __init__.py             # Registry of all ecosystems
      base.py                 # Abstract base class for ecosystem adapters
      pip_eco.py              # Python/pip adapter
      npm_eco.py              # Node/npm adapter
      cargo_eco.py            # Rust/cargo adapter
      go_eco.py               # Go modules adapter
      gem_eco.py              # Ruby/gem adapter
      docker_eco.py           # Docker image adapter
```
