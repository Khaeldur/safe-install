# Threat Model

This document describes the threats that safe-install addresses, the mechanisms it uses, and the limitations of each mechanism. It is written to be precise rather than persuasive.

## Scope

safe-install focuses on **install-time** threats in package manager ecosystems. Specifically, it targets the window of time between when you run an install command and when the package is available for import/use.

safe-install does NOT claim to provide comprehensive protection against all supply chain attacks. It reduces exposure in one phase (install-time) and provides heuristic detection in others.

## Attack Surface: Package Installation

When you run `pip install X`:

1. pip resolves the dependency tree (X + all transitive deps)
2. For each package, pip downloads from PyPI
3. If the package is a source distribution (sdist), pip runs `setup.py` or the PEP 517 build backend
4. The build script runs with **full user permissions**

Step 3 is the critical attack window. The build script can read any file, access any environment variable, open network connections, and execute arbitrary commands as your user. This applies identically across ecosystems: npm has preinstall/postinstall scripts, cargo has build.rs, gem has extconf.rb.

## What safe-install Reduces

### Install-time credential exposure (Docker sandbox)

**Mechanism**: Package download and build happen inside a Docker container with:
- No volume mounts (no access to host filesystem)
- No environment variables from the host
- `--cap-drop=ALL` (no Linux capabilities)
- `--read-only` root filesystem
- `--security-opt=no-new-privileges`
- Memory and CPU limits
- Restricted DNS (`--dns 1.1.1.1`)

**What this achieves**: Malicious code in setup.py/postinstall/build.rs executes inside the container where there is nothing to steal. SSH keys, cloud credentials, API tokens, browser data, and environment variables are not accessible.

**Residual risks**:
- Container escape exploits (mitigated by capability dropping, but not impossible)
- DNS-based data exfiltration from within the container (the container can make DNS queries)
- Network-based exfiltration to arbitrary hosts (the container has network access for package downloads)
- Resource exhaustion despite limits (the container can still consume its allocated memory/CPU)
- Side-channel attacks (timing, cache-based) are not addressed

**Confidence**: High. This is the strongest defense layer. It does not depend on detecting malicious behavior.

### Install-time credential exposure (Credential vault fallback)

**Mechanism**: When Docker is unavailable, safe-install temporarily moves sensitive files (SSH keys, cloud configs, etc.) to a temporary directory and clears sensitive environment variables. After install, everything is restored.

**What this achieves**: Reduces the set of credentials accessible to malicious build scripts.

**Residual risks**:
- The vault temp directory is discoverable by an attacker who knows about safe-install
- `/proc/self/environ` on Linux still shows the parent process environment
- Not all credential locations are known; custom or application-specific credentials may be missed
- Browser credential stores may not be movable while the browser is running
- Race conditions between vault lock/unlock and malicious code execution
- An attacker who detects the vault mechanism could wait for unlock

**Confidence**: Moderate. This is a meaningful speed bump, not a wall.

## What safe-install Detects Heuristically

### Suspicious source patterns

**Mechanism**: Regex-based pattern matching across package source code, with elevated severity for high-risk files (setup.py, postinstall.js, build.rs).

**What this detects**: Direct, unobfuscated use of HTTP libraries, subprocess execution, environment variable access, sensitive file reads, base64 encoding, socket creation, and dynamic code execution in build/install scripts.

**What this misses**:
- Any form of obfuscation (base64-wrapped code, byte arrays, encrypted payloads)
- Multi-stage loaders where the initial payload is benign
- Compiled native code with embedded malicious behavior
- Legitimate packages that use these patterns (false positives, mitigated by co-occurrence analysis and whitelisting)

**Confidence**: Low to moderate. Useful as an early warning system. Not reliable as a primary defense.

### Typosquatting

**Mechanism**: Edit-distance comparison of the requested package name against a list of popular packages.

**What this detects**: Simple misspellings and character substitutions (e.g., `reqeusts` vs `requests`).

**What this misses**:
- Homoglyph attacks (visually similar Unicode characters) despite config claiming support
- Packages with legitimately similar names
- Novel typosquats against packages not in the popular list
- Name confusion across ecosystems

**Confidence**: Moderate for common cases. The accuracy claim has not been validated against an adversarial corpus.

### Package metadata anomalies

**Mechanism**: Queries PyPI/npm registry APIs for package age, maintainer history, download counts, and recent version changes.

**What this detects**: Very new packages, recent maintainer changes, packages with suspiciously low download counts.

**What this misses**:
- Compromised packages with long legitimate histories (the litellm case)
- Attacks via legitimate maintainer accounts
- Sophisticated social engineering where attackers build trust over time

**Confidence**: Low to moderate. Useful as one signal among many.

## What Remains Possible Despite safe-install

These threats are NOT addressed or only partially addressed:

### Import-time code execution

When you `import pkg` in your real environment, the package's `__init__.py` and all imported modules execute with full user permissions. The Docker sandbox protects install-time only.

The `safe-install guard` command provides an experimental import hook for interactive Python sessions, but this does not protect production code.

### Native extensions in wheels

Pre-built wheels (`.whl`) can contain compiled shared libraries (`.so`, `.dll`) that execute arbitrary code when loaded. Source inspection cannot analyze compiled code. Binary analysis is a stub.

### Time-delayed payloads

Malicious code can wait (hours, days) before activating. A clean install-time scan says nothing about future behavior.

### Build tool compromise

If pip, npm, or cargo themselves are compromised, safe-install (which invokes these tools) cannot detect the compromise.

### Registry infrastructure attacks

If PyPI or npm registry infrastructure is compromised at the server level, packages could be silently replaced. Hash verification helps only if you have a trusted prior hash.

### Dependency confusion / namespace attacks

safe-install has a `DependencyConfusionDetector` module but it is not deeply integrated. It checks for packages that might be internal names registered on public registries, but this requires knowing your internal package names.

## Threat Matrix

| Attack Vector | Docker Sandbox | Vault | Source Scan | Network Monitor | Typosquat |
|--------------|:-:|:-:|:-:|:-:|:-:|
| Credential theft in setup.py | **Blocked** | **Reduced** | Detected* | Detected* | - |
| Credential theft in __init__.py | - | - | Detected* | - | - |
| Dependency confusion | - | - | - | - | - |
| Typosquatting | - | - | - | - | **Detected** |
| Compromised maintainer | **Blocked** (install-time) | **Reduced** | Maybe | Detected* | - |
| Cryptominer in install | **Blocked** (resource limited) | - | Detected* | Detected* | - |
| RAM/CPU bomb | **Limited** | - | - | - | - |
| DNS exfiltration | Partial | - | - | - | - |
| Time-delayed payload | - | - | - | - | - |
| Native code in wheel | **Blocked** (install-time only) | **Reduced** | - | Detected* | - |

`*` Detection is heuristic and bypassable. "Detected" means "may be detected in non-obfuscated cases."

`**Blocked**` at install-time means the malicious code runs in the sandbox where it cannot access host resources. It does NOT mean the package is safe to import afterward.

## Recommendations

1. **Use Docker**: It is the only defense layer that does not depend on pattern matching or behavioral detection.
2. **Prefer binary-only installs** for pip (`--binary-only`): wheels do not execute setup.py.
3. **Use virtual environments**: Limit the blast radius of import-time attacks.
4. **Minimize dependencies**: Fewer deps = smaller attack surface.
5. **Pin exact versions with hashes**: Prevents silent upgrades to compromised versions.
6. **Audit before install**: `safe-install audit pkg --deep` before `safe-install install pkg`.
7. **Monitor for credential leaks**: Rotate keys if any install seems suspicious.
8. **Do not rely solely on safe-install**: It is one layer in your security posture, not a complete solution.
