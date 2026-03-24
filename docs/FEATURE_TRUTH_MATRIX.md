# Feature Truth Matrix

Last updated: 2026-03-25

This document classifies every major claim and subsystem in safe-install against what the code actually does. The goal is brutal honesty so that contributors and users can make informed decisions.

## Status Legend

| Status | Meaning |
|--------|---------|
| **WORKING** | Code exists, executes the claimed behavior, has been exercised |
| **PARTIAL** | Code exists but is incomplete, untested against adversarial inputs, or limited in scope |
| **STUB** | Code exists but does not meaningfully deliver the claimed functionality |
| **MISLEADING** | The claim significantly overstates what the code does |
| **MISSING** | No code exists for the claimed feature |

## Risk Legend

| Risk | Meaning |
|------|---------|
| **LOW** | Cosmetic or minor gap, no security implication |
| **MEDIUM** | Users may over-rely on a feature that under-delivers |
| **HIGH** | Users may believe they are protected when they are not |
| **CRITICAL** | Active misrepresentation of security capability |

---

## Core Thesis

| Claim | Evidence | Status | Risk | Remediation |
|-------|----------|--------|------|-------------|
| Docker-first install isolation | `DockerSandbox` in `core.py` runs `docker run` with `--cap-drop=ALL`, `--read-only`, memory limits, no volume mounts. `download_and_copy()` extracts artifacts via `docker cp`. | **WORKING** | LOW | Strongest layer. Accurately described. Needs adversarial testing (container escape, network exfil from within sandbox). |
| "This tool stops that" (README headline) | Nothing "stops" supply chain attacks completely. Docker isolation reduces install-time exposure. Source inspection is heuristic. Import-time attacks are unaddressed. | **MISLEADING** | **CRITICAL** | Rewrite to "reduces install-time exposure" or "adds friction and visibility". Remove absolute language. |
| "Flawless" (Docker layer description) | Docker sandbox is strong but not flawless. Container escapes exist (rare with `--cap-drop=ALL`). DNS exfil from within container is possible. Network is not fully blocked. | **MISLEADING** | **HIGH** | Replace "Flawless" with "Strong" or "High confidence". Acknowledge residual risks. |
| "Zero Dependencies" | True. Only stdlib is used at runtime. `pystray` and `Pillow` are optional for tray. | **WORKING** | LOW | Accurate. |

---

## Ecosystem Adapters

| Ecosystem | Claim | Evidence | Status | Risk | Remediation |
|-----------|-------|----------|--------|------|-------------|
| **pip** | Full sandboxed install + source inspection | `pip_eco.py` (119 lines): resolve via `pip install --dry-run --report`, download source via `pip download`, sandbox script builds wheels in Docker, local install via `pip install --no-deps`. Source patterns for Python are comprehensive. | **WORKING** | LOW | Best-supported ecosystem. Needs adversarial test corpus. |
| **npm** | Full sandboxed install + source inspection | `npm_eco.py` (94 lines): resolve via `npm view`, sandbox downloads via `npm pack`, local install with `--ignore-scripts`. JS patterns exist. | **WORKING** | LOW | Meaningful protection. `--ignore-scripts` is the key defense. Dep resolution is shallow (direct deps only via `npm view dependencies`). |
| **cargo** | Sandboxed install + source inspection | `cargo_eco.py` (76 lines): resolve is a stub (`cargo search` returns only the package itself, not transitive deps). Sandbox script uses `cargo fetch` into registry cache. `download_source` calls `cargo download` which is not a standard cargo subcommand. `local_install` just prints a message. | **PARTIAL** | **HIGH** | Dep resolution is non-functional. `cargo download` does not exist as a standard command. Local install is a no-op. Sandbox script is plausible but untested. Must label as experimental. |
| **go** | Sandboxed install + source inspection | `go_eco.py` (65 lines): resolve via `go list -m -json`, sandbox via `go mod download`. Local install just prints a message. Go patterns exist but are minimal. | **PARTIAL** | **MEDIUM** | Dep resolution gets top-level module only. Local install is a no-op. Sandbox script is plausible. Label as experimental. |
| **gem** | Sandboxed install + source inspection | `gem_eco.py` (84 lines): resolve via `gem dependency --remote`, sandbox via `gem fetch`, local install via `gem install --local`. Ruby patterns exist. | **PARTIAL** | **MEDIUM** | Dep resolution gets direct deps only (no transitive). Local `gem install --local` still runs `extconf.rb` for native gems. Label as experimental. |
| **docker** | Image scanning + Dockerfile analysis | `docker_eco.py` (100 lines): resolve via `docker manifest inspect`, sandbox via `docker pull + save`, local via `docker load`. `scan_dockerfile()` exists but is never called in the install flow. | **PARTIAL** | **MEDIUM** | Dockerfile scanning is implemented but not wired into any flow. Docker image "sandboxing" doesn't make sense (you're running Docker inside Docker). Label as experimental. |

---

## Security Layers

| Layer | README Claim | Evidence | Status | Risk | Remediation |
|-------|-------------|----------|--------|------|-------------|
| **1. Docker Sandbox** | "Flawless" | `DockerSandbox` class: real Docker isolation with proper security flags. Well-implemented. | **WORKING** | **MEDIUM** | Drop "Flawless". Say "Strong isolation" with caveats (DNS exfil, container escapes are theoretically possible). |
| **2. Binary-only mode** | "Flawless (install-time)" | pip: `--only-binary :all:` flag passed. npm: `--ignore-scripts`. Cargo: N/A (always source). | **WORKING** (pip/npm) | LOW | Accurate for pip. Clarify npm is script-suppression, not binary-only. |
| **3. Hash lockfile** | "Flawless (tampering)" | `HashVerifier` class exists (40 lines). Verifies files against a lockfile. No `lock` CLI command exists to generate lockfiles. | **PARTIAL** | **MEDIUM** | Verification works if you have a lockfile. But there is no way to generate one. The `safe-install lock` command referenced in ARCHITECTURE.md does not exist. |
| **4. Typosquat detection** | "~95%" | `typosquat.py` (124 lines): edit-distance comparison against popular package names. Has a bundled popular packages list. | **PARTIAL** | **MEDIUM** | Implementation exists but "~95%" is unvalidated. No false-positive/negative testing. No homoglyph detection despite config claiming it. Remove percentage claim. |
| **5. Package intelligence** | "~90%" | `intelligence.py` (357 lines): queries PyPI/npm JSON APIs for age, maintainer info, download counts. Checks for recent maintainer changes, young packages, low downloads. | **PARTIAL** | **MEDIUM** | Real implementation that queries registries. "~90%" is unvalidated. No known-malicious list integration. No Sigstore verification despite config claiming it. Remove percentage. |
| **6. Source inspection** | "~70%" | `SourceInspector` in `core.py` (~250 lines): regex patterns for Python, JS, Rust, Go, Ruby. Comment filtering, co-occurrence weighting, high-risk file prioritization. | **WORKING** | **MEDIUM** | Real and useful heuristic scanner. "~70%" is made up. Trivially bypassable by obfuscation. State as "heuristic, not comprehensive". |
| **7. Credential vault** | "~95%" | `CredentialVault` class: moves sensitive files to temp dir, clears env vars, restores after install. | **WORKING** | **MEDIUM** | Real implementation. "~95%" is fabricated. Known bypasses: vault temp dir is discoverable, `/proc/self/environ` on Linux, incomplete path coverage. Remove percentage. |
| **8. Filesystem snapshot** | "~85%" | `filesystem_snapshot.py` (216 lines): before/after snapshot of watched directories. | **PARTIAL** | **MEDIUM** | Implementation exists but only monitors configured paths. "~85%" is unvalidated. No adversarial testing. |
| **9. Vault hardening** | "~90%" | `vault_hardening.py` (118 lines): tracks processes before/after install, checks for suspicious new processes. | **STUB** | **HIGH** | Despite the name "vault hardening", this is a process-monitoring stub. No encryption, no decoy files, no tamper detection as README claims. The name and description are misleading. |
| **10. DNS defense** | "~80%" | `dns_defense.py` (117 lines): appears to monitor DNS queries during install. | **PARTIAL** | **MEDIUM** | Implementation exists but DNS monitoring via userspace is inherently incomplete. Not integrated into the main install flow. |
| **11. Import guard** | "~75%" | `import_guard.py` (117 lines): Python import hook that intercepts module loads. | **PARTIAL** | **MEDIUM** | Real implementation but only works in an interactive Python shell started by `safe-install guard`. Does not protect normal `import` statements in user code. |
| **12. Runtime monitor** | "~60%" | `runtime_monitor.py` (111 lines): uses strace/dtrace to monitor process behavior. | **STUB** | **HIGH** | Basic framework exists. Requires strace/dtrace (not available on all platforms). No meaningful analysis of captured events. Very early prototype. |
| **Network monitor** | "Runs throughout install" | `NetworkMonitor` class: background thread polling `ss`/`netstat` every 1s, reverse-DNS lookup, allowlist check. | **WORKING** | LOW | Real implementation. 1s polling interval means fast exfil can slip through. Correctly described as limited. |

---

## CLI Commands

| Command | Evidence | Status | Risk |
|---------|----------|--------|------|
| `safe-install install <pkg>` | Full 8-step flow in `base.py`. Exercises sandbox, vault, source scan, network monitor. | **WORKING** | LOW |
| `safe-install audit <pkg>` | Downloads source, runs typosquat + inspector + intelligence. | **WORKING** | LOW |
| `safe-install scan <path>` | Scans local directory with SourceInspector. | **WORKING** | LOW |
| `safe-install check-env` | Lists exposed files and env vars. | **WORKING** | LOW |
| `safe-install verify` | Calls `BootstrapVerifier`. Points to non-existent release artifacts. | **PARTIAL** | **MEDIUM** |
| `safe-install monitor` | Calls `RuntimeMonitor`. Requires strace. | **STUB** | **MEDIUM** |
| `safe-install guard` | Starts interactive Python shell with import hook. | **PARTIAL** | LOW |
| `safe-install api <cmd>` | JSON API for programmatic access. | **WORKING** | LOW |
| `safe-install activate` | Installs shell shims for pip/npm wrapping. | **PARTIAL** | LOW |
| `safe-install lock` | Referenced in ARCHITECTURE.md. | **MISSING** | **MEDIUM** |

---

## Distribution Channels

| Channel | Claim | Evidence | Status | Risk | Remediation |
|---------|-------|----------|--------|------|-------------|
| **PyPI** | `pip install safe-install` | `pyproject.toml` configured. Entry points defined. Package structure correct. | **WORKING** | LOW | Needs actual PyPI publication. |
| **GitHub Action** | `uses: safe-install/safe-install-action@v1` | `github-action/action.yml` exists with scripts. References wrong repo org. | **PARTIAL** | **MEDIUM** | Fix repo reference. Action scripts exist but are untested in real CI. |
| **VS Code extension** | "Install from VS Code Marketplace" | No VS Code extension code exists in repo. Config in `config.py` has `vscode` section. | **MISSING** | **HIGH** | Remove claim or clearly label as planned. |
| **System tray app** | `pip install safe-install[tray]` | Optional dependency on `pystray`+`Pillow`. No tray app code found in repo. Config has `tray` section. | **MISSING** | **HIGH** | Remove claim or clearly label as planned. |
| **Docker Desktop extension** | "Install from Docker Hub" | No Docker Desktop extension code exists. | **MISSING** | **HIGH** | Remove claim entirely. |

---

## Bootstrap and Release Verification

| Feature | Evidence | Status | Risk | Remediation |
|---------|----------|--------|------|-------------|
| `bootstrap_verify.sh` | Fetches SHA256SUMS from GitHub releases. Points to wrong org (`safe-install/safe-install`). No releases exist. | **MISLEADING** | **HIGH** | Script will always fall through to "no published hash" path. Fix URL. Add honest messaging. |
| `bootstrap.py` (Python) | Same as above but in Python. Points to wrong URL. | **MISLEADING** | **HIGH** | Fix URL. Acknowledge no release artifacts exist yet. |
| Release signing | Not mentioned but implied by verification flow | **MISSING** | **MEDIUM** | No code signing, no Sigstore, no reproducible builds. Document this honestly. |
| `install.sh` | Downloads via `pip install safe-install` after detecting Python. | **WORKING** | LOW | Fix repo URLs. |
| `install.ps1` | Same flow for Windows PowerShell. | **WORKING** | LOW | Fix repo URLs. |

---

## Packaging Metadata

| Item | Evidence | Status | Risk | Remediation |
|------|----------|--------|------|-------------|
| `pyproject.toml` URLs | All point to `safe-install/safe-install` (wrong org). | **MISLEADING** | **MEDIUM** | Fix to `Khaeldur/safe-install`. |
| Development Status classifier | Claims "4 - Beta" | **MISLEADING** | **MEDIUM** | Should be "3 - Alpha" given current state. |
| Python 3.14 support claim | Listed in classifiers. Python 3.14 is pre-release. | **PARTIAL** | LOW | Remove until actually tested. |

---

## Summary

### What is genuinely good
- Docker sandbox implementation is real and well-constructed
- pip ecosystem adapter is complete and functional
- npm ecosystem adapter provides meaningful protection
- Source inspector is a useful heuristic scanner across 5 languages
- Credential vault is a real fallback mechanism
- Network monitor provides basic anomaly detection during install
- Zero-dependency architecture is genuine and valuable for a security tool
- CLI flow is well-structured with proper 8-step pipeline

### What needs honest labeling
- cargo/go/gem/docker adapters are experimental at best
- All percentage claims (95%, 90%, 70%, etc.) are fabricated
- "Flawless" is never appropriate for security claims
- Several security layers are stubs or early prototypes
- Hash lockfile verification exists but lockfile generation does not

### What must be removed or clearly marked as planned
- VS Code extension (does not exist)
- System tray app (does not exist)
- Docker Desktop extension (does not exist)
- "This tool stops that" framing
- All unvalidated percentages
