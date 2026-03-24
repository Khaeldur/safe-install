# Validation Plan

This document describes what testing exists today, what testing is needed, and what claims the project is allowed to make at each maturity level.

## Current Test Coverage Assessment

### What exists

The CI pipeline (`.github/workflows/ci.yml`) runs two tests across a matrix of 3 OS x 6 Python versions:

1. **`safe-install scan ./src/`**: Runs the source inspector against safe-install's own source code. This verifies the scanner loads and produces output without crashing. It does NOT verify detection accuracy.

2. **`safe-install audit safe-install --dry-run`**: Runs the audit flow (typosquat check, dep resolution, source inspection) against the `safe-install` package itself in dry-run mode. This verifies the audit pipeline does not crash. It does NOT verify that any findings are correct.

The `tests/` directory contains:
- `test_detection.py`: Exists but scope and coverage are unknown.
- `test_full_suite.py`: Exists but scope and coverage are unknown.
- `attack_payloads/`: Directory exists, contents unknown.

### What this means

Current CI is a **smoke test**. It verifies that the tool runs without errors on multiple platforms and Python versions. It does NOT validate:
- Detection accuracy (true positive rate)
- False positive rate
- Sandbox escape resistance
- Vault bypass resistance
- Correct behavior under adversarial conditions
- Ecosystem adapter functionality with real packages

### Honest assessment

| Test Category | Status | Notes |
|--------------|--------|-------|
| Unit tests for core logic | Unknown | test_detection.py exists but is not run in CI |
| Integration tests (real packages) | Missing | No tests install real packages through the full pipeline |
| Adversarial detection tests | Missing | No tests with known-malicious payloads |
| False positive tests | Missing | No tests against corpus of legitimate packages |
| Sandbox escape tests | Missing | No tests attempting to escape Docker isolation |
| Vault bypass tests | Missing | No tests attempting to access credentials during vault lock |
| Ecosystem adapter tests | Missing | No tests verifying each adapter works with real packages |
| Cross-platform tests | Smoke only | CI runs on 3 OSes but only tests scan/audit |
| Performance tests | Missing | No tests for timeout behavior, large dependency trees |

## Adversarial Test Corpus Plan

### Phase 1: Known attack patterns (immediate)

Create test fixtures under `tests/attack_payloads/` for each language:

**Python**:
- Direct exfiltration in setup.py (urllib, requests, socket)
- Base64-obfuscated exfiltration
- Environment variable access + HTTP send
- File read of ~/.ssh/id_rsa + network exfil
- Dynamic import + exec patterns
- Byte array code execution
- Time-delayed payload in __init__.py

**JavaScript**:
- child_process.exec in preinstall.js
- fs.readFile + https.request in postinstall.js
- process.env exfiltration
- eval/Function-based payload

**Rust**:
- std::process::Command in build.rs
- std::net::TcpStream in build.rs
- std::env::var exfiltration in build.rs

**Go**:
- exec.Command in main.go init()
- net.Dial in init()
- os.Getenv exfiltration

**Ruby**:
- system() in extconf.rb
- Net::HTTP in Rakefile
- ENV access + exfiltration

### Phase 2: Obfuscation variants (short-term)

For each Phase 1 payload, create obfuscated versions:
- Base64 encoding
- Character code arrays
- String concatenation to build function names
- importlib.import_module with encoded module names
- Multi-file payloads (benign setup.py imports malicious helper)
- Conditional execution (only on specific OS or hostname)

### Phase 3: Real-world reproductions (medium-term)

Reproduce (sanitized) versions of real attacks:
- litellm-style setup.py credential theft
- event-stream-style targeted postinstall
- rustdecimal-style build.rs exfiltration
- ua-parser-js-style cryptominer install script

### Phase 4: Sandbox testing (medium-term)

- Attempt to access host filesystem from within sandbox container
- Attempt to read host environment variables from within sandbox
- Attempt DNS exfiltration from within sandbox
- Attempt to escape container (known CVEs for specific Docker versions)
- Attempt to exhaust resources beyond limits

## False Positive / False Negative Tracking

### Proposed structure

Create `tests/accuracy/` with:

```
tests/accuracy/
  false_positives/      # Legitimate packages that trigger findings
    requests.txt        # e.g., "setup.py uses urllib - expected"
    flask.txt
  false_negatives/      # Known malicious patterns not detected
    base64_obfuscated.py
    byte_array_exec.py
  tracking.json         # Running counts
```

### Metrics to track

| Metric | Definition | Target |
|--------|-----------|--------|
| True Positive Rate | % of known-malicious payloads detected | Track, do not claim |
| False Positive Rate | % of legitimate packages incorrectly flagged | < 5% for top-1000 packages |
| Detection latency | Time from pattern added to detection functional | Continuous |
| Bypass rate | % of obfuscated variants that evade detection | Track, do not claim |

Do NOT publish these as accuracy percentages in user-facing docs until the corpus is large enough and the methodology is documented.

## Claims Ladder

### Level 0: Prototype (current state)

**What exists**: Working code with smoke tests. No adversarial validation.

**Allowed claims**:
- "Reduces install-time credential exposure via Docker isolation"
- "Scans source for common exfiltration patterns (heuristic, not comprehensive)"
- "Experimental / alpha / prototype"
- "Docker sandbox provides strong (not absolute) install-time isolation"

**NOT allowed**:
- Any percentages (95%, 90%, etc.)
- "Flawless", "stops", "prevents", "guarantees"
- "Production-ready"
- "Comprehensive" or "complete" protection

### Level 1: Alpha with tests

**Requirements to reach this level**:
- Phase 1 adversarial corpus created and passing
- False positive testing against top-100 pip packages
- Ecosystem adapter smoke tests with real packages (pip, npm at minimum)
- All tests running in CI

**Additional claims allowed**:
- "Tested against [N] known attack patterns"
- "False positive rate below [X]% against top-100 pip packages"
- Specific detection capabilities listed (e.g., "detects unobfuscated exfiltration in setup.py")

### Level 2: Beta

**Requirements to reach this level**:
- Phase 2 obfuscation corpus tested
- Phase 3 real-world reproductions tested
- Sandbox escape testing completed
- Vault bypass testing completed
- pip and npm adapters validated against 50+ real packages
- cargo adapter functional with real crates
- False positive rate documented and below 5%

**Additional claims allowed**:
- "Beta" status
- Detection rates for specific attack categories (with methodology reference)
- "Docker sandbox tested against [specific escape vectors]"
- Ecosystem-specific maturity claims with evidence

### Level 3: Validated Beta

**Requirements to reach this level**:
- External security audit completed
- Phase 4 sandbox testing completed
- All ecosystem adapters validated
- Performance benchmarks established
- Documented false negative analysis

**Additional claims allowed**:
- "Externally audited"
- Qualified detection percentages with methodology links
- Comparison against other tools (with reproducible benchmarks)

### Level 4: Production-Ready

**Requirements to reach this level**:
- Multiple external audits
- Reproducible builds
- Signed releases
- Formal threat model review
- Incident response plan
- 12+ months of community usage without critical bypasses

**Additional claims allowed**:
- "Production-ready"
- Quantified security claims with confidence intervals

## CI Gating Policy

### Current (Level 0)

- Smoke tests must pass (scan self, audit self)
- No test failures allowed

### Target (Level 1)

- All Phase 1 adversarial tests must pass
- False positive rate against top-100 must be below threshold
- Real-package ecosystem tests must pass for pip and npm
- Coverage metrics reported (not gated)

### Target (Level 2)

- All Phase 2 obfuscation tests must pass
- No regression in detection rates
- All ecosystem adapter tests must pass
- Performance benchmarks must not regress more than 10%

### Policy

- README claims must not exceed the current level's allowed claims
- CI should enforce claim-level consistency (e.g., fail if README contains "flawless" while at Level 0)
- Version bumps require updating the claims ladder assessment
