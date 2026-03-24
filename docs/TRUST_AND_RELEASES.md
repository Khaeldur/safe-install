# Trust and Releases

This document explains how to verify safe-install, what verification mechanisms exist today, and what is planned.

## Canonical Repository

The canonical source for safe-install is:

    https://github.com/Khaeldur/safe-install

All other mirrors, forks, or copies should be verified against this source.

## Install Methods

### pip install (recommended)

```bash
pip install safe-install
```

This installs from PyPI. The package is built and uploaded via GitHub Actions (`publish.yml`) using PyPI trusted publisher (OIDC). No manual credentials are involved in the publish process.

### git clone

```bash
git clone https://github.com/Khaeldur/safe-install.git
cd safe-install
pip install -e .
```

This gives you the exact source from the canonical repo. You can audit before installing.

### curl installer

```bash
curl -sSL https://raw.githubusercontent.com/Khaeldur/safe-install/main/install.sh | bash
```

This script detects your Python version and runs `pip install safe-install`. It does not download or execute any binaries beyond what pip does. Note that piping curl to bash carries inherent supply chain risks; review the script first if this concerns you.

## What Verification Exists Today

### Local hash computation

The `safe-install verify` command and `bootstrap_verify.sh` script compute a SHA256 hash of all `.py` files in the installed package. This hash is deterministic for a given version of the source code.

### Package integrity check

`BootstrapVerifier.check_package_integrity()` checks for:
- Orphan `.pyc` files (compiled without matching source)
- Unexpected file types in the package directory
- Zero-byte source files (potential truncation)

### PyPI trusted publisher

The `publish.yml` workflow uses `pypa/gh-action-pypi-publish` with OIDC (`id-token: write`). This means the PyPI package is published directly from GitHub Actions without stored API tokens.

## What Does NOT Exist Yet

The following verification mechanisms are planned but not yet implemented:

### Release artifacts with SHA256SUMS

The `bootstrap_verify.sh` script attempts to fetch `SHA256SUMS` from GitHub releases, but no releases with this artifact have been published yet. The script gracefully falls back to displaying the local hash for manual comparison.

### Code signing

There is no GPG or Sigstore signing of releases, commits, or packages.

### Reproducible builds

Builds are not reproducible. The same source may produce different package artifacts depending on the build environment. This means you cannot independently verify that a PyPI package matches the GitHub source by rebuilding.

### Sigstore attestations

PyPI supports Sigstore attestations for packages published via trusted publishers. This is not yet configured.

### SBOM (Software Bill of Materials)

No SBOM is generated or published with releases.

## Current Trust Limitations

1. **You trust GitHub**: The source lives on GitHub. If GitHub or the maintainer's GitHub account is compromised, the source and releases could be tampered with.

2. **You trust PyPI**: The package is installed from PyPI. PyPI's infrastructure and the trusted publisher OIDC flow are the trust boundary.

3. **No independent verification path**: Without reproducible builds or signed releases, there is no way to independently verify that the PyPI package matches the GitHub source beyond manual comparison.

4. **Single maintainer**: The project currently has a small number of maintainers. Key person risk applies.

## Planned Improvements

In rough priority order:

1. Publish GitHub releases with SHA256SUMS artifacts
2. Enable Sigstore attestations on PyPI publishes
3. Add GPG signing to releases
4. Investigate reproducible builds
5. Generate and publish SBOM
6. Multi-maintainer release approval

## How to Verify Manually

Until automated verification is established:

```bash
# 1. Install the package
pip install safe-install

# 2. Find where it's installed
python3 -c "import safe_install; print(safe_install.__file__)"

# 3. Clone the repo
git clone https://github.com/Khaeldur/safe-install.git /tmp/safe-install-verify

# 4. Compare the source
diff -r /tmp/safe-install-verify/src/safe_install/ $(python3 -c "from pathlib import Path; import safe_install; print(Path(safe_install.__file__).parent)")

# 5. Or use the built-in verify command (computes local hash)
safe-install verify
```
