# Contributing to safe-install

Thanks for your interest in improving supply chain security for everyone. This guide covers how to contribute to safe-install.

## Development Setup

```bash
git clone https://github.com/safe-install/safe-install.git
cd safe-install
export PYTHONPATH=src
python -m safe_install --help
```

No dependencies to install -- safe-install has zero runtime dependencies by design.

### Running Tests

```bash
PYTHONPATH=src python -m safe_install scan ./src/
PYTHONPATH=src python -m safe_install audit safe-install
```

## Code Style

- **Zero dependencies.** Do not add any runtime dependencies. The stdlib is all you get.
- **Python 3.9+.** Do not use features unavailable in Python 3.9 (e.g., `match` statements, `X | Y` union types).
- **Follow existing patterns.** Look at the code around what you're changing and match it.
- **No over-engineering.** Prefer simple, readable code over clever abstractions.

## Adding New Defense Patterns

Defense patterns live in `src/safe_install/core.py` (the `SourceInspector` class) and in ecosystem-specific files under `src/safe_install/ecosystems/`.

To add a new detection pattern:

1. Identify the attack technique and find real-world examples.
2. Add the pattern to the appropriate inspector method.
3. Add test payloads under `tests/attack_payloads/` so the scanner can be validated against them.
4. Run the scanner against a corpus of popular legitimate packages to check for false positives.
5. Document the pattern in your PR description with links to advisories or write-ups.

## Adding New Ecosystem Adapters

Ecosystem adapters live in `src/safe_install/ecosystems/`. Each adapter extends `base.py`.

To add a new ecosystem:

1. Create `src/safe_install/ecosystems/<name>_eco.py` following the pattern in existing adapters (e.g., `pip_eco.py`).
2. Implement the required interface from `base.py`.
3. Register the ecosystem in `src/safe_install/ecosystems/__init__.py`.
4. Add relevant source inspection patterns for that ecosystem's build system.
5. Update `README.md` to mention the new ecosystem.

## Pull Request Process

1. Fork the repo and create a branch from `main`.
2. Make your changes with clear, focused commits.
3. Ensure the scanner runs cleanly on itself (`safe-install scan ./src/`).
4. Test on at least one real package from each affected ecosystem.
5. Open a PR with a clear description of what changed and why.
6. Address any review feedback.

PRs should be focused -- one feature, one bug fix, or one pattern per PR. Large PRs are harder to review and more likely to introduce issues.

## Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/safe-install/safe-install/issues/new?template=bug_report.md).
- **Feature requests**: Use the [feature request template](https://github.com/safe-install/safe-install/issues/new?template=feature_request.md).
- **False positives**: Use the [false positive template](https://github.com/safe-install/safe-install/issues/new?template=false_positive.md). These are especially valuable for improving detection accuracy.
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md). Do **not** open a public issue.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
