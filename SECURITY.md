# Security Policy

## Reporting Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Please report security vulnerabilities by emailing **security@safe-install.dev**.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, but we aim for critical issues within 2 weeks

## Disclosure

We follow coordinated disclosure. We'll work with you on a timeline for public disclosure after a fix is available.

## Scope

The following are in scope:
- Bypasses of any defense layer (sandbox escape, vault bypass, inspection evasion)
- False negatives where a known malicious pattern is not detected
- Vulnerabilities in the tool itself (code execution, path traversal, etc.)

## A Note on Irony

Yes, we're aware of the irony that a supply chain defense tool could itself be a target. That's why safe-install has zero dependencies, supports single-file deployment, and we encourage you to audit the source. If you find something, we want to know.
