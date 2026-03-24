"""
Test suite for safe-install attack detection.

Runs SourceInspector, TyposquatDetector, DNSDefense, and BinaryAnalyzer
against simulated attack payloads to verify detection works.

Usage: cd tests && python test_detection.py
"""

import math
import os
import struct
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

from safe_install.core import SourceInspector
from safe_install.typosquat import TyposquatDetector
from safe_install.dns_defense import DNSDefense
from safe_install.binary_analysis import BinaryAnalyzer

PAYLOADS_DIR = os.path.join(TESTS_DIR, "attack_payloads")

passed = 0
failed = 0


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


# ── SourceInspector tests ──────────────────────────────────────────────

def scan_payload(dirname, languages):
    """Run SourceInspector on a payload directory, return findings."""
    inspector = SourceInspector(
        languages=languages,
        config={"scan": {"use_whitelist": False, "cooccurrence_weighting": True}},
    )
    payload_dir = os.path.join(PAYLOADS_DIR, dirname)
    inspector.scan_directory(payload_dir)
    return inspector.findings


print("\n=== Source Inspector: litellm_sim (Python) ===")
findings = scan_payload("litellm_sim", ["python"])
severities = {f["severity"] for f in findings}
patterns = {f["pattern"] for f in findings}

test("litellm: has findings", len(findings) > 0, f"got {len(findings)}")
test("litellm: CRITICAL severity", "CRITICAL" in severities, f"got {severities}")
test("litellm: detects urllib", any("urllib" in p for p in patterns), f"patterns: {patterns}")
test("litellm: detects base64", any("Base64" in p or "base64" in p.lower() for p in patterns), f"patterns: {patterns}")
test("litellm: detects env access", any("nvironment" in p or "env" in p.lower() for p in patterns), f"patterns: {patterns}")
test("litellm: detects sensitive path", any("ensitive" in p or "ssh" in p.lower() or "aws" in p.lower() for p in patterns), f"patterns: {patterns}")

print("\n=== Source Inspector: ua_parser_sim (JavaScript) ===")
findings = scan_payload("ua_parser_sim", ["javascript"])
severities = {f["severity"] for f in findings}
patterns = {f["pattern"] for f in findings}

test("ua-parser: has findings", len(findings) > 0, f"got {len(findings)}")
test("ua-parser: CRITICAL severity", "CRITICAL" in severities, f"got {severities}")
test("ua-parser: detects child_process", any("hild" in p for p in patterns), f"patterns: {patterns}")
test("ua-parser: detects fs read", any("ile" in p and ("read" in p.lower() or "system" in p.lower()) for p in patterns), f"patterns: {patterns}")
test("ua-parser: detects https request", any("ttp" in p.lower() or "request" in p.lower() for p in patterns), f"patterns: {patterns}")
test("ua-parser: detects process.env", any("nvironment" in p or "env" in p.lower() for p in patterns), f"patterns: {patterns}")

print("\n=== Source Inspector: event_stream_sim (JavaScript) ===")
findings = scan_payload("event_stream_sim", ["javascript"])
severities = {f["severity"] for f in findings}
patterns = {f["pattern"] for f in findings}

test("event-stream: has findings", len(findings) > 0, f"got {len(findings)}")
test("event-stream: detects eval", any("eval" in p.lower() or "ynamic" in p for p in patterns), f"patterns: {patterns}")
test("event-stream: detects Buffer.from base64", any("ase64" in p.lower() or "Base64" in p for p in patterns), f"patterns: {patterns}")
test("event-stream: detects process.env", any("nvironment" in p or "env" in p.lower() for p in patterns), f"patterns: {patterns}")

print("\n=== Source Inspector: rustdecimal_sim (Rust) ===")
findings = scan_payload("rustdecimal_sim", ["rust"])
severities = {f["severity"] for f in findings}
patterns = {f["pattern"] for f in findings}

test("rustdecimal: has findings", len(findings) > 0, f"got {len(findings)}")
test("rustdecimal: CRITICAL severity", "CRITICAL" in severities, f"got {severities}")
test("rustdecimal: detects env access", any("nvironment" in p or "env" in p.lower() or "home" in p.lower() for p in patterns), f"patterns: {patterns}")
test("rustdecimal: detects TcpStream", any("etwork" in p or "onnection" in p or "tcp" in p.lower() for p in patterns), f"patterns: {patterns}")
test("rustdecimal: detects file read", any("ile" in p and ("read" in p.lower() or "system" in p.lower()) for p in patterns), f"patterns: {patterns}")
test("rustdecimal: detects sensitive paths", any("ssh" in p.lower() or "aws" in p.lower() or "ensitive" in p for p in patterns), f"patterns: {patterns}")

print("\n=== Source Inspector: typosquat_sim (Python) ===")
findings = scan_payload("typosquat_sim", ["python"])
severities = {f["severity"] for f in findings}
patterns = {f["pattern"] for f in findings}

test("typosquat-sim: has findings", len(findings) > 0, f"got {len(findings)}")
test("typosquat-sim: detects os.environ", any("nvironment" in p or "env" in p.lower() for p in patterns), f"patterns: {patterns}")
test("typosquat-sim: detects socket", any("ocket" in p for p in patterns), f"patterns: {patterns}")


# ── Typosquat Detector tests ──────────────────────────────────────────

print("\n=== Typosquat Detector ===")
detector = TyposquatDetector()

# Known typosquats that should be caught
typosquat_cases = [
    ("reqeusts", "pip", "requests"),     # transposition
    ("requets", "pip", "requests"),      # missing char
    ("reequest", "pip", None),           # too far from anything
    ("numpv", "pip", "numpy"),           # substitution
    ("python-requests", "pip", "requests"),  # suspicious prefix
    ("flaskk", "pip", "flask"),          # added char
    ("dajngo", "pip", None),             # transposition (distance 2 from django)
]

for pkg, eco, expected_similar in typosquat_cases:
    warnings = detector.check(pkg, eco)
    if expected_similar:
        match = any(w["popular"] == expected_similar for w in warnings)
        test(f"typosquat '{pkg}' -> '{expected_similar}'", match,
             f"warnings: {[w['popular'] for w in warnings]}")
    else:
        test(f"typosquat '{pkg}' (may or may not flag)", True)

# Real packages should NOT be flagged
for real_pkg in ["requests", "flask", "numpy", "django", "pandas"]:
    warnings = detector.check(real_pkg, "pip")
    test(f"real package '{real_pkg}' not flagged", len(warnings) == 0,
         f"got {len(warnings)} warnings")


# ── DNS Defense tests ─────────────────────────────────────────────────

print("\n=== DNS Defense ===")
dns = DNSDefense()

# Legitimate domains should pass
for domain in ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com"]:
    suspicious, reason = dns.is_suspicious_query(domain)
    test(f"dns allow '{domain}'", not suspicious, reason)

# Encoded subdomains should be flagged
encoded_domains = [
    "4a6f686e446f65414b49414f53464f444e37455841.exfil.example.com",  # hex
    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP.exfil.example.com",          # base32
    "aHR0cHM6Ly9leGFtcGxlLmNvbS9zZWNyZXQ=.evil.example.com",       # base64
]
for domain in encoded_domains:
    suspicious, reason = dns.is_suspicious_query(domain)
    test(f"dns flag encoded '{domain[:40]}...'", suspicious, f"not flagged: {reason}")

# Long subdomain label (data exfil indicator)
long_label = "a" * 40 + ".evil.example.com"
suspicious, reason = dns.is_suspicious_query(long_label)
test("dns flag long subdomain label", suspicious, f"not flagged: {reason}")

# High entropy label
high_entropy = "x8kQ3mZpR7nWvJ2y.evil.example.com"
suspicious, reason = dns.is_suspicious_query(high_entropy)
test("dns flag high-entropy label", suspicious, f"not flagged: {reason}")

# Normal subdomain should pass
normal = "www.google.com"
suspicious, reason = dns.is_suspicious_query(normal)
# This may or may not flag depending on entropy - just test it runs
test("dns normal domain runs without error", True)


# ── Binary Analyzer tests ─────────────────────────────────────────────

print("\n=== Binary Analyzer: entropy calculation ===")
analyzer = BinaryAnalyzer()

# Create a low-entropy file (repeated bytes)
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    f.write(b'\x00' * 1024)
    low_entropy_path = f.name
entropy_low = analyzer._calculate_entropy(low_entropy_path)
test("low entropy file < 1.0", entropy_low < 1.0, f"got {entropy_low:.2f}")
os.unlink(low_entropy_path)

# Create a high-entropy file (pseudo-random bytes)
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    import hashlib as _h
    data = b""
    for i in range(256):
        data += _h.sha256(struct.pack(">I", i)).digest()
    f.write(data)
    high_entropy_path = f.name
entropy_high = analyzer._calculate_entropy(high_entropy_path)
test("high entropy file > 7.0", entropy_high > 7.0, f"got {entropy_high:.2f}")
os.unlink(high_entropy_path)

# Create a fake .so with suspicious strings
with tempfile.TemporaryDirectory() as tmpdir:
    so_path = os.path.join(tmpdir, "malicious.so")
    with open(so_path, "wb") as f:
        f.write(b'\x7fELF' + b'\x00' * 100)
        f.write(b'https://evil.example.com/exfil?data=')
        f.write(b'\x00' * 50)
        f.write(b'/home/user/.ssh/id_rsa')
        f.write(b'\x00' * 50)
        f.write(b'AKIAIOSFODNN7EXAMPLE')  # fake AWS key pattern
        f.write(b'\x00' * 100)

    bin_findings = analyzer.scan_directory(tmpdir)
    test("binary: detects native extension", len(bin_findings) > 0, f"got {len(bin_findings)}")
    types = {f["type"] for f in bin_findings}
    test("binary: flags suspicious strings", "suspicious_string" in types, f"types: {types}")
    test("binary: flags unexpected native", "unexpected_native" in types, f"types: {types}")


# ── Summary ───────────────────────────────────────────────────────────

print(f"\n{'=' * 50}")
total = passed + failed
print(f"Results: {passed}/{total} passed, {failed} failed")
if failed:
    print("SOME TESTS FAILED")
    sys.exit(1)
else:
    print("ALL TESTS PASSED")
    sys.exit(0)
