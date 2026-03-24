"""Gap 3: Compiled binary analysis - detect native extensions, extract strings, check entropy."""

import math
import os
import re
import struct
from .core import c


class BinaryAnalyzer:
    NATIVE_EXTENSIONS = {'.so', '.dll', '.pyd', '.dylib'}
    SUSPICIOUS_STRINGS = [
        r'https?://[^\s"\']+',
        r'/\.ssh/', r'/\.aws/', r'/\.kube/', r'/\.gnupg/',
        r'password', r'passwd', r'credential', r'token', r'secret',
        r'exfil', r'beacon', r'c2server', r'backdoor',
        r'AKIA[0-9A-Z]{16}',
        r'ghp_[a-zA-Z0-9]{36}',
    ]
    KNOWN_NATIVE = {
        'numpy', 'pandas', 'scipy', 'pillow', 'cryptography', 'lxml',
        'psycopg2', 'grpcio', 'pyarrow', 'regex', 'pyyaml', 'markupsafe',
        'msgpack', 'ujson', 'orjson', 'multidict', 'yarl', 'frozenlist',
        'aiohttp', 'greenlet', 'cffi', 'bcrypt', 'pynacl',
    }

    def __init__(self, config=None):
        self.config = config or {}
        self.findings = []
        cfg = self.config.get("binary_analysis", {})
        self.entropy_threshold = cfg.get("entropy_threshold", 7.5)
        known = cfg.get("known_native_packages", [])
        self.known_native = self.KNOWN_NATIVE | set(known)

    def scan_directory(self, directory: str) -> list:
        """Find and analyze all native extensions."""
        self.findings = []
        binaries = self._detect_native_extensions(directory)
        for abspath, relpath in binaries:
            self.findings.extend(self.analyze_binary(abspath, relpath))
        return self.findings

    def analyze_binary(self, filepath: str, relpath: str) -> list:
        """Analyze a single binary. Returns findings."""
        findings = []
        expected = self._is_expected_native(relpath)

        if not expected:
            findings.append({
                'severity': 'WARNING',
                'type': 'unexpected_native',
                'file': relpath,
                'detail': 'Native extension from unexpected package',
            })

        entropy = self._calculate_entropy(filepath)
        if entropy > self.entropy_threshold:
            findings.append({
                'severity': 'WARNING',
                'type': 'high_entropy',
                'file': relpath,
                'detail': f'High entropy: {entropy:.2f} (threshold {self.entropy_threshold})',
            })

        strings = self._extract_strings(filepath)
        findings.extend(self._scan_strings(strings, relpath))

        return findings

    def _detect_native_extensions(self, directory: str) -> list:
        """Return list of (abspath, relpath) for native extensions."""
        results = []
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.NATIVE_EXTENSIONS:
                    abspath = os.path.join(root, fname)
                    relpath = os.path.relpath(abspath, directory)
                    results.append((abspath, relpath))
        return results

    def _extract_strings(self, filepath: str, min_length: int = 4) -> list:
        """Extract printable ASCII strings from binary. Pure Python."""
        strings = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except (OSError, IOError):
            return strings

        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_length:
            strings.append(''.join(current))
        return strings

    def _scan_strings(self, strings: list, relpath: str) -> list:
        """Check extracted strings against suspicious patterns."""
        findings = []
        compiled = [(p, re.compile(p, re.IGNORECASE)) for p in self.SUSPICIOUS_STRINGS]
        seen = set()
        for s in strings:
            for pattern_str, pattern_re in compiled:
                if pattern_re.search(s):
                    key = (relpath, pattern_str)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            'severity': 'WARNING',
                            'type': 'suspicious_string',
                            'file': relpath,
                            'detail': f'Pattern [{pattern_str}] matched: {s[:80]}',
                        })
        return findings

    def _calculate_entropy(self, filepath: str, block_size: int = 256) -> float:
        """Shannon entropy of file. >7.5 = likely encrypted/compressed."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except (OSError, IOError):
            return 0.0

        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_expected_native(self, relpath: str) -> bool:
        """Check if this native extension belongs to a known package."""
        parts = relpath.replace('\\', '/').lower().split('/')
        for part in parts:
            normalized = part.replace('-', '_').replace('.', '_')
            for known in self.known_native:
                if known in normalized:
                    return True
        return False

    def report(self) -> bool:
        """Print findings. Returns True if CRITICAL."""
        if not self.findings:
            print(c("  [binary] No suspicious native extensions found.", "green"))
            return False

        has_critical = False
        for f in self.findings:
            sev = f['severity']
            if sev == 'CRITICAL':
                has_critical = True
                color = 'red'
            elif sev == 'WARNING':
                color = 'yellow'
            else:
                color = 'dim'
            print(c(f"  [binary] {sev}: {f['type']} in {f['file']}", color))
            print(c(f"           {f['detail']}", 'dim'))
        return has_critical
