"""Gap 9: DNS exfiltration defense — restrict DNS in sandbox, detect suspicious queries."""

import math
import os
import re
import string
from .core import c


class DNSDefense:
    REGISTRY_DOMAINS = {
        'pypi.org', 'files.pythonhosted.org', 'upload.pypi.org',
        'registry.npmjs.org', 'crates.io', 'static.crates.io',
        'rubygems.org', 'proxy.golang.org', 'sum.golang.org',
        'github.com', 'gitlab.com', 'raw.githubusercontent.com',
        'objects.githubusercontent.com',
    }

    def __init__(self, config=None):
        self.config = config or {}
        dns_cfg = self.config.get("dns", {})
        self.allowed_domains = set(self.REGISTRY_DOMAINS)
        self.allowed_domains.update(dns_cfg.get("allowed_domains", []))
        self.restrict_in_sandbox = dns_cfg.get("restrict_in_sandbox", True)
        self.suspicious_queries = []

    def get_docker_dns_args(self) -> list:
        """Return Docker CLI args for restricted DNS."""
        if not self.restrict_in_sandbox:
            return []
        return ['--dns', '1.1.1.1', '--dns', '1.0.0.1']

    def is_suspicious_query(self, domain: str) -> tuple:
        """Check if a DNS query looks like data exfiltration.
        Returns (suspicious, reason)."""
        domain = domain.lower().rstrip('.')

        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith('.' + allowed):
                return (False, '')

        if self._check_subdomain_length(domain):
            reason = f"long subdomain label (>30 chars) in {domain}"
            self.suspicious_queries.append({'domain': domain, 'reason': reason})
            return (True, reason)

        pattern_reason = self._check_query_pattern(domain)
        if pattern_reason:
            self.suspicious_queries.append({'domain': domain, 'reason': pattern_reason})
            return (True, pattern_reason)

        labels = domain.split('.')
        for label in labels:
            if len(label) > 6:
                entropy = self._label_entropy(label)
                if entropy > 3.5:
                    reason = f"high entropy label '{label}' ({entropy:.2f} bits) in {domain}"
                    self.suspicious_queries.append({'domain': domain, 'reason': reason})
                    return (True, reason)

        return (False, '')

    def _label_entropy(self, label: str) -> float:
        """Shannon entropy of a DNS label."""
        if not label:
            return 0.0
        length = len(label)
        freq = {}
        for ch in label:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _check_subdomain_length(self, domain: str) -> bool:
        """DNS labels > 30 chars often indicate encoded data."""
        labels = domain.split('.')
        for label in labels:
            if len(label) > 30:
                return True
        return False

    def _check_query_pattern(self, domain: str) -> str:
        """Check for hex-encoded, base32, base64 patterns in labels."""
        labels = domain.split('.')
        for label in labels:
            if len(label) < 8:
                continue
            if re.fullmatch(r'[0-9a-f]+', label) and len(label) >= 16:
                return f"hex-encoded label '{label}' in {domain}"
            if re.fullmatch(r'[A-Z2-7]+=*', label.upper()) and len(label) >= 16:
                return f"base32-encoded label '{label}' in {domain}"
            if re.fullmatch(r'[A-Za-z0-9+/]+=*', label) and len(label) >= 20:
                return f"base64-encoded label '{label}' in {domain}"
        return None

    def analyze_queries(self, queries: list) -> list:
        """Analyze a batch of DNS queries. Returns suspicious ones."""
        results = []
        for q in queries:
            suspicious, reason = self.is_suspicious_query(q)
            if suspicious:
                results.append({'domain': q, 'reason': reason})
        return results

    def report(self) -> bool:
        """Print DNS findings. Returns True if suspicious."""
        if not self.suspicious_queries:
            print(f"  {c('DNS', 'bold')}: {c('no suspicious queries', 'green')}")
            return False
        print(f"  {c('DNS', 'bold')}: {c(f'{len(self.suspicious_queries)} suspicious queries', 'red')}")
        for sq in self.suspicious_queries:
            print(f"    {c('!', 'red')} {sq['domain']}: {sq['reason']}")
        return True
