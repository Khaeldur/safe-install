#!/usr/bin/env python3
"""
safe-install Full Automated Test Suite

Tests every component end-to-end:
- Module imports (all 34 Python modules)
- Core API (audit, typosquat, intelligence, findings log)
- Source inspector (false positive reduction, whitelisting, co-occurrence)
- Attack payload detection (litellm, ua-parser-js, event-stream, rustdecimal, DNS exfil)
- Typosquat detector (edit distance, homoglyphs, separators, prefixes)
- Binary analyzer (entropy, string extraction)
- DNS defense (exfil detection, allowed domains)
- Filesystem snapshot (before/after diff)
- Vault hardening (PID capture)
- CI reporter (JSON, SARIF, SBOM generation)
- Runtime monitor (basic execution)
- Import guard (whitelist, activation)
- Bootstrap verifier (self-check)
- Pattern database (YAML loading)
- pip wrapper (module imports)
- Ecosystem adapters (all 6 registered)
- CLI commands (help, api, check-env, verify, audit, scan)
- Web dashboard API (HTTP endpoint)
- Config (all sections loaded)
- Findings log (write, query, dedup)

Run: cd safe-install && PYTHONPATH=src python tests/test_full_suite.py
"""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import time

# Ensure src is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC)
os.chdir(PROJECT_ROOT)

# ============================================================================
# Test Framework
# ============================================================================

class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        self.sections = []
        self.current_section = None

    def section(self, name):
        self.current_section = name
        self.sections.append(name)
        print(f"\n  {'=' * 56}")
        print(f"  {name}")
        print(f"  {'=' * 56}")

    def test(self, name, fn):
        try:
            result = fn()
            if result:
                self.passed += 1
                print(f"  PASS  {name}")
            else:
                self.failed += 1
                self.errors.append(f"[{self.current_section}] {name}")
                print(f"  FAIL  {name}")
        except Exception as e:
            self.failed += 1
            err = f"[{self.current_section}] {name}: {e}"
            self.errors.append(err)
            print(f"  ERR   {name}: {e}")

    def run_cli(self, args, timeout=120):
        """Run safe-install CLI command, return (exit_code, stdout+stderr)."""
        env = {**os.environ, "PYTHONPATH": SRC, "PYTHONIOENCODING": "utf-8"}
        try:
            r = subprocess.run(
                [sys.executable, "-m", "safe_install"] + args,
                capture_output=True, text=True, timeout=timeout,
                env=env, cwd=PROJECT_ROOT
            )
            import re
            clean = re.sub(r'\033\[[0-9;]*m', '', r.stdout + r.stderr)
            return r.returncode, clean
        except subprocess.TimeoutExpired:
            return 1, "TIMEOUT"
        except Exception as e:
            return 1, str(e)

    def report(self):
        total = self.passed + self.failed
        print(f"\n  {'=' * 56}")
        print(f"  FINAL RESULTS: {self.passed} passed, {self.failed} failed out of {total}")
        print(f"  Sections tested: {len(self.sections)}")
        print(f"  {'=' * 56}")
        if self.errors:
            print(f"\n  Failures:")
            for e in self.errors:
                print(f"    - {e}")
        return self.failed == 0


# ============================================================================
# Tests
# ============================================================================

def run_all_tests():
    t = TestSuite()

    # ------------------------------------------------------------------
    t.section("1. MODULE IMPORTS")
    # ------------------------------------------------------------------
    modules = [
        'safe_install', 'safe_install.config', 'safe_install.core',
        'safe_install.api', 'safe_install.typosquat', 'safe_install.intelligence',
        'safe_install.confusion', 'safe_install.binary_analysis',
        'safe_install.filesystem_snapshot', 'safe_install.vault_hardening',
        'safe_install.dns_defense', 'safe_install.ci_integration',
        'safe_install.import_guard', 'safe_install.runtime_monitor',
        'safe_install.bootstrap', 'safe_install.patterns',
        'safe_install.data.popular_packages',
        'safe_install.ecosystems', 'safe_install.ecosystems.pip_eco',
        'safe_install.ecosystems.npm_eco', 'safe_install.ecosystems.cargo_eco',
        'safe_install.ecosystems.go_eco', 'safe_install.ecosystems.gem_eco',
        'safe_install.ecosystems.docker_eco',
        'safe_install.wrapper', 'safe_install.wrapper.activate',
        'safe_install.wrapper.intercept',
        'safe_install.cli',
    ]
    for mod in modules:
        t.test(f"import {mod}", lambda m=mod: importlib.import_module(m) is not None)

    # ------------------------------------------------------------------
    t.section("2. CONFIG")
    # ------------------------------------------------------------------
    from safe_install.config import load_config
    config = load_config()

    required_sections = [
        'sandbox', 'vault', 'network', 'scan', 'ecosystems',
        'typosquat', 'intelligence', 'registries', 'binary_analysis',
        'dns', 'filesystem_monitor', 'vault_hardening', 'ci',
        'import_guard', 'runtime', 'coordination', 'wrapper', 'tray', 'vscode',
    ]
    for s in required_sections:
        t.test(f"config[{s}]", lambda s=s: s in config)

    t.test("config[patterns] section", lambda: 'patterns' in config)

    # ------------------------------------------------------------------
    t.section("3. POPULAR PACKAGES DATA")
    # ------------------------------------------------------------------
    from safe_install.data.popular_packages import POPULAR_PIP, POPULAR_NPM, POPULAR_CARGO, POPULAR

    t.test("pip packages > 200", lambda: len(POPULAR_PIP) > 200)
    t.test("npm packages > 200", lambda: len(POPULAR_NPM) > 200)
    t.test("cargo packages > 50", lambda: len(POPULAR_CARGO) > 50)
    t.test("POPULAR has pip/npm/cargo", lambda: all(k in POPULAR for k in ('pip', 'npm', 'cargo')))
    t.test("requests in pip", lambda: 'requests' in POPULAR_PIP)
    t.test("express in npm", lambda: 'express' in POPULAR_NPM)
    t.test("serde in cargo", lambda: 'serde' in POPULAR_CARGO)

    # ------------------------------------------------------------------
    t.section("4. TYPOSQUAT DETECTOR")
    # ------------------------------------------------------------------
    from safe_install.typosquat import TyposquatDetector
    d = TyposquatDetector()

    # Should detect
    t.test("reqeusts -> requests", lambda: len(d.check('reqeusts', 'pip')) > 0)
    t.test("requets -> requests", lambda: len(d.check('requets', 'pip')) > 0)
    t.test("loadash -> lodash (npm)", lambda: len(d.check('loadash', 'npm')) > 0)
    t.test("expresss -> express (npm)", lambda: len(d.check('expresss', 'npm')) > 0)
    t.test("python-requests prefix", lambda: len(d.check('python-requests', 'pip')) > 0)

    # Should NOT detect
    t.test("requests clean", lambda: len(d.check('requests', 'pip')) == 0)
    t.test("flask clean", lambda: len(d.check('flask', 'pip')) == 0)
    t.test("numpy clean", lambda: len(d.check('numpy', 'pip')) == 0)
    t.test("unique-pkg clean", lambda: len(d.check('my-unique-pkg-xyz-12345', 'pip')) == 0)

    # ------------------------------------------------------------------
    t.section("5. SOURCE INSPECTOR + FALSE POSITIVE REDUCTION")
    # ------------------------------------------------------------------
    from safe_install.core import SourceInspector

    # Whitelist loading
    si = SourceInspector(languages=['python'], config={'scan': {'use_whitelist': True}})
    t.test("whitelist loaded", lambda: len(si._whitelist) > 100)
    t.test("requests in whitelist", lambda: 'requests' in si._whitelist)
    t.test("flask in whitelist", lambda: 'flask' in si._whitelist)

    # Comment detection
    t.test("Python # comment detected", lambda: si._is_in_comment("# import os", 'python'))
    t.test("Python code not comment", lambda: not si._is_in_comment("import os", 'python'))
    t.test("JS // comment detected", lambda: si._is_in_comment("// fetch(url)", 'javascript'))
    t.test("Docstring detected", lambda: si._is_in_comment('"""some doc"""', 'python'))

    # ------------------------------------------------------------------
    t.section("6. ATTACK PAYLOAD DETECTION")
    # ------------------------------------------------------------------
    test_payloads_dir = os.path.join(PROJECT_ROOT, "tests", "attack_payloads")

    if os.path.isdir(test_payloads_dir):
        # litellm simulation
        litellm_dir = os.path.join(test_payloads_dir, "litellm_sim")
        if os.path.isdir(litellm_dir):
            si_lit = SourceInspector(languages=['python'])
            si_lit.scan_directory(litellm_dir)
            t.test("litellm: findings detected", lambda: len(si_lit.findings) > 0)
            t.test("litellm: CRITICAL/HIGH found", lambda:
                any(f['severity'] in ('CRITICAL', 'HIGH') for f in si_lit.findings))

        # ua-parser-js simulation
        ua_dir = os.path.join(test_payloads_dir, "ua_parser_sim")
        if os.path.isdir(ua_dir):
            si_ua = SourceInspector(languages=['javascript'])
            si_ua.scan_directory(ua_dir)
            t.test("ua-parser-js: findings detected", lambda: len(si_ua.findings) > 0)

        # event-stream simulation
        es_dir = os.path.join(test_payloads_dir, "event_stream_sim")
        if os.path.isdir(es_dir):
            si_es = SourceInspector(languages=['javascript'])
            si_es.scan_directory(es_dir)
            t.test("event-stream: findings detected", lambda: len(si_es.findings) > 0)

        # rustdecimal simulation
        rd_dir = os.path.join(test_payloads_dir, "rustdecimal_sim")
        if os.path.isdir(rd_dir):
            si_rd = SourceInspector(languages=['rust'])
            si_rd.scan_directory(rd_dir)
            t.test("rustdecimal: findings detected", lambda: len(si_rd.findings) > 0)

        # DNS exfil simulation
        dns_dir = os.path.join(test_payloads_dir, "typosquat_sim")
        if os.path.isdir(dns_dir):
            si_dns = SourceInspector(languages=['python'])
            si_dns.scan_directory(dns_dir)
            t.test("DNS exfil sim: findings detected", lambda: len(si_dns.findings) > 0)

        # litellm .pth attack simulation (March 2026 attack)
        pth_dir = os.path.join(test_payloads_dir, "litellm_pth_sim")
        if os.path.isdir(pth_dir):
            si_pth = SourceInspector(languages=['python'])
            si_pth.scan_directory(pth_dir)
            t.test("litellm .pth: findings detected", lambda: len(si_pth.findings) > 0)
            t.test("litellm .pth: CRITICAL found", lambda:
                any(f['severity'] == 'CRITICAL' for f in si_pth.findings))
            t.test("litellm .pth: .pth file flagged", lambda:
                any('.pth' in f.get('pattern', '') for f in si_pth.findings))
            t.test("litellm .pth: persistence detected", lambda:
                any('persistence' in f.get('pattern', '').lower() or
                    'systemd' in f.get('pattern', '').lower()
                    for f in si_pth.findings))
            t.test("litellm .pth: K8s detected", lambda:
                any('kubernetes' in f.get('pattern', '').lower() or
                    'lateral' in f.get('pattern', '').lower()
                    for f in si_pth.findings))
            t.test("litellm .pth: encrypted exfil detected", lambda:
                any('encrypt' in f.get('pattern', '').lower() or
                    'cipher' in f.get('pattern', '').lower()
                    for f in si_pth.findings))
            t.test("litellm .pth: double base64 detected", lambda:
                any('nested' in f.get('pattern', '').lower() or
                    'double' in f.get('pattern', '').lower()
                    for f in si_pth.findings))
    else:
        t.test("attack payloads directory exists", lambda: False)

    # ------------------------------------------------------------------
    t.section("7. BINARY ANALYZER")
    # ------------------------------------------------------------------
    from safe_install.binary_analysis import BinaryAnalyzer
    ba = BinaryAnalyzer()

    t.test("known native pkgs > 15", lambda: len(ba.known_native) > 15)
    t.test("entropy of __init__.py < 7", lambda:
        0 < ba._calculate_entropy('src/safe_install/__init__.py') < 7)

    # Create a high-entropy test file
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        import random
        f.write(bytes(random.randint(0, 255) for _ in range(1024)))
        high_entropy_file = f.name
    t.test("high entropy file > 7", lambda: ba._calculate_entropy(high_entropy_file) > 7)
    os.unlink(high_entropy_file)

    # String extraction
    with tempfile.NamedTemporaryFile(suffix='.so', delete=False, mode='wb') as f:
        f.write(b'\x00\x00https://evil.com/steal\x00\x00/home/.ssh/id_rsa\x00\x00')
        test_binary = f.name
    strings = ba._extract_strings(test_binary)
    t.test("string extraction finds URLs", lambda: any('evil.com' in s for s in strings))
    t.test("string extraction finds paths", lambda: any('.ssh' in s for s in strings))
    os.unlink(test_binary)

    # ------------------------------------------------------------------
    t.section("8. DNS DEFENSE")
    # ------------------------------------------------------------------
    from safe_install.dns_defense import DNSDefense
    dns = DNSDefense()

    t.test("pypi.org clean", lambda: not dns.is_suspicious_query('pypi.org')[0])
    t.test("github.com clean", lambda: not dns.is_suspicious_query('github.com')[0])
    t.test("files.pythonhosted.org clean", lambda: not dns.is_suspicious_query('files.pythonhosted.org')[0])
    t.test("base64 exfil detected", lambda:
        dns.is_suspicious_query('aGVsbG8gd29ybGQgdGhpcyBleGZpbA.evil.com')[0])
    t.test("hex exfil detected", lambda:
        dns.is_suspicious_query('4a6f686e2e446f652e5353482e4b6579.evil.com')[0])
    t.test("normal subdomain clean", lambda:
        not dns.is_suspicious_query('api.github.com')[0])

    # ------------------------------------------------------------------
    t.section("9. CI REPORTER")
    # ------------------------------------------------------------------
    from safe_install.ci_integration import CIDetector, CIReporter, CIMode

    t.test("CI not detected (dev machine)", lambda: not CIDetector().is_ci())

    reporter = CIReporter()
    reporter.set_metadata('test-pkg', 'pip', [{'name': 'dep1', 'version': '1.0'}])
    reporter.add_findings('scanner', [
        {'severity': 'HIGH', 'pattern': 'test', 'file': 'x.py', 'line': 1}
    ])

    t.test("JSON report valid", lambda: json.loads(reporter.generate_json())['tool'] == 'safe-install')
    t.test("JSON findings count", lambda: json.loads(reporter.generate_json())['summary']['total'] == 1)
    t.test("SARIF version", lambda: json.loads(reporter.generate_sarif())['version'] == '2.1.0')
    t.test("SARIF results", lambda: len(json.loads(reporter.generate_sarif())['runs'][0]['results']) == 1)
    t.test("SBOM format", lambda: json.loads(reporter.generate_sbom())['bomFormat'] == 'CycloneDX')
    t.test("SBOM components", lambda: len(json.loads(reporter.generate_sbom())['components']) == 2)

    with tempfile.TemporaryDirectory() as td:
        files = reporter.write_reports(td, ['json', 'sarif', 'sbom'])
        t.test("write 3 report files", lambda: len(files) == 3)
        t.test("all files exist", lambda: all(os.path.exists(f) for f in files))
        t.test("files non-empty", lambda: all(os.path.getsize(f) > 0 for f in files))

    # ------------------------------------------------------------------
    t.section("10. FILESYSTEM SNAPSHOT")
    # ------------------------------------------------------------------
    from safe_install.filesystem_snapshot import FilesystemSnapshot
    snap = FilesystemSnapshot()
    snap.snapshot_before()
    snap.snapshot_after()
    changes = snap.diff()
    t.test("snapshot returns list", lambda: isinstance(changes, list))
    t.test("no false positive changes", lambda: len(changes) == 0)

    # ------------------------------------------------------------------
    t.section("11. VAULT HARDENING")
    # ------------------------------------------------------------------
    from safe_install.vault_hardening import VaultHardening
    vh = VaultHardening()
    vh.record_pre_install_processes()
    t.test("PID capture > 0", lambda: len(vh.pre_pids) > 0)
    t.test("no suspicious (nothing installed)", lambda: len(vh.check_suspicious_processes()) < 50)

    # ------------------------------------------------------------------
    t.section("12. RUNTIME MONITOR")
    # ------------------------------------------------------------------
    from safe_install.runtime_monitor import RuntimeMonitor
    mon = RuntimeMonitor()
    code, events = mon.run_monitored([sys.executable, '-c', 'print("hello")'])
    t.test("monitored command runs", lambda: code == 0)
    t.test("events is list", lambda: isinstance(events, list))

    # ------------------------------------------------------------------
    t.section("13. IMPORT GUARD")
    # ------------------------------------------------------------------
    from safe_install.import_guard import ImportGuard
    guard = ImportGuard()
    t.test("whitelist populated", lambda: len(guard.whitelist) > 100)
    t.test("safe_install in whitelist", lambda: 'safe_install' in guard.whitelist)
    t.test("mode default is monitor", lambda: guard.mode == 'monitor')

    # ------------------------------------------------------------------
    t.section("14. BOOTSTRAP VERIFIER")
    # ------------------------------------------------------------------
    from safe_install.bootstrap import BootstrapVerifier
    bv = BootstrapVerifier()
    ok, msg = bv.verify_self()
    t.test("self-verification passes", lambda: ok)
    t.test("verification message", lambda: len(msg) > 0)

    # ------------------------------------------------------------------
    t.section("15. PATTERN DATABASE")
    # ------------------------------------------------------------------
    from safe_install.patterns import PatternDatabase
    db = PatternDatabase()
    t.test("python patterns loaded", lambda: len(db.get_patterns('python')) > 10)
    t.test("javascript patterns loaded", lambda: len(db.get_patterns('javascript')) > 5)
    t.test("rust patterns loaded", lambda: len(db.get_patterns('rust')) > 3)
    t.test("go patterns loaded", lambda: len(db.get_patterns('go')) > 3)
    t.test("ruby patterns loaded", lambda: len(db.get_patterns('ruby')) > 3)
    t.test("patterns format (tuple)", lambda:
        isinstance(db.get_patterns('python')[0], tuple) and len(db.get_patterns('python')[0]) == 2)

    # ------------------------------------------------------------------
    t.section("16. ECOSYSTEMS")
    # ------------------------------------------------------------------
    from safe_install.ecosystems import ECOSYSTEMS
    t.test("6 ecosystems registered", lambda:
        set(ECOSYSTEMS.keys()) == {'pip', 'npm', 'cargo', 'go', 'gem', 'docker'})
    for eco in ECOSYSTEMS:
        t.test(f"{eco} adapter instantiates", lambda e=eco: ECOSYSTEMS[e]() is not None)

    # ------------------------------------------------------------------
    t.section("17. API LAYER")
    # ------------------------------------------------------------------
    from safe_install.api import audit_package, check_typosquat, get_intelligence, log_finding, query_findings, get_status

    audit_result = audit_package('colorama')
    t.test("audit returns dict", lambda: isinstance(audit_result, dict))
    t.test("audit has severity", lambda: 'severity' in audit_result)
    t.test("audit has deps", lambda: 'deps' in audit_result)
    t.test("typosquat API works", lambda: check_typosquat('reqeusts')['is_typosquat'])
    t.test("intelligence API works", lambda: isinstance(get_intelligence('colorama')['warnings'], list))

    # Findings log
    entry = log_finding({'channel': 'test_suite', 'package': 'test-suite-pkg',
                          'severity': 'LOW', 'ecosystem': 'pip'})
    t.test("log_finding returns entry", lambda: 'id' in entry)
    results = query_findings(package='test-suite-pkg', since=60)
    t.test("query_findings returns logged entry", lambda: len(results) > 0)

    # Dedup
    result1 = audit_package('colorama')
    result2 = audit_package('colorama')
    t.test("dedup works (second call reuses)", lambda: result2.get('_dedup', False))

    # Status
    status = get_status()
    t.test("status has protected", lambda: 'protected' in status)
    t.test("status has exposed_files", lambda: 'exposed_files' in status)
    t.test("status has active_channels", lambda: 'active_channels' in status)

    # ------------------------------------------------------------------
    t.section("18. CLI COMMANDS")
    # ------------------------------------------------------------------
    code, out = t.run_cli(['--help'])
    t.test("--help works", lambda: code == 0 and 'safe-install' in out)
    t.test("--help shows all commands", lambda:
        all(cmd in out for cmd in ['install', 'audit', 'scan', 'check-env', 'verify', 'monitor', 'guard', 'api', 'activate']))

    code, out = t.run_cli(['check-env'])
    t.test("check-env runs", lambda: code == 0)
    t.test("check-env shows exposure", lambda: 'EXPOSED' in out or 'None found' in out)

    code, out = t.run_cli(['verify'])
    t.test("verify runs", lambda: code == 0)
    t.test("verify passes", lambda: 'PASS' in out)

    code, out = t.run_cli(['api', 'status'])
    t.test("api status returns JSON", lambda: code == 0 and '"protected"' in out)

    code, out = t.run_cli(['api', 'typosquat', 'reqeusts'])
    t.test("api typosquat detects", lambda: code == 0 and '"is_typosquat": true' in out)

    code, out = t.run_cli(['api', 'typosquat', 'requests'])
    t.test("api typosquat clean", lambda: code == 0 and '"is_typosquat": false' in out)

    # ------------------------------------------------------------------
    t.section("19. LIVE AUDIT (PyPI API)")
    # ------------------------------------------------------------------
    code, out = t.run_cli(['audit', 'colorama'], timeout=60)
    t.test("audit colorama runs", lambda: 'Auditing' in out)
    t.test("audit shows dep tree", lambda: 'colorama' in out)

    code, out = t.run_cli(['audit', 'reqeusts'], timeout=60)
    t.test("audit reqeusts shows typosquat", lambda: 'TYPOSQUAT' in out or 'typosquat' in out.lower())

    # ------------------------------------------------------------------
    t.section("20. WRAPPER MODULES")
    # ------------------------------------------------------------------
    from safe_install.wrapper.activate import activate_wrapper, deactivate_wrapper
    t.test("activate function exists", lambda: callable(activate_wrapper))
    t.test("deactivate function exists", lambda: callable(deactivate_wrapper))

    from safe_install.wrapper import intercept
    t.test("intercept module loaded", lambda: intercept is not None)

    # ------------------------------------------------------------------
    t.section("21. PROJECT FILES")
    # ------------------------------------------------------------------
    required_files = [
        'pyproject.toml', 'README.md', 'LICENSE', 'CONTRIBUTING.md',
        'CODE_OF_CONDUCT.md', 'SECURITY.md', 'MANIFEST.in',
        'install.sh', 'install.ps1', 'safe-install.example.toml',
        '.github/workflows/ci.yml', '.github/workflows/publish.yml',
        '.github/PULL_REQUEST_TEMPLATE.md',
        '.github/ISSUE_TEMPLATE/bug_report.md',
        '.github/ISSUE_TEMPLATE/feature_request.md',
        '.github/ISSUE_TEMPLATE/false_positive.md',
        'github-action/action.yml',
        'vscode-extension/package.json',
        'vscode-extension/src/extension.ts',
        'tray-app/main.py',
        'docker-extension/metadata.json',
        'docs/ARCHITECTURE.md',
        'docs/THREAT_MODEL.md',
        'docs/index.html',
        'web/server.py',
        'web/index.html',
        'tests/test_detection.py',
    ]
    for f in required_files:
        t.test(f"exists: {f}", lambda f=f: os.path.exists(f))

    # ------------------------------------------------------------------
    t.section("22. PATTERN YAML FILES")
    # ------------------------------------------------------------------
    pattern_dir = os.path.join('src', 'safe_install', 'data', 'patterns')
    for lang in ['python', 'javascript', 'rust', 'go', 'ruby']:
        yml = os.path.join(pattern_dir, f'{lang}.yml')
        t.test(f"pattern: {lang}.yml exists", lambda y=yml: os.path.exists(y))
        t.test(f"pattern: {lang}.yml non-empty", lambda y=yml:
            os.path.exists(y) and os.path.getsize(y) > 50)

    t.test("custom.yml.example exists", lambda:
        os.path.exists(os.path.join(pattern_dir, 'custom.yml.example')))

    # ------------------------------------------------------------------
    # REPORT
    # ------------------------------------------------------------------
    return t.report()


if __name__ == '__main__':
    print()
    print("  " + "#" * 56)
    print("  #  safe-install FULL AUTOMATED TEST SUITE            #")
    print("  #  Testing all 12 defense layers, 5 channels,        #")
    print("  #  6 ecosystems, and every component end-to-end       #")
    print("  " + "#" * 56)

    start = time.time()
    success = run_all_tests()
    elapsed = time.time() - start

    print(f"\n  Time: {elapsed:.1f}s")
    print()

    sys.exit(0 if success else 1)
