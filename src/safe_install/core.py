"""
Core protection layers shared across all ecosystems.

Layer 1: DockerSandbox  — Docker isolation
Layer 2: CredentialVault — hide files/env vars (fallback)
Layer 3: NetworkMonitor  — detect unexpected connections
Layer 4: SourceInspector — heuristic pattern scan
"""

import glob
import hashlib
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path

from .config import get_sensitive_paths, get_sensitive_env_vars

COLORS = {
    'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
    'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
    'bold': '\033[1m', 'dim': '\033[2m', 'reset': '\033[0m',
}

def c(text, color):
    if not sys.stdout.isatty():
        return str(text)
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


# ---------------------------------------------------------------------------
# Docker Sandbox
# ---------------------------------------------------------------------------

class DockerSandbox:
    def __init__(self, config=None):
        self.config = config or {}
        self.available = self._check()

    def _check(self):
        try:
            r = subprocess.run(['docker', 'info'], capture_output=True, timeout=10)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_in_sandbox(self, image, script, timeout=600):
        """Run a script in an isolated container. Returns (ok, stdout, stderr)."""
        sandbox_cfg = self.config.get("sandbox", {})
        mem = sandbox_cfg.get("memory_limit", "2g")
        cpus = str(sandbox_cfg.get("cpu_limit", "2"))

        cmd = [
            'docker', 'run', '--rm',
            '--name', f'safe-install-{os.getpid()}',
            f'--memory={mem}', f'--memory-swap={mem}',
            f'--cpus={cpus}',
            '--cap-drop=ALL',
            '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
            '--tmpfs', '/install:rw,noexec,nosuid,size=2g',
            '--security-opt=no-new-privileges:true',
            '--dns', '1.1.1.1',
            image,
            'sh', '-c', script,
        ]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode == 0, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'rm', '-f', f'safe-install-{os.getpid()}'],
                         capture_output=True, timeout=10)
            return False, '', 'Timed out'
        except Exception as e:
            return False, '', str(e)

    def download_and_copy(self, image, download_script, container_output_dir):
        """Run download in container, then copy artifacts out."""
        container_name = f'safe-install-cp-{os.getpid()}'
        sandbox_cfg = self.config.get("sandbox", {})
        mem = sandbox_cfg.get("memory_limit", "2g")
        cpus = str(sandbox_cfg.get("cpu_limit", "2"))
        timeout = sandbox_cfg.get("timeout", 600)

        host_dir = tempfile.mkdtemp(prefix='safe_install_out_')

        cmd = [
            'docker', 'run',
            '--name', container_name,
            f'--memory={mem}', f'--memory-swap={mem}',
            f'--cpus={cpus}',
            '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true',
            '--dns', '1.1.1.1',
            image,
            'sh', '-c', download_script,
        ]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                print(f"  {c('[ERROR]', 'red')} Container failed: {r.stderr[:300]}")
                subprocess.run(['docker', 'rm', '-f', container_name],
                             capture_output=True, timeout=10)
                return None

            subprocess.run(
                ['docker', 'cp', f'{container_name}:{container_output_dir}/.', host_dir],
                capture_output=True, timeout=60
            )
            subprocess.run(['docker', 'rm', '-f', container_name],
                         capture_output=True, timeout=10)
            return host_dir
        except Exception as e:
            print(f"  {c('[ERROR]', 'red')} Sandbox error: {e}")
            subprocess.run(['docker', 'rm', '-f', container_name],
                         capture_output=True, timeout=10)
            return None


# ---------------------------------------------------------------------------
# Credential Vault
# ---------------------------------------------------------------------------

class CredentialVault:
    def __init__(self, config=None, dry_run=False):
        self.config = config or {}
        self.dry_run = dry_run
        self.vault_dir = None
        self.moved_files = []
        self.saved_env = {}

    def lock(self):
        self.vault_dir = Path(tempfile.mkdtemp(prefix='safe_install_vault_'))
        if platform.system() != 'Windows':
            os.chmod(self.vault_dir, 0o700)

        sensitive_paths = get_sensitive_paths(self.config)
        hidden = 0
        for p in sensitive_paths:
            src = Path(os.path.expanduser(p))
            if '*' in str(src):
                sources = [Path(g) for g in glob.glob(str(src))]
            else:
                sources = [src]

            for s in sources:
                if not s.exists():
                    continue
                rel = str(s).replace(os.path.expanduser('~'), '').lstrip(os.sep)
                dst = self.vault_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                if self.dry_run:
                    print(f"  {c('[DRY]', 'yellow')} Would hide: {s}")
                    hidden += 1
                    continue
                try:
                    shutil.move(str(s), str(dst))
                    self.moved_files.append((str(s), str(dst)))
                    hidden += 1
                except Exception as e:
                    print(f"  {c('[WARN]', 'yellow')} Could not hide {s}: {e}")

        sensitive_vars = get_sensitive_env_vars(self.config)
        for var in sensitive_vars:
            val = os.environ.get(var)
            if val:
                self.saved_env[var] = val
                if not self.dry_run:
                    del os.environ[var]

        print(f"  {c('Vault locked:', 'green')} {hidden} paths hidden, {len(self.saved_env)} env vars cleared")

    def unlock(self):
        restored = 0
        for src_orig, dst in reversed(self.moved_files):
            try:
                Path(src_orig).parent.mkdir(parents=True, exist_ok=True)
                shutil.move(dst, src_orig)
                restored += 1
            except Exception as e:
                print(f"  {c('[ERROR]', 'red')} Restore failed {src_orig}: {e}")
                print(f"         Backup: {dst}")
        for var, val in self.saved_env.items():
            os.environ[var] = val
        if self.vault_dir and self.vault_dir.exists():
            shutil.rmtree(self.vault_dir, ignore_errors=True)
        print(f"  {c('Vault unlocked:', 'green')} {restored} paths, {len(self.saved_env)} env vars restored")


# ---------------------------------------------------------------------------
# Network Monitor
# ---------------------------------------------------------------------------

class NetworkMonitor:
    def __init__(self, config=None):
        self.config = config or {}
        self.baseline = set()
        self.suspicious = []
        self._running = False
        self._thread = None

        net_cfg = self.config.get("network", {})
        self.allowed_hosts = set(net_cfg.get("allowed_hosts", [
            'pypi.org', 'files.pythonhosted.org',
            'registry.npmjs.org', 'crates.io',
            'github.com', 'gitlab.com',
        ]))

    def _get_connections(self):
        try:
            if platform.system() == 'Windows':
                r = subprocess.run(['netstat', '-n', '-o'], capture_output=True, text=True, timeout=10)
            else:
                r = subprocess.run(['ss', '-tnp'], capture_output=True, text=True, timeout=10)
                if r.returncode != 0:
                    r = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=10)
            conns = set()
            for line in r.stdout.splitlines():
                for part in line.split():
                    m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', part)
                    if m and m.group(2) in ('443', '80', '8443'):
                        conns.add(m.group(1))
            return conns
        except Exception:
            return set()

    def _resolve(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _is_allowed(self, ip):
        host = self._resolve(ip)
        if any(a in host for a in self.allowed_hosts):
            return True
        return any(ip.startswith(p) for p in ('10.', '172.16.', '172.17.', '172.18.', '192.168.', '127.'))

    def start(self):
        self.baseline = self._get_connections()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            for ip in self._get_connections() - self.baseline:
                if not self._is_allowed(ip):
                    entry = f"{ip} ({self._resolve(ip)})"
                    if entry not in self.suspicious:
                        self.suspicious.append(entry)
                        print(f"  {c('[ALERT]', 'red')} Unexpected connection: {entry}")
            time.sleep(1)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        return self.suspicious


# ---------------------------------------------------------------------------
# Source Inspector (generic — works for any language)
# ---------------------------------------------------------------------------

EXFIL_PATTERNS_PYTHON = [
    (r'urllib\.request\.(urlopen|Request)', 'HTTP request via urllib'),
    (r'requests\.(get|post|put|patch)', 'HTTP request via requests'),
    (r'http\.client\.HTTP', 'HTTP request via http.client'),
    (r'socket\.socket\(', 'Raw socket creation'),
    (r'socket\.connect\(', 'Socket connection'),
    (r'subprocess\.(Popen|call|run|check_output)', 'Subprocess execution'),
    (r'os\.system\(', 'OS command execution'),
    (r'os\.popen\(', 'OS command via popen'),
    (r'os\.exec', 'Process replacement'),
    (r'base64\.(b64decode|b64encode|decodebytes)', 'Base64 (obfuscation)'),
    (r'exec\(', 'Dynamic code execution'),
    (r'eval\(', 'Dynamic code evaluation'),
    (r'__import__\(', 'Dynamic import'),
    (r'os\.environ', 'Environment variable access'),
    (r'os\.path\.expanduser.*\.(ssh|aws|kube|gnupg|git)', 'Sensitive path access'),
    (r'open\(.*\.(pem|key|crt|ssh|aws|env|credentials|token|secret)', 'Sensitive file read'),
    (r'ctypes\.(CDLL|windll|cdll)', 'Native library loading'),
    (r'keyring\.(get_password|set_password)', 'Keyring access'),
    (r'getpass\.(getuser|getpass)', 'Credential collection'),
    # litellm-inspired: nested encoding detection
    (r'base64\.b64decode\(.*base64\.b64decode', 'Double base64 encoding (nested obfuscation)'),
    (r'b64decode\(.*decode\(.*b64decode', 'Chained base64 decoding (nested obfuscation)'),
    (r'codecs\.decode\(.*base64', 'Codecs + base64 (layered obfuscation)'),
    # litellm-inspired: .pth file creation/manipulation
    (r'\.pth["\']', '.pth file reference (auto-execute on Python startup)'),
    (r'site-packages.*\.pth', '.pth file in site-packages (persistence)'),
    (r'sysconfig\.get_path.*purelib', 'Site-packages path lookup (possible .pth injection)'),
    # litellm-inspired: encrypted exfiltration
    (r'(AES|Cipher|PKCS|RSA).*new\(', 'Crypto cipher creation (possible encrypted exfil)'),
    (r'Crypto\.(Cipher|PublicKey|Random)', 'PyCryptodome usage (possible encrypted exfil)'),
    (r'cryptography\.(fernet|hazmat)', 'Cryptography lib (possible encrypted exfil)'),
    # litellm-inspired: systemd/cron persistence
    (r'systemd.*service|\.service["\']|sysmon\.service', 'Systemd service reference (persistence)'),
    (r'crontab|cron\.d', 'Crontab manipulation (persistence)'),
    (r'/etc/systemd|systemctl|WantedBy=', 'Systemd manipulation (persistence)'),
    # litellm-inspired: K8s lateral movement
    (r'kubectl|kubernetes\.client|from kubernetes import', 'Kubernetes API access (lateral movement)'),
    (r'KubeConfig|load_kube_config|load_incluster', 'Kubernetes config loading (lateral movement)'),
    (r'create_namespaced_pod|privileged.*[Tt]rue', 'K8s privileged pod creation (lateral movement)'),
    # litellm-inspired: tarball creation for exfil
    (r'tarfile\.open.*["\']w', 'Tar archive creation (possible data staging for exfil)'),
    (r'shutil\.make_archive', 'Archive creation (possible data staging for exfil)'),
]

EXFIL_PATTERNS_JS = [
    (r'require\(["\']child_process["\']\)', 'Child process import'),
    (r'exec\(|execSync\(|spawn\(|spawnSync\(', 'Command execution'),
    (r'fs\.readFile|fs\.readFileSync', 'File system read'),
    (r'process\.env', 'Environment variable access'),
    (r'https?\.request\(|fetch\(|axios\.|got\(', 'HTTP request'),
    (r'net\.createConnection|net\.connect', 'Socket connection'),
    (r'dns\.resolve|dns\.lookup', 'DNS operation'),
    (r'Buffer\.from\(.*base64', 'Base64 (obfuscation)'),
    (r'eval\(|Function\(', 'Dynamic code execution'),
    (r'require\(["\']os["\']\)', 'OS module import'),
    (r'\.homedir\(\).*\.(ssh|aws|kube|gnupg)', 'Sensitive path access'),
    (r'path\.join\(.*\.(pem|key|env|credentials|token)', 'Sensitive file path'),
    (r'crypto\.create', 'Crypto operation in install'),
    (r'WebSocket\(|ws\(', 'WebSocket connection'),
]

EXFIL_PATTERNS_RUST = [
    (r'std::process::Command', 'Command execution'),
    (r'std::net::(TcpStream|UdpSocket)', 'Network connection'),
    (r'std::env::(var|vars|home_dir)', 'Environment/home access'),
    (r'std::fs::(read|read_to_string)', 'File system read'),
    (r'reqwest::|hyper::|curl::', 'HTTP client usage'),
    (r'\.ssh|\.aws|\.kube|\.gnupg', 'Sensitive path reference'),
]

EXFIL_PATTERNS_GO = [
    (r'os/exec|exec\.Command', 'Command execution'),
    (r'net\.Dial|net\.Listen|http\.Get|http\.Post', 'Network connection'),
    (r'os\.Getenv|os\.Environ', 'Environment access'),
    (r'os\.ReadFile|ioutil\.ReadFile', 'File read'),
    (r'os\.UserHomeDir.*\.(ssh|aws|kube)', 'Sensitive path access'),
]

EXFIL_PATTERNS_RUBY = [
    (r'system\(|exec\(|`.*`|%x\[', 'Command execution'),
    (r'Net::HTTP|URI\.open|open-uri|Faraday|HTTParty', 'HTTP request'),
    (r'ENV\[|ENV\.fetch', 'Environment variable access'),
    (r'File\.read|IO\.read', 'File read'),
    (r'Dir\.home.*\.(ssh|aws|kube)', 'Sensitive path access'),
    (r'Socket\.new|TCPSocket\.new', 'Socket connection'),
]

PATTERNS_BY_LANG = {
    'python': (EXFIL_PATTERNS_PYTHON, {'.py', '.pth'}),
    'javascript': (EXFIL_PATTERNS_JS, {'.js', '.mjs', '.cjs', '.ts'}),
    'rust': (EXFIL_PATTERNS_RUST, {'.rs'}),
    'go': (EXFIL_PATTERNS_GO, {'.go'}),
    'ruby': (EXFIL_PATTERNS_RUBY, {'.rb'}),
}

HIGH_RISK_FILES = {
    'python': ['setup.py', 'setup.cfg', 'conftest.py', '__init__.py', '__main__.py',
               '*.pth'],  # .pth files execute on every Python startup
    'javascript': ['package.json', 'preinstall.js', 'postinstall.js', 'install.js',
                   'preinstall.sh', 'postinstall.sh', 'index.js'],
    'rust': ['build.rs', 'lib.rs', 'main.rs'],
    'go': ['main.go'],
    'ruby': ['Rakefile', 'extconf.rb', 'Gemfile'],
}


class SourceInspector:
    READ_KEYWORDS = {'environment', 'sensitive', 'file read', 'credential', 'keyring',
                     'env', 'path access'}
    SEND_KEYWORDS = {'http', 'socket', 'dns', 'websocket', 'network', 'connection'}

    def __init__(self, languages=None, config=None):
        self.languages = languages or ['python']
        self.findings = []
        self.config = config or {}
        scan_cfg = self.config.get('scan', {})
        self._use_whitelist = scan_cfg.get('use_whitelist', True)
        self._use_cooccurrence = scan_cfg.get('cooccurrence_weighting', True)

        if self._use_whitelist:
            try:
                from .data.popular_packages import POPULAR
                self._whitelist = POPULAR.get('pip', set()) | POPULAR.get('npm', set())
            except ImportError:
                self._whitelist = set()
        else:
            self._whitelist = set()

    def _is_in_comment(self, line, lang):
        stripped = line.lstrip()
        if lang == 'python':
            if stripped.startswith('#'):
                return True
            if stripped.startswith(('"""', "'''")):
                return True
            # RST docstring references like :class:`http.client.HTTPResponse`
            if ':class:`' in stripped or ':meth:`' in stripped or ':func:`' in stripped:
                return True
            # Doctest lines
            if stripped.startswith('>>>'):
                return True
            # RST-style parameter docs
            if stripped.startswith(':param ') or stripped.startswith(':type '):
                return True
        elif lang in ('javascript', 'rust', 'go'):
            if stripped.startswith('//'):
                return True
            if stripped.startswith('/*') or stripped.startswith('*'):
                return True
        elif lang == 'ruby':
            if stripped.startswith('#'):
                return True
        return False

    def _apply_cooccurrence(self):
        by_file = {}
        for f in self.findings:
            by_file.setdefault(f['file'], []).append(f)

        downgraded = []
        for filepath, items in by_file.items():
            is_high_risk = any(i['severity'] in ('CRITICAL', 'HIGH') for i in items)
            if len(items) == 1 and not is_high_risk:
                continue  # single match in non-high-risk file: drop it
            if len(items) >= 2:
                descs = {i['pattern'].lower() for i in items}
                has_read = any(any(kw in d for kw in self.READ_KEYWORDS) for d in descs)
                has_send = any(any(kw in d for kw in self.SEND_KEYWORDS) for d in descs)
                if has_read and has_send:
                    for i in items:
                        if i['severity'] != 'CRITICAL':
                            i['severity'] = 'CRITICAL'
            downgraded.extend(items)
        self.findings = downgraded

    def scan_file(self, filepath, relpath):
        ext = os.path.splitext(filepath)[1]
        basename = os.path.basename(filepath)

        for lang in self.languages:
            patterns, extensions = PATTERNS_BY_LANG.get(lang, ([], set()))
            if ext not in extensions:
                continue

            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
            except Exception:
                return

            is_high_risk = basename in HIGH_RISK_FILES.get(lang, [])
            check_patterns = patterns if is_high_risk else [
                p for p in patterns if any(kw in p[1].lower() for kw in
                    ['http', 'socket', 'sensitive', 'command', 'exec',
                     'base64', 'obfuscation', 'native', 'credential', 'dns'])
            ]

            for pattern, desc in check_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    lines = content.splitlines()
                    ctx = lines[line_num - 1].strip() if line_num <= len(lines) else ''

                    if self._is_in_comment(ctx, lang):
                        continue

                    if len(ctx) > 120:
                        ctx = ctx[:120] + '...'

                    severity = 'HIGH' if is_high_risk else 'MEDIUM'
                    if is_high_risk and any(kw in desc.lower() for kw in
                            ['http', 'socket', 'environment', 'sensitive', 'command']):
                        severity = 'CRITICAL'

                    self.findings.append({
                        'severity': severity, 'file': relpath,
                        'line': line_num, 'pattern': desc,
                        'context': ctx, 'language': lang,
                    })

    def _scan_pth_files(self, directory):
        """Scan for .pth files — these execute on every Python startup (litellm attack vector)."""
        for root, dirs, files in os.walk(directory):
            for fname in files:
                if fname.endswith('.pth'):
                    filepath = os.path.join(root, fname)
                    relpath = os.path.relpath(filepath, directory)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read().strip()
                    except Exception:
                        continue
                    # Any .pth file with executable code (not just path entries) is CRITICAL
                    has_import = 'import ' in content
                    has_exec = any(kw in content for kw in ['exec(', 'eval(', '__import__',
                                                            'subprocess', 'os.system', 'urllib',
                                                            'requests.', 'socket.', 'base64'])
                    if has_import or has_exec:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'file': relpath,
                            'line': 1,
                            'pattern': '.pth file with executable code (runs on every Python startup)',
                            'context': content[:120] + ('...' if len(content) > 120 else ''),
                            'language': 'python',
                        })
                    elif content and not all(line.startswith('#') or line.startswith('/')
                                            or line.startswith('.') or not line.strip()
                                            for line in content.splitlines()):
                        self.findings.append({
                            'severity': 'HIGH',
                            'file': relpath,
                            'line': 1,
                            'pattern': '.pth file with non-path content (suspicious)',
                            'context': content[:120] + ('...' if len(content) > 120 else ''),
                            'language': 'python',
                        })

    def scan_directory(self, directory):
        if self._use_whitelist and self._whitelist:
            pkg_name = os.path.basename(directory.rstrip(os.sep)).lower()
            pkg_name = re.sub(r'[-_]\d+[\d.]*.*$', '', pkg_name).replace('_', '-').rstrip('-')
            if pkg_name in self._whitelist:
                print(f"  {c(f'Skipping {pkg_name} (whitelisted)', 'dim')}")
                return

        # Scan .pth files first (litellm attack vector)
        self._scan_pth_files(directory)

        skip_dirs = {'tests', 'test', 'testing', 'examples', 'docs',
                     'node_modules', '.git', '__pycache__', 'vendor'}
        all_high_risk = set()
        for lang in self.languages:
            all_high_risk.update(HIGH_RISK_FILES.get(lang, []))

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            relroot = os.path.relpath(root, directory)
            is_test = any(p in skip_dirs for p in relroot.split(os.sep))

            for fname in files:
                if is_test and fname not in all_high_risk:
                    continue
                self.scan_file(os.path.join(root, fname),
                              os.path.relpath(os.path.join(root, fname), directory))

        if self._use_cooccurrence:
            self._apply_cooccurrence()

    def report(self, max_per_severity=15):
        if not self.findings:
            print(f"  {c('No suspicious patterns found', 'green')}")
            return False

        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f['severity'], []).append(f)

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
            items = by_sev.get(sev, [])
            if not items:
                continue
            color = 'red' if sev in ('CRITICAL', 'HIGH') else 'yellow'
            print(f"\n  {c(f'[{sev}]', color)} -- {len(items)} finding(s):")
            for item in items[:max_per_severity]:
                lang_tag = c(f'[{item["language"]}]', 'dim')
                print(f"    {lang_tag} {item['file']}:{item['line']} -- {item['pattern']}")
                print(f"      {c(item['context'], 'dim')}")
            if len(items) > max_per_severity:
                print(f"    ... and {len(items) - max_per_severity} more")

        return 'CRITICAL' in by_sev


# ---------------------------------------------------------------------------
# Hash Verification
# ---------------------------------------------------------------------------

class HashVerifier:
    @staticmethod
    def hash_file(filepath):
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def verify_against_lockfile(artifact_dir, lockfile_path):
        if not os.path.exists(lockfile_path):
            return True

        expected = {}
        with open(lockfile_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = re.match(r'(\S+)==(\S+)\s+--hash=sha256:(\w+)', line)
                if m:
                    expected[m.group(1).lower()] = m.group(3)

        mismatches = []
        for fname in os.listdir(artifact_dir):
            fpath = os.path.join(artifact_dir, fname)
            if not os.path.isfile(fpath):
                continue
            actual = HashVerifier.hash_file(fpath)
            pkg_name = fname.split('-')[0].lower().replace('_', '-')
            if pkg_name in expected and expected[pkg_name] != actual:
                mismatches.append((pkg_name, expected[pkg_name][:16], actual[:16]))

        if mismatches:
            print(f"\n  {c('HASH MISMATCH!', 'red')}")
            for name, exp, act in mismatches:
                print(f"    {name}: expected {exp}... got {act}...")
            return False
        return True


# ---------------------------------------------------------------------------
# Environment Check
# ---------------------------------------------------------------------------

def check_environment(config):
    print(f"\n{c('  Credential exposure check', 'bold')}\n")

    print(f"  {c('Sensitive files on disk:', 'bold')}")
    found_files = 0
    for p in get_sensitive_paths(config):
        ep = Path(os.path.expanduser(p))
        if ep.exists():
            if ep.is_dir():
                try:
                    size = sum(f.stat().st_size for f in ep.rglob('*') if f.is_file())
                except Exception:
                    size = 0
            else:
                size = ep.stat().st_size
            print(f"    {c('EXPOSED', 'red')} {ep} ({size // 1024}KB)")
            found_files += 1
    if not found_files:
        print(f"    {c('None found', 'green')}")

    print(f"\n  {c('Sensitive env vars set:', 'bold')}")
    found_env = 0
    for var in get_sensitive_env_vars(config):
        val = os.environ.get(var)
        if val:
            masked = val[:4] + '...' + val[-4:] if len(val) > 12 else '***'
            print(f"    {c('EXPOSED', 'red')} {var}={masked}")
            found_env += 1
    if not found_env:
        print(f"    {c('None found', 'green')}")

    print(f"\n  {c('Isolation capabilities:', 'bold')}")
    docker = DockerSandbox(config)
    print(f"    Docker: {c('available', 'green') if docker.available else c('NOT available', 'red')}")

    bubblewrap = shutil.which('bwrap')
    print(f"    Bubblewrap: {c('available', 'green') if bubblewrap else c('NOT available', 'yellow')}")

    print(f"\n  {c('Summary:', 'bold')} {found_files} files, {found_env} env vars exposed")
    print(f"  Any malicious package install could read ALL of these.\n")
