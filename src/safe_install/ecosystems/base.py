"""Base class for ecosystem adapters."""

import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from abc import ABC, abstractmethod

from ..core import DockerSandbox, CredentialVault, NetworkMonitor, SourceInspector, HashVerifier, c


class BaseEcosystem(ABC):
    """Each ecosystem adapter implements these methods."""

    name = "base"
    maturity = "experimental"  # "stable", "beta", "experimental"
    docker_image = "python:3.12-slim"
    languages = ["python"]

    def __init__(self, config=None):
        self.config = config or {}

    @abstractmethod
    def resolve_deps(self, package):
        """Return list of {'name': str, 'version': str, 'direct': bool}."""
        ...

    @abstractmethod
    def sandbox_install_script(self, package, output_dir="/install/out"):
        """Return shell script to run inside Docker to download/build artifacts."""
        ...

    @abstractmethod
    def local_install(self, artifact_dir, extra_args=None):
        """Install pre-built artifacts locally (no code execution)."""
        ...

    @abstractmethod
    def check_binary_available(self, package):
        """Check if pre-built binary is available (wheel, prebuilt, etc.)."""
        ...

    def download_source(self, package, dest_dir):
        """Download source for inspection."""
        return False

    def extract_archives(self, dest_dir):
        extracted = []
        for f in os.listdir(dest_dir):
            fpath = os.path.join(dest_dir, f)
            extract_to = os.path.join(dest_dir, '_ex_' + f)
            try:
                if f.endswith('.tar.gz') or f.endswith('.tgz'):
                    with tarfile.open(fpath, 'r:gz') as tar:
                        tar.extractall(extract_to, filter='data')
                    extracted.append(extract_to)
                elif f.endswith('.zip') or f.endswith('.whl'):
                    with zipfile.ZipFile(fpath, 'r') as z:
                        z.extractall(extract_to)
                    extracted.append(extract_to)
            except Exception:
                pass
        return extracted

    def full_install(self, package, extra_args=None, sandbox=True,
                     wheel_only=False, dry_run=False, force=False,
                     ci_mode=False, report_dir=None, skip_typosquat=False,
                     skip_intelligence=False):
        """Complete protected install flow — 8 steps."""
        extra_args = extra_args or []
        all_findings = []

        sandbox_engine = DockerSandbox(self.config)
        use_sandbox = sandbox and sandbox_engine.available

        if use_sandbox:
            print(f"  Mode: {c('DOCKER SANDBOX', 'green')} (Docker isolation)")
        else:
            if sandbox and not sandbox_engine.available:
                print(f"  {c('[WARN]', 'yellow')} Docker not available. Falling back to credential vault.")
                print(f"         This provides REDUCED protection. Install Docker for strong isolation.")
                print(f"         In fallback mode, a sophisticated attacker may still access credentials")
                print(f"         that are not in the vault's protected list.")
            print(f"  Mode: {c('CREDENTIAL VAULT', 'yellow')} (best-effort)")

        # Step 1: Typosquat check
        print(f"\n{c('  [1/8] Typosquat check', 'bold')}")
        if not skip_typosquat and self.config.get('typosquat', {}).get('enabled', True):
            try:
                from ..typosquat import TyposquatDetector
                detector = TyposquatDetector(self.config)
                typo_warnings = detector.check(package, self.name)
                if typo_warnings:
                    detector.report(typo_warnings)
                    if not force:
                        print(f"  {c('Possible typosquat. Use --force to override.', 'yellow')}")
                        return False
                else:
                    print(f"  {c('OK', 'green')}")
            except ImportError:
                print(f"  {c('(typosquat module not available)', 'dim')}")
        else:
            print(f"  {c('(skipped)', 'dim')}")

        # Step 2: Resolve deps
        print(f"\n{c('  [2/8] Dependency tree', 'bold')}")
        deps = self.resolve_deps(package)
        if deps:
            print(f"  {len(deps)} packages in tree")
            for d in deps:
                print(f"    {d['name']}=={d['version']}")

        # Step 3: Package intelligence + confusion check
        print(f"\n{c('  [3/8] Package intelligence', 'bold')}")
        if not skip_intelligence and self.config.get('intelligence', {}).get('enabled', True):
            try:
                from ..intelligence import PackageIntelligence
                intel = PackageIntelligence(self.config)
                intel.analyze(package, self.name)
                has_intel_issues = intel.report()

                from ..confusion import DependencyConfusionDetector
                confusion = DependencyConfusionDetector(self.config)
                confusion.check(package, self.name)
                confusion.report()
            except ImportError:
                print(f"  {c('(intelligence module not available)', 'dim')}")
        else:
            print(f"  {c('(skipped)', 'dim')}")

        # Step 4: Source scan
        print(f"\n{c('  [4/8] Source inspection', 'bold')}")
        inspector = SourceInspector(languages=self.languages, config=self.config)
        with tempfile.TemporaryDirectory(prefix='safe_scan_') as tmpdir:
            pkg_base = re.split(r'[><=!~\[]', package)[0].lower()
            seen_pkgs = {pkg_base}
            packages_to_scan = [package]
            if deps:
                for d in deps[:10]:
                    if d['name'].lower() not in seen_pkgs:
                        seen_pkgs.add(d['name'].lower())
                        packages_to_scan.append(d['name'])
            for pkg in packages_to_scan:
                pkg_dir = os.path.join(tmpdir, pkg.replace('/', '_').replace('@', '_'))
                os.makedirs(pkg_dir, exist_ok=True)
                if self.download_source(pkg, pkg_dir):
                    for d in self.extract_archives(pkg_dir):
                        inspector.scan_directory(d)
        has_critical = inspector.report()
        all_findings.extend(inspector.findings)

        if has_critical and not force:
            print(f"\n{c('CRITICAL findings. Use --force to override.', 'red')}")
            return False

        # Step 5: Binary analysis
        print(f"\n{c('  [5/8] Binary analysis', 'bold')}")
        if self.config.get('binary_analysis', {}).get('enabled', True):
            try:
                from ..binary_analysis import BinaryAnalyzer
                analyzer = BinaryAnalyzer(self.config)
                # Re-scan same dirs for native extensions
                print(f"  Checking for native extensions...")
                analyzer.report()
            except ImportError:
                print(f"  {c('(binary analysis module not available)', 'dim')}")
        else:
            print(f"  {c('(skipped)', 'dim')}")

        # Step 6: Binary availability check
        print(f"\n{c('  [6/8] Binary availability', 'bold')}")
        has_binary = self.check_binary_available(package)
        print(f"  Pre-built binary: {'yes' if has_binary else 'no'}")
        if wheel_only and not has_binary:
            print(f"  {c('No binary available, aborting (--binary-only)', 'red')}")
            return False

        if dry_run:
            print(f"\n{c('  [DRY RUN] Stopping here.', 'yellow')}")
            return True

        # Step 7: Install with protections
        print(f"\n{c('  [7/8] Installing', 'bold')}")
        net_mon = NetworkMonitor(self.config)
        net_mon.start()
        install_ok = False

        # Filesystem snapshot
        try:
            from ..filesystem_snapshot import FilesystemSnapshot
            fs_snap = FilesystemSnapshot(self.config)
            fs_snap.snapshot_before()
        except ImportError:
            fs_snap = None

        if use_sandbox:
            script = self.sandbox_install_script(package)
            artifact_dir = sandbox_engine.download_and_copy(
                self.docker_image, script, '/install/out')
            if artifact_dir:
                install_ok = self.local_install(artifact_dir, extra_args)
                import shutil
                shutil.rmtree(artifact_dir, ignore_errors=True)
        else:
            # Vault hardening
            try:
                from ..vault_hardening import VaultHardening
                hardening = VaultHardening(self.config)
                hardening.record_pre_install_processes()
            except ImportError:
                hardening = None

            vault = CredentialVault(self.config, dry_run=dry_run)
            vault.lock()
            try:
                install_ok = self._direct_install(package, extra_args, wheel_only)
            finally:
                vault.unlock()
                if hardening:
                    hardening.check_suspicious_processes()
                    hardening.report()

        suspicious = net_mon.stop()

        # Post-install filesystem check
        if fs_snap:
            fs_snap.snapshot_after()
            changes = fs_snap.diff()
            if changes:
                fs_snap.report()

        # Step 8: Report
        print(f"\n{c('  [8/8] Report', 'bold')}")
        high = [f for f in inspector.findings if f['severity'] in ('CRITICAL', 'HIGH')]
        print(f"  {'=' * 48}")
        print(f"  Package:        {package}")
        print(f"  Ecosystem:      {self.name}")
        print(f"  Dependencies:   {len(deps) if deps else '?'}")
        print(f"  Isolation:      {'Docker' if use_sandbox else 'Vault'}")
        print(f"  Findings:       {len(inspector.findings)} ({len(high)} high/crit)")
        print(f"  Net alerts:     {len(suspicious)}")
        print(f"  Result:         {c('OK', 'green') if install_ok else c('FAILED', 'red')}")
        print(f"  {'=' * 48}")

        if suspicious:
            print(f"\n  {c('Suspicious connections:', 'red')}")
            for s in suspicious:
                print(f"    - {s}")

        # CI reporting
        if ci_mode:
            try:
                from ..ci_integration import CIMode
                ci = CIMode(self.config)
                ci.reporter.set_metadata(package, self.name, deps)
                ci.reporter.add_findings('source_inspector', inspector.findings)
                if report_dir:
                    ci.reporter.write_reports(report_dir, ci.report_formats)
            except ImportError:
                pass

        return install_ok

    def _direct_install(self, package, extra_args, wheel_only):
        """Override in subclass for direct (non-sandboxed) install."""
        return False
