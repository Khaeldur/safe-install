"""Gap 2: Import-time attack defense - sys.meta_path hook for first-import scanning."""

import importlib
import os
import subprocess
import sys
from .core import c, SourceInspector


class ImportGuard:
    def __init__(self, config=None):
        self.config = config or {}
        cfg = self.config.get("import_guard", {})
        self.mode = cfg.get("mode", "monitor")
        self.whitelist = set()
        self.scanned = set()
        self.findings = []
        self._active = False
        self._load_whitelist(cfg.get("whitelist_path"))

    def _load_whitelist(self, path=None):
        try:
            from .data.popular_packages import POPULAR_PIP
            self.whitelist.update(POPULAR_PIP)
        except ImportError:
            pass
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.whitelist.add(line)
        self.whitelist.add('safe_install')
        if hasattr(sys, 'stdlib_module_names'):
            self.whitelist.update(sys.stdlib_module_names)

    def activate(self):
        if not self._active:
            sys.meta_path.insert(0, self)
            self._active = True
            print(f"  {c('ImportGuard activated', 'green')} (mode: {self.mode})")

    def deactivate(self):
        if self._active and self in sys.meta_path:
            sys.meta_path.remove(self)
            self._active = False
            print(f"  {c('ImportGuard deactivated', 'yellow')}")

    def find_module(self, fullname, path=None):
        top = fullname.split('.')[0]
        if top in self.whitelist or top in self.scanned or top.startswith('_'):
            return None
        return self

    def load_module(self, fullname):
        top = fullname.split('.')[0]
        self.scanned.add(top)
        sys.meta_path.remove(self)
        try:
            pkg_path = self._find_package_path(top)
            if pkg_path:
                findings = self._scan_package(top, pkg_path)
                if findings:
                    self.findings.extend(findings)
                    critical = any(f['severity'] == 'CRITICAL' for f in findings)
                    if self.mode == "block" and critical:
                        print(f"  {c('[BLOCKED]', 'red')} Import of {top} blocked")
                        raise ImportError(f"safe-install blocked import of {top}")
                    if self.mode == "sandbox" and critical:
                        safe, msg = self._sandbox_import(fullname)
                        if not safe:
                            print(f"  {c('[BLOCKED]', 'red')} Sandbox blocked {top}")
                            raise ImportError(f"safe-install sandbox blocked {top}")
            return importlib.import_module(fullname)
        finally:
            if self._active:
                sys.meta_path.insert(0, self)

    def _find_package_path(self, name):
        for p in sys.path:
            d = os.path.join(p, name)
            if os.path.isdir(d):
                return d
            f = os.path.join(p, name + '.py')
            if os.path.isfile(f):
                return f
        return None

    def _scan_package(self, name, path):
        print(f"  {c('[ImportGuard]', 'cyan')} Scanning {name}...")
        inspector = SourceInspector(languages=['python'])
        if os.path.isdir(path):
            inspector.scan_directory(path)
        else:
            inspector.scan_file(path, os.path.basename(path))
        if inspector.findings:
            high = [f for f in inspector.findings if f['severity'] in ('CRITICAL', 'HIGH')]
            print(f"  {c('[ImportGuard]', 'cyan')} {name}: {len(inspector.findings)} findings ({len(high)} high/crit)")
        return inspector.findings

    def _sandbox_import(self, fullname):
        try:
            env = {k: v for k, v in os.environ.items()
                   if k in ('PATH', 'PYTHONPATH', 'SYSTEMROOT', 'TEMP', 'TMP')}
            r = subprocess.run(
                [sys.executable, '-c', f'import {fullname}; print("IMPORT_OK")'],
                capture_output=True, text=True, timeout=30, env=env)
            return ('IMPORT_OK' in r.stdout), r.stdout + r.stderr
        except Exception as e:
            return False, str(e)

    def report(self):
        if not self.findings:
            print(f"  {c('ImportGuard: no issues', 'green')}")
            return False
        print(f"  {c('ImportGuard:', 'yellow')} {len(self.findings)} findings")
        return any(f['severity'] == 'CRITICAL' for f in self.findings)
