"""Bootstrap verification - verify safe-install itself hasn't been tampered with.

NOTE: Release artifacts with SHA256SUMS do not yet exist on GitHub.
Until releases are established, verify_self() will always return
(True, "no published hash to verify against"). The local hash
computation and package integrity checks are functional.
"""

import hashlib
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

from .core import c


class BootstrapVerifier:
    HASH_URL = "https://github.com/Khaeldur/safe-install/releases/latest/download/SHA256SUMS"

    def __init__(self, config=None):
        self.config = config or {}

    def verify_self(self) -> tuple:
        """Verify the running safe-install against published hash.
        Returns (is_valid, message)."""
        installed_hash = self._get_installed_hash()
        published_hash = self._fetch_published_hash()

        if published_hash is None:
            return (True, "no published release hash available yet (pre-release)")

        if installed_hash == published_hash:
            return (True, f"integrity OK ({installed_hash[:12]}...)")

        return (False, f"MISMATCH: installed={installed_hash[:12]}... published={published_hash[:12]}...")

    def _get_installed_hash(self) -> str:
        """SHA256 of all .py files in the safe_install package directory, sorted and concatenated."""
        pkg_dir = self._get_package_dir()
        py_files = sorted(pkg_dir.rglob("*.py"))

        hasher = hashlib.sha256()
        for f in py_files:
            rel = f.relative_to(pkg_dir).as_posix()
            hasher.update(rel.encode("utf-8"))
            hasher.update(f.read_bytes())

        return hasher.hexdigest()

    def _get_package_dir(self) -> Path:
        """Return the directory where safe_install is installed."""
        return Path(__file__).resolve().parent

    def _fetch_published_hash(self) -> str | None:
        """Fetch SHA256SUMS from GitHub releases using urllib.
        Returns expected hash or None on failure."""
        url = self.config.get("hash_url", self.HASH_URL)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "safe-install-bootstrap"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8").strip()
        except (urllib.error.URLError, OSError, ValueError):
            return None

        # SHA256SUMS format: "<hash>  safe-install" or "<hash>  safe_install"
        for line in body.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and "safe" in parts[1].lower():
                return parts[0]
            # Single-line file with just the hash
            if len(parts) == 1 and len(parts[0]) == 64:
                return parts[0]

        return None

    @staticmethod
    def generate_hash_file(package_dir: str = None) -> str:
        """Generate SHA256 hash of the package. Used during release to create SHA256SUMS."""
        if package_dir is None:
            pkg = Path(__file__).resolve().parent
        else:
            pkg = Path(package_dir)

        py_files = sorted(pkg.rglob("*.py"))

        hasher = hashlib.sha256()
        for f in py_files:
            rel = f.relative_to(pkg).as_posix()
            hasher.update(rel.encode("utf-8"))
            hasher.update(f.read_bytes())

        return hasher.hexdigest()

    def check_package_integrity(self) -> list:
        """Check all .py and .pyc files for unexpected modifications.
        Returns list of issues found."""
        issues = []
        pkg_dir = self._get_package_dir()

        # Check for .pyc without matching .py
        for pyc in pkg_dir.rglob("*.pyc"):
            # __pycache__/module.cpython-XY.pyc -> module.py
            stem = pyc.stem.split(".")[0]
            expected_py = pyc.parent.parent / (stem + ".py")
            if not expected_py.exists():
                issues.append({
                    "type": "orphan_pyc",
                    "path": str(pyc),
                    "detail": f"compiled file with no matching source: {stem}.py",
                })

        # Check for unexpected files (not .py, .pyc, or known data)
        known_ext = {".py", ".pyc", ".pyi", ".json", ".yaml", ".yml", ".toml", ".txt", ".cfg"}
        for f in pkg_dir.rglob("*"):
            if f.is_dir():
                continue
            if f.suffix not in known_ext and f.name != "__pycache__":
                issues.append({
                    "type": "unexpected_file",
                    "path": str(f),
                    "detail": f"unexpected file type: {f.suffix or '(no extension)'}",
                })

        # Check for zero-byte .py files (potential truncation)
        for py in pkg_dir.rglob("*.py"):
            if py.stat().st_size == 0 and py.name != "__init__.py":
                issues.append({
                    "type": "empty_source",
                    "path": str(py),
                    "detail": "non-init source file is empty",
                })

        return issues
