"""Gap 6: Dependency confusion detection - public vs private registry conflicts."""

import json
import urllib.request
import urllib.error
from typing import Optional

from .core import c


class DependencyConfusionDetector:
    def __init__(self, config=None):
        self.config = config or {}
        registries_cfg = self.config.get("registries", {})
        self.private_registries = registries_cfg.get("private", [])
        self.internal_packages = set(registries_cfg.get("internal_packages", []))
        self.internal_prefixes = registries_cfg.get("internal_prefixes", [])
        self.warnings = []

    def check(self, package: str, ecosystem: str = "pip") -> list:
        """Check for dependency confusion. Returns warnings."""
        self.warnings = []

        match = self._matches_internal_pattern(package)
        if not match:
            return self.warnings

        if ecosystem in ("pip", "python"):
            public = self._exists_on_pypi(package)
        elif ecosystem in ("npm", "node"):
            public = self._exists_on_npm(package)
        else:
            return self.warnings

        if public:
            self.warnings.append({
                "level": "HIGH",
                "category": "dependency_confusion",
                "message": (
                    f"Package '{package}' matches internal pattern '{match}' "
                    f"but also exists on public registry (v{public['version']}). "
                    f"This could be a dependency confusion attack."
                ),
            })

            if self.private_registries:
                self.warnings.append({
                    "level": "MEDIUM",
                    "category": "confusion_mitigation",
                    "message": (
                        f"Verify that '{package}' is pinned to your private registry. "
                        f"Configured private registries: {', '.join(self.private_registries)}"
                    ),
                })
        else:
            self.warnings.append({
                "level": "LOW",
                "category": "internal_only",
                "message": (
                    f"Package '{package}' matches internal pattern '{match}' "
                    f"and does NOT exist on public registry (good)"
                ),
            })

        return self.warnings

    def _exists_on_pypi(self, package: str) -> Optional[dict]:
        """Check PyPI, return {'version': str} or None."""
        url = f"https://pypi.org/pypi/{package}/json"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                version = data.get("info", {}).get("version", "unknown")
                return {"version": version}
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    def _exists_on_npm(self, package: str) -> Optional[dict]:
        """Check npm, return {'version': str} or None."""
        url = f"https://registry.npmjs.org/{package}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                version = data.get("dist-tags", {}).get("latest", "unknown")
                return {"version": version}
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    def _matches_internal_pattern(self, package: str) -> Optional[str]:
        """Check if name matches internal_packages or internal_prefixes.
        Returns the matching pattern or None."""
        if package in self.internal_packages:
            return package

        for prefix in self.internal_prefixes:
            if package.startswith(prefix):
                return f"{prefix}*"

        return None

    def _version_gt(self, v1: str, v2: str) -> bool:
        """Simple version comparison (split by dots, compare numerically)."""
        def parse(v):
            parts = []
            for p in v.split("."):
                try:
                    parts.append(int(p))
                except ValueError:
                    parts.append(0)
            return parts

        p1 = parse(v1)
        p2 = parse(v2)
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))
        return p1 > p2

    def report(self) -> bool:
        """Print warnings. Returns True if HIGH found."""
        if not self.warnings:
            print(f"  {c('No dependency confusion risks detected', 'green')}")
            return False

        has_high = False
        for w in self.warnings:
            level = w["level"]
            if level == "HIGH":
                color = "red"
                has_high = True
            elif level == "MEDIUM":
                color = "yellow"
            else:
                color = "dim"
            print(f"  {c(f'[{level}]', color)} {w['category']}: {w['message']}")

        return has_high
