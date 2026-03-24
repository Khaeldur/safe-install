"""Gap 5+10: Package intelligence - maintainer changes, release timing, Sigstore verification."""

import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Optional

from .core import c


class PackageIntelligence:
    PYPI_API = "https://pypi.org/pypi/{package}/json"
    NPM_API = "https://registry.npmjs.org/{package}"

    def __init__(self, config=None):
        self.config = config or {}
        self.warnings = []
        self._timeout = 10

    def analyze(self, package: str, ecosystem: str = "pip", version: Optional[str] = None) -> list:
        """Run all intelligence checks. Returns list of warnings.
        Each: {'level': 'HIGH'|'MEDIUM'|'LOW', 'category': str, 'message': str}"""
        self.warnings = []
        try:
            if ecosystem in ("pip", "python"):
                self.warnings = self._analyze_pypi(package, version)
            elif ecosystem in ("npm", "node"):
                self.warnings = self._analyze_npm(package, version)
        except Exception as e:
            print(f"  {c('[WARN]', 'yellow')} Intelligence check failed for {package}: {e}")
        return self.warnings

    def _query_api(self, url: str) -> Optional[dict]:
        """HTTP GET with timeout, returns parsed JSON or None."""
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as e:
            print(f"  {c('[WARN]', 'yellow')} API query failed ({url}): {e}")
            return None

    def _analyze_pypi(self, package: str, version: Optional[str] = None) -> list:
        """Analyze PyPI package metadata."""
        data = self._query_api(self.PYPI_API.format(package=package))
        if not data:
            return []

        warnings = []
        info = data.get("info", {})
        releases = data.get("releases", {})

        age_warnings = self._check_package_age_pypi(releases)
        warnings.extend(age_warnings)

        timing_warnings = self._check_release_timing(releases)
        warnings.extend(timing_warnings)

        version_warnings = self._check_version_anomalies(releases)
        warnings.extend(version_warnings)

        yanked = []
        for ver, files in releases.items():
            if files and any(f.get("yanked", False) for f in files):
                yanked.append(ver)
        if yanked:
            warnings.append({
                "level": "MEDIUM",
                "category": "yanked_versions",
                "message": f"Package has {len(yanked)} yanked version(s): {', '.join(yanked[:5])}",
            })

        if version:
            sig = self.check_sigstore(package, version)
            if sig and not sig["has_attestation"]:
                warnings.append({
                    "level": "LOW",
                    "category": "sigstore",
                    "message": sig["message"],
                })

        return warnings

    def _analyze_npm(self, package: str, version: Optional[str] = None) -> list:
        """Analyze npm package metadata."""
        data = self._query_api(self.NPM_API.format(package=package))
        if not data:
            return []

        warnings = []
        time_info = data.get("time", {})
        versions = data.get("versions", {})

        created = time_info.get("created")
        if created:
            warnings.extend(self._check_package_age(created))

        modified = time_info.get("modified")
        if modified and created:
            version_times = {
                k: v for k, v in time_info.items()
                if k not in ("created", "modified")
            }
            warnings.extend(self._check_npm_release_timing(version_times))

        dist_tags = data.get("dist-tags", {})
        latest = dist_tags.get("latest", "")
        if latest and versions:
            sorted_versions = [
                k for k in time_info
                if k not in ("created", "modified")
            ]
            if len(sorted_versions) >= 2:
                version_count = len(sorted_versions)
                if version_count < 3:
                    warnings.append({
                        "level": "MEDIUM",
                        "category": "low_version_count",
                        "message": f"Package has only {version_count} published version(s)",
                    })

        deprecated = data.get("versions", {}).get(latest, {}).get("deprecated")
        if deprecated:
            warnings.append({
                "level": "HIGH",
                "category": "deprecated",
                "message": f"Latest version is deprecated: {deprecated}",
            })

        return warnings

    def _check_release_timing(self, releases: dict) -> list:
        """Flag: release < 24h old, large gaps then sudden release."""
        warnings = []
        now = datetime.now(timezone.utc)

        upload_times = []
        for ver, files in releases.items():
            for f in files:
                ts = f.get("upload_time_iso_8601") or f.get("upload_time")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        upload_times.append((ver, dt))
                    except (ValueError, TypeError):
                        pass
                    break

        if not upload_times:
            return warnings

        upload_times.sort(key=lambda x: x[1])

        latest_ver, latest_time = upload_times[-1]
        age = now - latest_time
        if age < timedelta(hours=24):
            warnings.append({
                "level": "MEDIUM",
                "category": "fresh_release",
                "message": f"Latest release ({latest_ver}) is less than 24 hours old",
            })

        if len(upload_times) >= 3:
            gaps = []
            for i in range(1, len(upload_times)):
                gap = (upload_times[i][1] - upload_times[i - 1][1]).days
                gaps.append(gap)

            if len(gaps) >= 2:
                avg_gap = sum(gaps[:-1]) / len(gaps[:-1])
                last_gap = gaps[-1]
                if avg_gap > 180 and last_gap < 7:
                    warnings.append({
                        "level": "HIGH",
                        "category": "dormant_then_active",
                        "message": (
                            f"Package was dormant (avg {avg_gap:.0f} days between releases) "
                            f"then suddenly released {latest_ver} after only {last_gap} day(s)"
                        ),
                    })

        return warnings

    def _check_package_age_pypi(self, releases: dict) -> list:
        """Flag: package created < 30 days ago (from PyPI releases dict)."""
        earliest = None
        for ver, files in releases.items():
            for f in files:
                ts = f.get("upload_time_iso_8601") or f.get("upload_time")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if earliest is None or dt < earliest:
                            earliest = dt
                    except (ValueError, TypeError):
                        pass
                    break
        if earliest:
            return self._check_package_age(earliest.isoformat())
        return []

    def _check_package_age(self, first_release: str) -> list:
        """Flag: package created < 30 days ago."""
        warnings = []
        try:
            dt = datetime.fromisoformat(first_release.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - dt
            if age < timedelta(days=30):
                warnings.append({
                    "level": "HIGH",
                    "category": "new_package",
                    "message": f"Package is only {age.days} day(s) old",
                })
            elif age < timedelta(days=90):
                warnings.append({
                    "level": "MEDIUM",
                    "category": "young_package",
                    "message": f"Package is only {age.days} day(s) old",
                })
        except (ValueError, TypeError):
            pass
        return warnings

    def _check_version_anomalies(self, releases: dict) -> list:
        """Flag: version count drops (yanked), unusual version schemes."""
        warnings = []
        version_names = list(releases.keys())
        if not version_names:
            return warnings

        non_standard = []
        for v in version_names:
            if not re.match(r"^\d+(\.\d+){0,3}(\.?(a|b|rc|dev|post)\d*)?$", v):
                non_standard.append(v)

        if non_standard and len(non_standard) > len(version_names) * 0.3:
            warnings.append({
                "level": "LOW",
                "category": "unusual_versions",
                "message": f"{len(non_standard)} non-standard version(s): {', '.join(non_standard[:3])}",
            })

        yanked_count = 0
        for ver, files in releases.items():
            if files and any(f.get("yanked", False) for f in files):
                yanked_count += 1
        if yanked_count > len(version_names) * 0.5 and yanked_count > 2:
            warnings.append({
                "level": "HIGH",
                "category": "many_yanked",
                "message": f"{yanked_count}/{len(version_names)} versions are yanked",
            })

        return warnings

    def _check_npm_release_timing(self, version_times: dict) -> list:
        """Check npm release timing patterns."""
        warnings = []
        now = datetime.now(timezone.utc)

        parsed = []
        for ver, ts in version_times.items():
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                parsed.append((ver, dt))
            except (ValueError, TypeError):
                pass

        if not parsed:
            return warnings

        parsed.sort(key=lambda x: x[1])

        latest_ver, latest_time = parsed[-1]
        if (now - latest_time) < timedelta(hours=24):
            warnings.append({
                "level": "MEDIUM",
                "category": "fresh_release",
                "message": f"Latest release ({latest_ver}) is less than 24 hours old",
            })

        if len(parsed) >= 3:
            gaps = []
            for i in range(1, len(parsed)):
                gap = (parsed[i][1] - parsed[i - 1][1]).days
                gaps.append(gap)

            if len(gaps) >= 2:
                avg_gap = sum(gaps[:-1]) / len(gaps[:-1])
                last_gap = gaps[-1]
                if avg_gap > 180 and last_gap < 7:
                    warnings.append({
                        "level": "HIGH",
                        "category": "dormant_then_active",
                        "message": (
                            f"Package was dormant (avg {avg_gap:.0f} days between releases) "
                            f"then suddenly released {latest_ver} after only {last_gap} day(s)"
                        ),
                    })

        return warnings

    def check_sigstore(self, package: str, version: str) -> dict:
        """Check for Sigstore attestations on PyPI.
        Returns {'has_attestation': bool, 'message': str}."""
        url = f"https://pypi.org/integrity/{package}/{version}/"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 200:
                    return {
                        "has_attestation": True,
                        "message": f"Sigstore attestation found for {package}=={version}",
                    }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    "has_attestation": False,
                    "message": f"No Sigstore attestation for {package}=={version}",
                }
        except (urllib.error.URLError, OSError):
            pass
        return {
            "has_attestation": False,
            "message": f"Could not check Sigstore for {package}=={version} (endpoint unavailable)",
        }

    def report(self) -> bool:
        """Print warnings. Returns True if HIGH+ found."""
        if not self.warnings:
            print(f"  {c('No intelligence warnings', 'green')}")
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
