"""Programmatic API for safe-install — JSON-in/JSON-out interface.

All 5 distribution channels (wrapper, VS Code, tray, GitHub Action, Docker extension)
call these functions. Returns structured dicts instead of printing to stdout.
"""

import datetime
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path

from .config import load_config, get_sensitive_paths, get_sensitive_env_vars


def _get_findings_log_path(config=None):
    config = config or load_config()
    coord = config.get("coordination", {})
    path = coord.get("findings_log", "~/.config/safe-install/findings.jsonl")
    return os.path.expanduser(path)


def _get_dedup_window(config=None):
    config = config or load_config()
    return config.get("coordination", {}).get("dedup_window_seconds", 300)


# ---------------------------------------------------------------------------
# Core API Functions
# ---------------------------------------------------------------------------

def audit_package(package, ecosystem="pip", config=None):
    """Full audit of a package. Returns structured dict."""
    config = config or load_config()
    result = {
        "package": package,
        "ecosystem": ecosystem,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "severity": "CLEAN",
        "deps": [],
        "typosquat": {},
        "intelligence": [],
        "findings": [],
        "binary": {},
    }

    # Check dedup
    recent = query_findings(package=package, since=_get_dedup_window(config),
                            config=config)
    if recent:
        return {**recent[0], "_dedup": True, "_original_channel": recent[0].get("channel")}

    # Typosquat
    try:
        from .typosquat import TyposquatDetector
        detector = TyposquatDetector(config)
        typo_warnings = detector.check(package, ecosystem)
        result["typosquat"] = {
            "is_typosquat": len(typo_warnings) > 0,
            "warnings": typo_warnings,
        }
    except Exception:
        pass

    # Resolve deps
    try:
        from .ecosystems import ECOSYSTEMS
        eco_class = ECOSYSTEMS.get(ecosystem)
        if eco_class:
            eco = eco_class(config)
            deps = eco.resolve_deps(package)
            result["deps"] = deps or []
    except Exception:
        pass

    # Intelligence
    try:
        from .intelligence import PackageIntelligence
        intel = PackageIntelligence(config)
        warnings = intel.analyze(package, ecosystem)
        result["intelligence"] = warnings
    except Exception:
        pass

    # Source inspection
    try:
        from .core import SourceInspector
        from .ecosystems import ECOSYSTEMS
        eco_class = ECOSYSTEMS.get(ecosystem)
        if eco_class:
            eco = eco_class(config)
            inspector = SourceInspector(languages=eco.languages, config=config)
            with tempfile.TemporaryDirectory(prefix="safe_api_") as tmpdir:
                pkg_base = re.split(r'[><=!~\[]', package)[0].lower()
                seen = {pkg_base}
                packages_to_scan = [package]
                if result["deps"]:
                    for d in result["deps"][:10]:
                        if d["name"].lower() not in seen:
                            seen.add(d["name"].lower())
                            packages_to_scan.append(d["name"])
                for pkg in packages_to_scan:
                    pkg_dir = os.path.join(tmpdir, pkg.replace("/", "_").replace("@", "_"))
                    os.makedirs(pkg_dir, exist_ok=True)
                    if eco.download_source(pkg, pkg_dir):
                        for d in eco.extract_archives(pkg_dir):
                            inspector.scan_directory(d)
            result["findings"] = inspector.findings
    except Exception:
        pass

    # Binary check
    try:
        from .ecosystems import ECOSYSTEMS
        eco_class = ECOSYSTEMS.get(ecosystem)
        if eco_class:
            eco = eco_class(config)
            result["binary"] = {"available": eco.check_binary_available(package)}
    except Exception:
        pass

    # Determine overall severity
    severities = [f.get("severity", "LOW") for f in result["findings"]]
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if s in severities:
            result["severity"] = s
            break

    if result["typosquat"].get("is_typosquat"):
        if result["severity"] not in ("CRITICAL", "HIGH"):
            result["severity"] = "HIGH"

    for w in result.get("intelligence", []):
        if w.get("level") == "HIGH" and result["severity"] not in ("CRITICAL",):
            result["severity"] = "HIGH"

    # Log to findings.jsonl for dedup
    log_finding({
        "channel": "api",
        "package": package,
        "ecosystem": ecosystem,
        "severity": result["severity"],
        "findings_count": len(result["findings"]),
        "findings_summary": [f.get("pattern", "") for f in result["findings"][:5]],
    }, config)

    return result


def check_typosquat(package, ecosystem="pip", config=None):
    """Check for typosquatting. Returns dict."""
    config = config or load_config()
    try:
        from .typosquat import TyposquatDetector
        detector = TyposquatDetector(config)
        warnings = detector.check(package, ecosystem)
        return {
            "package": package,
            "is_typosquat": len(warnings) > 0,
            "warnings": warnings,
            "suggested": warnings[0]["popular"] if warnings else None,
        }
    except Exception as e:
        return {"package": package, "is_typosquat": False, "warnings": [], "error": str(e)}


def get_intelligence(package, ecosystem="pip", config=None):
    """Get package intelligence. Returns dict."""
    config = config or load_config()
    try:
        from .intelligence import PackageIntelligence
        intel = PackageIntelligence(config)
        warnings = intel.analyze(package, ecosystem)
        return {"package": package, "ecosystem": ecosystem, "warnings": warnings}
    except Exception as e:
        return {"package": package, "warnings": [], "error": str(e)}


def scan_deps_file(path, ecosystem=None, config=None):
    """Parse and audit a dependency file. Returns dict with per-package results."""
    config = config or load_config()
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return {"error": f"File not found: {path}", "packages": []}

    # Auto-detect ecosystem from filename
    basename = os.path.basename(path).lower()
    if ecosystem is None:
        if "requirements" in basename or basename == "setup.py":
            ecosystem = "pip"
        elif basename == "package.json":
            ecosystem = "npm"
        elif basename == "cargo.toml":
            ecosystem = "cargo"
        elif basename in ("go.mod", "go.sum"):
            ecosystem = "go"
        elif basename in ("gemfile", "gemfile.lock"):
            ecosystem = "gem"
        else:
            ecosystem = "pip"

    # Parse packages from file
    packages = _parse_deps_file(path, ecosystem)

    results = []
    for pkg in packages:
        result = audit_package(pkg["name"], ecosystem, config)
        result["line"] = pkg.get("line", 0)
        result["version_spec"] = pkg.get("version_spec", "")
        results.append(result)

    overall_severity = "CLEAN"
    for r in results:
        if r.get("severity") == "CRITICAL":
            overall_severity = "CRITICAL"
            break
        elif r.get("severity") == "HIGH" and overall_severity != "CRITICAL":
            overall_severity = "HIGH"
        elif r.get("severity") == "MEDIUM" and overall_severity not in ("CRITICAL", "HIGH"):
            overall_severity = "MEDIUM"

    return {
        "file": path,
        "ecosystem": ecosystem,
        "severity": overall_severity,
        "packages": results,
        "total": len(results),
    }


def _parse_deps_file(path, ecosystem):
    """Extract package names from dependency files."""
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return packages

    if ecosystem == "pip":
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = re.split(r"[><=!~\[;]", line)[0].strip()
            if name:
                packages.append({"name": name, "line": i, "version_spec": line})

    elif ecosystem == "npm":
        try:
            data = json.loads("".join(lines))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section, {})
                for name, ver in deps.items():
                    packages.append({"name": name, "line": 0, "version_spec": ver})
        except json.JSONDecodeError:
            pass

    elif ecosystem == "cargo":
        in_deps = False
        for i, line in enumerate(lines, 1):
            if line.strip() == "[dependencies]":
                in_deps = True
                continue
            if line.strip().startswith("[") and in_deps:
                in_deps = False
            if in_deps and "=" in line:
                name = line.split("=")[0].strip()
                if name:
                    packages.append({"name": name, "line": i, "version_spec": line.strip()})

    elif ecosystem == "go":
        for i, line in enumerate(lines, 1):
            parts = line.strip().split()
            if len(parts) >= 2 and "/" in parts[0]:
                packages.append({"name": parts[0], "line": i, "version_spec": parts[1] if len(parts) > 1 else ""})

    elif ecosystem == "gem":
        for i, line in enumerate(lines, 1):
            m = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line.strip())
            if m:
                packages.append({"name": m.group(1), "line": i, "version_spec": line.strip()})

    return packages


# ---------------------------------------------------------------------------
# Findings Log
# ---------------------------------------------------------------------------

def log_finding(finding, config=None):
    """Append a finding to the findings log."""
    config = config or load_config()
    log_path = _get_findings_log_path(config)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    entry = {
        "id": f"f_{int(time.time())}_{hashlib.md5(str(finding).encode()).hexdigest()[:8]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        **finding,
    }

    # Rotate if too large
    max_mb = config.get("coordination", {}).get("max_log_size_mb", 50)
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > max_mb * 1024 * 1024:
            backup = log_path + ".1"
            if os.path.exists(backup):
                os.remove(backup)
            os.rename(log_path, backup)
    except OSError:
        pass

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass

    return entry


def query_findings(package=None, since=None, channel=None, config=None):
    """Query findings log. 'since' is seconds ago (int) or ISO timestamp (str)."""
    config = config or load_config()
    log_path = _get_findings_log_path(config)

    if not os.path.exists(log_path):
        return []

    if isinstance(since, (int, float)):
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=since)
    elif isinstance(since, str):
        cutoff = datetime.datetime.fromisoformat(since)
    else:
        cutoff = None

    results = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if package and entry.get("package") != package:
                    continue
                if channel and entry.get("channel") != channel:
                    continue
                if cutoff:
                    ts = entry.get("timestamp", "")
                    try:
                        entry_time = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if entry_time < cutoff:
                            continue
                    except (ValueError, TypeError):
                        continue

                results.append(entry)
    except OSError:
        pass

    return results


def get_status(config=None):
    """Get current protection status."""
    config = config or load_config()
    log_path = _get_findings_log_path(config)

    # Count recent findings
    recent = query_findings(since=3600, config=config)  # last hour
    critical_count = sum(1 for f in recent if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in recent if f.get("severity") == "HIGH")

    # Check which channels have logged recently
    active_channels = set()
    for f in query_findings(since=86400, config=config):  # last 24h
        ch = f.get("channel")
        if ch:
            active_channels.add(ch)

    # Check wrapper status
    shim_dir = os.path.expanduser(
        config.get("wrapper", {}).get("shim_dir", "~/.config/safe-install/shims"))
    wrapper_active = os.path.isdir(shim_dir) and any(
        f.startswith("pip") for f in os.listdir(shim_dir)) if os.path.isdir(shim_dir) else False

    # Sensitive paths/vars exposure
    sensitive_files = sum(1 for p in get_sensitive_paths(config)
                         if os.path.exists(os.path.expanduser(p)))
    sensitive_vars = sum(1 for v in get_sensitive_env_vars(config)
                         if os.environ.get(v))

    return {
        "protected": wrapper_active or len(active_channels) > 0,
        "wrapper_active": wrapper_active,
        "active_channels": sorted(active_channels),
        "recent_scans_1h": len(recent),
        "critical_1h": critical_count,
        "high_1h": high_count,
        "exposed_files": sensitive_files,
        "exposed_vars": sensitive_vars,
        "config_path": str(Path.home() / ".config" / "safe-install" / "config.toml"),
        "findings_log": log_path,
    }
