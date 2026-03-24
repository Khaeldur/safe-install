"""Monitor OS processes for package manager install commands."""

import os
import platform
import re
import subprocess
import threading
import time


class ProcessMonitor:
    TARGETS = {
        "pip": "pip", "pip3": "pip", "pip.exe": "pip", "pip3.exe": "pip",
        "npm": "npm", "npm.cmd": "npm", "npx": "npm",
        "cargo": "cargo", "cargo.exe": "cargo",
        "go": "go", "go.exe": "go",
        "gem": "gem", "gem.cmd": "gem",
    }

    INSTALL_VERBS = {"install", "add", "i"}

    def __init__(self, on_detected, config=None):
        config = config or {}
        tray_cfg = config.get("tray", {})
        self.poll_interval = tray_cfg.get("poll_interval_seconds", 2)
        self.dedup_window = config.get("coordination", {}).get("dedup_window_seconds", 300)
        self.on_detected = on_detected
        self._stop_event = threading.Event()
        self._thread = None
        self._seen = {}  # (ecosystem, package) -> timestamp
        self._is_windows = platform.system() == "Windows"

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                procs = self._list_processes()
                for pid, cmdline in procs:
                    self._check_process(cmdline)
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval)

    def _list_processes(self):
        results = []
        try:
            if self._is_windows:
                out = subprocess.check_output(
                    ["tasklist", "/V", "/FO", "CSV"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=10,
                )
                for line in out.strip().splitlines()[1:]:
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        results.append((parts[1], line))

                # Also check via wmic for command lines
                out2 = subprocess.check_output(
                    ["wmic", "process", "get", "ProcessId,CommandLine", "/FORMAT:CSV"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=10,
                )
                for line in out2.strip().splitlines()[1:]:
                    parts = line.strip().split(",", 2)
                    if len(parts) >= 3:
                        results.append((parts[1], parts[2]))
            else:
                out = subprocess.check_output(
                    ["ps", "aux"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=10,
                )
                for line in out.strip().splitlines()[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        results.append((parts[1], parts[10]))
        except Exception:
            pass
        return results

    def _check_process(self, cmdline):
        parts = cmdline.split()
        if not parts:
            return

        for i, token in enumerate(parts):
            exe = os.path.basename(token.strip('"').strip("'"))
            ecosystem = self.TARGETS.get(exe)
            if not ecosystem:
                continue

            remaining = parts[i + 1:]
            if not remaining:
                continue

            verb = remaining[0].lower().strip("-")
            if verb not in self.INSTALL_VERBS:
                continue

            pkg = self._extract_package(remaining[1:], ecosystem)
            if not pkg:
                continue

            # Dedup
            key = (ecosystem, pkg)
            now = time.time()
            if key in self._seen and (now - self._seen[key]) < self.dedup_window:
                return
            self._seen[key] = now

            # Audit via API
            try:
                from safe_install.api import audit_package
                result = audit_package(pkg, ecosystem)
            except Exception:
                result = {
                    "package": pkg,
                    "ecosystem": ecosystem,
                    "severity": "CLEAN",
                    "findings": [],
                    "error": "audit unavailable",
                }

            self.on_detected(result)
            return

    def _extract_package(self, args, ecosystem):
        """Extract the package name from args after the install verb."""
        for arg in args:
            if arg.startswith("-"):
                continue
            # Strip version specifiers
            name = re.split(r"[><=!@~^]", arg)[0].strip()
            if name:
                return name
        return None
