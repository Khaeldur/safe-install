"""Gap 11: Filesystem snapshot - detect persistence attacks (crontab, .bashrc, systemd, etc.)."""

import hashlib
import os
import platform
import subprocess
from pathlib import Path
from .core import c


class FilesystemSnapshot:
    WATCH_PATHS = [
        "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
        "~/.config/systemd/user/",
        "~/.local/bin/",
        "~/.config/autostart/",
        # Windows
        "~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/",
    ]

    def __init__(self, config=None):
        self.config = config or {}
        extra = self.config.get("filesystem_monitor", {}).get("extra_watch_paths", [])
        self.watch_paths = list(self.WATCH_PATHS) + extra
        self.before = {}
        self.after = {}
        self.changes = []

    def snapshot_before(self) -> None:
        """Take pre-install snapshot."""
        self.before = self._take_snapshot()
        self._capture_cron_before()

    def snapshot_after(self) -> None:
        """Take post-install snapshot."""
        self.after = self._take_snapshot()

    def diff(self) -> list:
        """Compare snapshots. Returns list of changes."""
        self.changes = []
        all_paths = set(self.before.keys()) | set(self.after.keys())

        for path in sorted(all_paths):
            in_before = path in self.before
            in_after = path in self.after

            if in_after and not in_before:
                self.changes.append({
                    'type': 'created',
                    'path': path,
                    'severity': 'CRITICAL',
                    'detail': 'New file created during install',
                })
            elif in_before and not in_after:
                self.changes.append({
                    'type': 'deleted',
                    'path': path,
                    'severity': 'WARNING',
                    'detail': 'File deleted during install',
                })
            elif in_before and in_after:
                b = self.before[path]
                a = self.after[path]
                if b.get('hash') and a.get('hash') and b['hash'] != a['hash']:
                    self.changes.append({
                        'type': 'modified',
                        'path': path,
                        'severity': 'CRITICAL',
                        'detail': 'File content changed during install',
                    })
                elif b.get('mtime') != a.get('mtime'):
                    self.changes.append({
                        'type': 'touched',
                        'path': path,
                        'severity': 'WARNING',
                        'detail': 'File mtime changed during install',
                    })

        self.changes.extend(self._check_new_executables_in_path())
        self.changes.extend(self._check_cron_changes())
        return self.changes

    def _take_snapshot(self) -> dict:
        """Snapshot all watch paths. Returns {path: {mtime, size, hash}}."""
        snapshot = {}
        for wp in self.watch_paths:
            expanded = os.path.expanduser(wp)
            if os.path.isdir(expanded):
                snapshot.update(self._snapshot_directory(expanded))
            elif os.path.isfile(expanded):
                try:
                    st = os.stat(expanded)
                    snapshot[expanded] = {
                        'mtime': st.st_mtime,
                        'size': st.st_size,
                        'hash': self._hash_file(expanded),
                    }
                except OSError:
                    pass
        return snapshot

    def _hash_file(self, filepath: str) -> str:
        """SHA256 of file."""
        h = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
        except (OSError, IOError):
            return ""
        return h.hexdigest()

    def _snapshot_directory(self, dirpath: str) -> dict:
        """List all files with their mtime/size/hash."""
        result = {}
        try:
            for root, _dirs, files in os.walk(dirpath):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.stat(fpath)
                        result[fpath] = {
                            'mtime': st.st_mtime,
                            'size': st.st_size,
                            'hash': self._hash_file(fpath),
                        }
                    except OSError:
                        pass
        except OSError:
            pass
        return result

    def _check_new_executables_in_path(self) -> list:
        """Check PATH dirs for new executable files."""
        findings = []
        path_dirs = os.environ.get('PATH', '').split(os.pathsep)
        for d in path_dirs:
            if not os.path.isdir(d):
                continue
            before_files = set()
            after_files = set()
            for path, info in self.before.items():
                if path.startswith(d + os.sep):
                    before_files.add(path)
            for path, info in self.after.items():
                if path.startswith(d + os.sep):
                    after_files.add(path)
            new_files = after_files - before_files
            for f in new_files:
                if os.access(f, os.X_OK):
                    findings.append({
                        'type': 'new_executable',
                        'path': f,
                        'severity': 'CRITICAL',
                        'detail': f'New executable in PATH: {f}',
                    })
        return findings

    def _get_cron_cmd(self):
        if platform.system() == 'Windows':
            return ['schtasks', '/query', '/fo', 'CSV']
        return ['crontab', '-l']

    def _run_cron_cmd(self):
        try:
            r = subprocess.run(self._get_cron_cmd(), capture_output=True, text=True, timeout=10)
            output = r.stdout.strip()
            if platform.system() == 'Windows':
                # schtasks CSV includes volatile timestamps — extract only task names
                lines = output.splitlines()
                task_names = []
                for line in lines:
                    parts = line.split('","')
                    if parts:
                        task_names.append(parts[0].strip('"'))
                return '\n'.join(sorted(task_names))
            return output
        except (subprocess.SubprocessError, FileNotFoundError):
            return ""

    def _capture_cron_before(self):
        self._cron_before = self._run_cron_cmd()

    def _check_cron_changes(self) -> list:
        findings = []
        cron_after = self._run_cron_cmd()

        if self._cron_before != cron_after and cron_after:
            findings.append({
                'type': 'cron_changed',
                'path': 'crontab',
                'severity': 'CRITICAL',
                'detail': 'Scheduled tasks changed during install',
            })
        return findings

    def report(self) -> bool:
        """Print changes found. Returns True if suspicious."""
        if not self.changes:
            print(c("  [fs-snap] No filesystem changes detected.", "green"))
            return False

        has_suspicious = False
        for ch in self.changes:
            sev = ch['severity']
            if sev == 'CRITICAL':
                has_suspicious = True
                color = 'red'
            else:
                color = 'yellow'
            print(c(f"  [fs-snap] {sev}: {ch['type']} — {ch['path']}", color))
            print(c(f"            {ch['detail']}", 'dim'))
        return has_suspicious
