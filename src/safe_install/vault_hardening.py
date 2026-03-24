"""Gap 12: Vault hardening - detect lingering processes and post-unlock credential access."""

import os
import platform
import subprocess
import time
from .core import c


class VaultHardening:
    def __init__(self, config=None):
        self.config = config or {}
        cfg = self.config.get("vault_hardening", {})
        self.cooldown = cfg.get("cooldown", 5)
        self.auto_kill = cfg.get("kill_suspicious", False)
        self.pre_pids = set()
        self.suspicious_procs = []

    def record_pre_install_processes(self):
        self.pre_pids = self._get_pids()

    def check_suspicious_processes(self):
        new_pids = self._get_pids() - self.pre_pids
        self.suspicious_procs = []
        for pid in new_pids:
            info = self._get_process_info(pid)
            if info:
                self.suspicious_procs.append(info)
        return self.suspicious_procs

    def _get_pids(self):
        try:
            if platform.system() == 'Windows':
                r = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                                   capture_output=True, text=True, timeout=10)
                pids = set()
                for line in r.stdout.splitlines():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        try:
                            pids.add(int(parts[1].strip('"')))
                        except ValueError:
                            pass
                return pids
            else:
                r = subprocess.run(['ps', '-eo', 'pid', '--no-headers'],
                                   capture_output=True, text=True, timeout=10)
                return {int(l.strip()) for l in r.stdout.splitlines() if l.strip().isdigit()}
        except Exception:
            return set()

    def _get_process_info(self, pid):
        try:
            if platform.system() == 'Windows':
                r = subprocess.run(
                    ['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV', '/NH'],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        return {'pid': pid, 'name': parts[0].strip('"'), 'cmdline': ''}
            else:
                r = subprocess.run(['ps', '-p', str(pid), '-o', 'comm=,args='],
                                   capture_output=True, text=True, timeout=5)
                if r.stdout.strip():
                    parts = r.stdout.strip().split(None, 1)
                    return {'pid': pid, 'name': parts[0],
                            'cmdline': parts[1] if len(parts) > 1 else ''}
        except Exception:
            pass
        return None

    def kill_suspicious(self):
        if not self.auto_kill or not self.suspicious_procs:
            return 0
        killed = 0
        for proc in self.suspicious_procs:
            try:
                os.kill(proc['pid'], 9)
                killed += 1
            except Exception:
                pass
        return killed

    def post_unlock_monitor(self, sensitive_paths, duration=None):
        duration = duration or self.cooldown
        if duration <= 0:
            return []

        before = {}
        for p in sensitive_paths:
            ep = os.path.expanduser(p)
            try:
                before[ep] = os.stat(ep).st_atime
            except OSError:
                pass

        events = []
        end = time.time() + duration
        while time.time() < end:
            for path, old_at in before.items():
                try:
                    new_at = os.stat(path).st_atime
                    if new_at != old_at:
                        events.append({'path': path, 'event': 'accessed', 'time': time.time()})
                        before[path] = new_at
                except OSError:
                    pass
            time.sleep(0.5)
        return events

    def report(self):
        if not self.suspicious_procs:
            return False
        print(f"\n  {c('[WARN]', 'yellow')} {len(self.suspicious_procs)} new process(es) during install:")
        for p in self.suspicious_procs[:10]:
            print(f"    PID {p['pid']}: {p['name']} {p.get('cmdline', '')[:80]}")
        return True
