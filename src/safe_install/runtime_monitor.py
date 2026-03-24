"""Gap 13: Runtime monitoring - monitor file/network access during execution."""

import os
import platform
import re
import shutil
import subprocess
import time
from .core import c, NetworkMonitor
from .config import get_sensitive_paths


class RuntimeMonitor:
    def __init__(self, config=None):
        self.config = config or {}
        rt = self.config.get("runtime", {})
        self.mode = rt.get("mode", "monitor")
        self.use_strace = rt.get("use_strace", True) and platform.system() == 'Linux'
        self.events = []
        self.sensitive_paths = [os.path.expanduser(p) for p in get_sensitive_paths(self.config)]

    def run_monitored(self, command):
        if self.use_strace and shutil.which('strace'):
            return self._run_strace(command)
        return self._run_polling(command)

    def _run_strace(self, command):
        cmd = ['strace', '-f', '-e', 'trace=openat,connect,execve', '-o', '/dev/stderr', '--'] + command
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            events = [self._classify(e) for e in self._parse_strace(r.stderr)]
            self.events = events
            return r.returncode, events
        except subprocess.TimeoutExpired:
            return 1, [{'type': 'timeout', 'severity': 'HIGH', 'message': 'Timed out (300s)'}]

    def _run_polling(self, command):
        before = {}
        for p in self.sensitive_paths:
            try:
                before[p] = os.stat(p).st_atime
            except OSError:
                pass

        net = NetworkMonitor(self.config)
        net.start()
        try:
            r = subprocess.run(command, timeout=300)
            code = r.returncode
        except Exception:
            code = 1
        suspicious = net.stop()

        events = []
        for p, old in before.items():
            try:
                if os.stat(p).st_atime != old:
                    events.append({'type': 'file_access', 'path': p,
                                   'severity': 'CRITICAL', 'message': f'Sensitive file accessed: {p}'})
            except OSError:
                pass
        for conn in suspicious:
            events.append({'type': 'network', 'severity': 'HIGH',
                           'message': f'Unexpected connection: {conn}'})
        self.events = events
        return code, events

    def _parse_strace(self, output):
        events = []
        for line in output.splitlines():
            m = re.search(r'openat\(.*?"([^"]+)"', line)
            if m:
                events.append({'type': 'file_open', 'path': m.group(1)})
                continue
            m = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', line)
            if m:
                events.append({'type': 'network_connect', 'ip': m.group(1)})
                continue
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                events.append({'type': 'exec', 'path': m.group(1)})
        return events

    def _classify(self, event):
        if event['type'] == 'file_open':
            for s in self.sensitive_paths:
                if event['path'].startswith(s):
                    return {**event, 'severity': 'CRITICAL',
                            'message': f'Sensitive file: {event["path"]}'}
            return {**event, 'severity': 'LOW', 'message': f'File: {event["path"]}'}
        if event['type'] == 'network_connect':
            return {**event, 'severity': 'HIGH', 'message': f'Connect: {event["ip"]}'}
        if event['type'] == 'exec':
            return {**event, 'severity': 'MEDIUM', 'message': f'Exec: {event["path"]}'}
        return {**event, 'severity': 'LOW', 'message': str(event)}

    def report(self):
        if not self.events:
            print(f"  {c('No suspicious runtime events', 'green')}")
            return False
        crit = [e for e in self.events if e.get('severity') == 'CRITICAL']
        high = [e for e in self.events if e.get('severity') == 'HIGH']
        if crit:
            print(f"\n  {c('[CRITICAL]', 'red')} -- {len(crit)} event(s):")
            for e in crit[:10]:
                print(f"    {e['message']}")
        if high:
            print(f"\n  {c('[HIGH]', 'red')} -- {len(high)} event(s):")
            for e in high[:10]:
                print(f"    {e['message']}")
        return len(crit) > 0
