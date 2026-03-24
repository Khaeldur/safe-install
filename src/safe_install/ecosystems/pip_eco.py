"""Python/pip ecosystem adapter."""

import json
import os
import re
import subprocess
import sys

from .base import BaseEcosystem, c


class PipEcosystem(BaseEcosystem):
    name = "pip"
    maturity = "stable"
    languages = ["python"]

    @property
    def docker_image(self):
        return f"python:{sys.version_info.major}.{sys.version_info.minor}-slim"

    def resolve_deps(self, package):
        try:
            r = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--dry-run',
                 '--report', '-', package],
                capture_output=True, text=True, timeout=120)

            # Try JSON
            if r.returncode == 0:
                try:
                    report = json.loads(r.stdout)
                    return [{'name': i.get('metadata', {}).get('name', '?'),
                             'version': i.get('metadata', {}).get('version', '?'),
                             'direct': i.get('is_direct', False)}
                            for i in report.get('install', [])]
                except json.JSONDecodeError:
                    pass

            # Parse text
            output = r.stdout + r.stderr
            if not output.strip():
                r = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--dry-run', package],
                    capture_output=True, text=True, timeout=120)
                output = r.stdout + r.stderr

            deps, seen = [], set()
            for line in output.splitlines():
                m = re.search(r'Would install\s+(.*)', line)
                if m:
                    for pkg in m.group(1).split():
                        parts = pkg.rsplit('-', 1)
                        name = parts[0] if len(parts) == 2 else pkg
                        ver = parts[1] if len(parts) == 2 else '?'
                        if name.lower() not in seen:
                            seen.add(name.lower())
                            deps.append({'name': name, 'version': ver, 'direct': False})
                m = re.match(r'\s*Collecting\s+(\S+)', line)
                if m:
                    name = re.split(r'[><=!~\[]', m.group(1))[0]
                    if name.lower() not in seen:
                        seen.add(name.lower())
                        deps.append({'name': name, 'version': '?', 'direct': False})
                m = re.match(r'\s*Requirement already satisfied:\s+(\S+)\s.*\(([^)]+)\)', line)
                if m:
                    name = re.split(r'[><=!~\[]', m.group(1))[0]
                    if name.lower() not in seen:
                        seen.add(name.lower())
                        deps.append({'name': name, 'version': m.group(2), 'direct': False})
            return deps
        except Exception:
            return []

    def sandbox_install_script(self, package, output_dir="/install/out"):
        return f"""
set -e
mkdir -p {output_dir}
pip download --dest {output_dir} {package}
for f in {output_dir}/*.tar.gz {output_dir}/*.zip; do
    [ -f "$f" ] || continue
    pip wheel --no-deps --wheel-dir {output_dir} "$f" && rm "$f"
done
"""

    def local_install(self, artifact_dir, extra_args=None):
        extra_args = extra_args or []
        wheels = [os.path.join(artifact_dir, f)
                  for f in os.listdir(artifact_dir) if f.endswith('.whl')]
        if not wheels:
            return False
        r = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '--no-deps',
             '--no-build-isolation', '--force-reinstall'] + extra_args + wheels)
        return r.returncode == 0

    def check_binary_available(self, package):
        r = subprocess.run(
            [sys.executable, '-m', 'pip', 'download', '--only-binary', ':all:',
             '--no-deps', '--dry-run', package],
            capture_output=True, text=True, timeout=60)
        return r.returncode == 0

    def download_source(self, package, dest_dir):
        r = subprocess.run(
            [sys.executable, '-m', 'pip', 'download', '--no-deps',
             '--no-binary', ':all:', '-d', dest_dir, package],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            r = subprocess.run(
                [sys.executable, '-m', 'pip', 'download', '--no-deps',
                 '-d', dest_dir, package],
                capture_output=True, text=True, timeout=120)
        return r.returncode == 0

    def _direct_install(self, package, extra_args, wheel_only):
        cmd = [sys.executable, '-m', 'pip', 'install', package] + extra_args
        if wheel_only:
            cmd.extend(['--only-binary', ':all:'])
        return subprocess.run(cmd).returncode == 0
