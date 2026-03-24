"""Ruby/gem ecosystem adapter.

Gem supply chain attacks:
- rest-client (2019): Backdoor added by compromised maintainer account
- strong_password (2019): Backdoor added via stolen credentials
- bootstrap-sass (2019): Backdoor in official gem
- Native extensions (extconf.rb) run arbitrary code during install
"""

import json
import os
import subprocess

from .base import BaseEcosystem, c


class GemEcosystem(BaseEcosystem):
    name = "gem"
    docker_image = "ruby:3.2-slim"
    languages = ["ruby"]

    def resolve_deps(self, package):
        try:
            r = subprocess.run(
                ['gem', 'dependency', package, '--remote'],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return []
            deps = []
            for line in r.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith('Gem ') and line != package:
                    name = line.split('(')[0].strip()
                    if name:
                        deps.append({'name': name, 'version': '?', 'direct': True})
            return deps
        except Exception:
            return []

    def sandbox_install_script(self, package, output_dir="/install/out"):
        return f"""
set -e
mkdir -p {output_dir}
gem fetch {package}
mv *.gem {output_dir}/
"""

    def local_install(self, artifact_dir, extra_args=None):
        extra_args = extra_args or []
        gems = [os.path.join(artifact_dir, f)
                for f in os.listdir(artifact_dir) if f.endswith('.gem')]
        if not gems:
            return False
        for gem in gems:
            r = subprocess.run(['gem', 'install', '--local', gem] + extra_args)
            if r.returncode != 0:
                return False
        return True

    def check_binary_available(self, package):
        # Check if gem has native extensions
        try:
            r = subprocess.run(
                ['gem', 'specification', package, '--remote', '--marshal'],
                capture_output=True, text=True, timeout=30)
            # If it has extensions, it needs to compile (run extconf.rb)
            return 'extensions' not in r.stdout.lower()
        except Exception:
            return True

    def download_source(self, package, dest_dir):
        try:
            r = subprocess.run(
                ['gem', 'fetch', package],
                capture_output=True, text=True, timeout=120,
                cwd=dest_dir)
            return r.returncode == 0
        except Exception:
            return False

    def _direct_install(self, package, extra_args, wheel_only):
        cmd = ['gem', 'install', package] + (extra_args or [])
        return subprocess.run(cmd).returncode == 0
