"""npm ecosystem adapter.

npm supply chain attacks are even more common than pip:
- event-stream (2018): Backdoor targeting Bitcoin wallet Copay
- ua-parser-js (2021): Cryptominer + password stealer, 7M weekly downloads
- colors/faker (2022): Maintainer sabotage, infinite loop
- node-ipc (2022): Protestware, wiped files on Russian/Belarusian IPs
- @solana/web3.js (2024): Credential stealer in official Solana SDK

npm's attack surface is larger than pip because:
- preinstall/postinstall scripts run automatically
- Much deeper dependency trees (hundreds of transitive deps is common)
- No concept of wheels — every install can run arbitrary scripts
"""

import json
import os
import shutil
import subprocess

from .base import BaseEcosystem, c


class NpmEcosystem(BaseEcosystem):
    name = "npm"
    docker_image = "node:20-slim"
    languages = ["javascript"]

    def resolve_deps(self, package):
        try:
            r = subprocess.run(
                ['npm', 'view', package, 'dependencies', '--json'],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0 or not r.stdout.strip():
                return []
            deps_obj = json.loads(r.stdout)
            if isinstance(deps_obj, dict):
                return [{'name': k, 'version': v, 'direct': True}
                        for k, v in deps_obj.items()]
            return []
        except Exception:
            return []

    def sandbox_install_script(self, package, output_dir="/install/out"):
        # npm pack downloads the tarball without running scripts
        return f"""
set -e
mkdir -p {output_dir}
cd {output_dir}
npm pack {package} --pack-destination .
"""

    def local_install(self, artifact_dir, extra_args=None):
        extra_args = extra_args or []
        tarballs = [os.path.join(artifact_dir, f)
                    for f in os.listdir(artifact_dir) if f.endswith('.tgz')]
        if not tarballs:
            return False
        # --ignore-scripts is CRITICAL — prevents preinstall/postinstall
        cmd = ['npm', 'install', '--ignore-scripts'] + extra_args + tarballs
        return subprocess.run(cmd).returncode == 0

    def check_binary_available(self, package):
        # npm doesn't have a binary/source distinction like pip
        # But we can check if it has install scripts (the dangerous part)
        try:
            r = subprocess.run(
                ['npm', 'view', package, 'scripts', '--json'],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                scripts = json.loads(r.stdout)
                dangerous = {'preinstall', 'postinstall', 'install', 'prepare'}
                has_scripts = bool(dangerous & set(scripts.keys()))
                if has_scripts:
                    print(f"  {c('[WARN]', 'yellow')} Package has install scripts: "
                          f"{dangerous & set(scripts.keys())}")
                return not has_scripts
            return True
        except Exception:
            return True

    def download_source(self, package, dest_dir):
        try:
            r = subprocess.run(
                ['npm', 'pack', package, '--pack-destination', dest_dir],
                capture_output=True, text=True, timeout=120)
            return r.returncode == 0
        except Exception:
            return False

    def _direct_install(self, package, extra_args, wheel_only):
        cmd = ['npm', 'install', '--ignore-scripts', package] + extra_args
        return subprocess.run(cmd).returncode == 0
