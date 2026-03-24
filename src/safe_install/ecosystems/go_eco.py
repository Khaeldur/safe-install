"""Go modules ecosystem adapter.

Go supply chain attacks:
- Go checksum database (sum.golang.org) provides some protection
- But init() functions in Go run automatically on import
- build constraints can hide malicious code for specific OS/arch
"""

import json
import os
import subprocess

from .base import BaseEcosystem, c


class GoEcosystem(BaseEcosystem):
    name = "go"
    maturity = "experimental"
    docker_image = "golang:1.22-alpine"
    languages = ["go"]

    def resolve_deps(self, package):
        try:
            r = subprocess.run(
                ['go', 'list', '-m', '-json', package + '@latest'],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                info = json.loads(r.stdout)
                return [{'name': info.get('Path', package),
                        'version': info.get('Version', '?'),
                        'direct': True}]
            return []
        except Exception:
            return []

    def sandbox_install_script(self, package, output_dir="/install/out"):
        return f"""
set -e
mkdir -p {output_dir}
cd /tmp
go mod init testmod
go get {package}@latest
cp -r $GOPATH/pkg/mod/cache/download/* {output_dir}/ 2>/dev/null || true
"""

    def local_install(self, artifact_dir, extra_args=None):
        print(f"  {c('[INFO]', 'blue')} Go module cache populated at {artifact_dir}")
        return True

    def check_binary_available(self, package):
        return False  # Go is always source-compiled

    def download_source(self, package, dest_dir):
        try:
            r = subprocess.run(
                ['go', 'mod', 'download', '-x', package + '@latest'],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, 'GOPATH': dest_dir})
            return r.returncode == 0
        except Exception:
            return False

    def _direct_install(self, package, extra_args, wheel_only):
        cmd = ['go', 'install', package + '@latest'] + (extra_args or [])
        return subprocess.run(cmd).returncode == 0
