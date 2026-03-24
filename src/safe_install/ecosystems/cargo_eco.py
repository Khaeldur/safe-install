"""Rust/cargo ecosystem adapter.

Cargo supply chain attacks:
- rustdecimal (2022): Typosquat of rust_decimal, stole env vars via
  build.rs (Rust's equivalent of setup.py)
- crates.io has had multiple typosquatting campaigns

Cargo's attack surface:
- build.rs scripts run at compile time with full system access
- proc macros execute at compile time
- No sandboxing for build scripts
"""

import json
import os
import subprocess

from .base import BaseEcosystem, c


class CargoEcosystem(BaseEcosystem):
    name = "cargo"
    maturity = "experimental"
    docker_image = "rust:slim"
    languages = ["rust"]

    def resolve_deps(self, package):
        # cargo doesn't have a simple "resolve deps for a package" command
        # without a Cargo.toml. We check the crate's metadata.
        try:
            r = subprocess.run(
                ['cargo', 'search', '--limit', '1', package],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return []
            # Basic info only — full tree needs Cargo.toml context
            return [{'name': package, 'version': '?', 'direct': True}]
        except FileNotFoundError:
            print(f"  {c('[WARN]', 'yellow')} cargo not found")
            return []
        except Exception:
            return []

    def sandbox_install_script(self, package, output_dir="/install/out"):
        return f"""
set -e
mkdir -p {output_dir}
cd /tmp
cargo init --name testpkg
echo '{package} = "*"' >> Cargo.toml
cargo fetch
cp -r $CARGO_HOME/registry/cache/* {output_dir}/ 2>/dev/null || true
"""

    def local_install(self, artifact_dir, extra_args=None):
        print(f"  {c('[INFO]', 'blue')} Cargo crates downloaded to {artifact_dir}")
        print(f"  Add to your Cargo.toml and build from local registry cache")
        return True

    def check_binary_available(self, package):
        # Rust crates are always source — the question is whether they have build.rs
        # which is the equivalent of setup.py (arbitrary code execution at build time)
        return False  # Always conservative for Rust

    def download_source(self, package, dest_dir):
        try:
            r = subprocess.run(
                ['cargo', 'download', package, '-o', dest_dir],
                capture_output=True, text=True, timeout=120)
            return r.returncode == 0
        except Exception:
            return False

    def _direct_install(self, package, extra_args, wheel_only):
        cmd = ['cargo', 'install', package] + (extra_args or [])
        return subprocess.run(cmd).returncode == 0
