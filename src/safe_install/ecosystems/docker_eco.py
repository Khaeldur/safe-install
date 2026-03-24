"""Docker image ecosystem adapter.

Docker supply chain attacks:
- Thousands of malicious images on Docker Hub with cryptominers
- Typosquatting of popular images (e.g., "ngnix" instead of "nginx")
- Dockerfile RUN commands can exfiltrate during build
- Multi-stage builds can hide malicious layers
- Base image poisoning (compromised upstream images)

Docker's unique risk: images run with access to the Docker socket,
host network, and potentially mounted volumes.
"""

import json
import os
import subprocess

from .base import BaseEcosystem, c


class DockerEcosystem(BaseEcosystem):
    name = "docker"
    docker_image = "docker:cli"
    languages = []  # Dockerfiles are their own thing

    def resolve_deps(self, image):
        """Inspect image layers and base images."""
        try:
            r = subprocess.run(
                ['docker', 'manifest', 'inspect', image],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                manifest = json.loads(r.stdout)
                layers = manifest.get('layers', [])
                return [{'name': f'layer-{i}',
                        'version': l.get('digest', '?')[:16],
                        'direct': i == 0}
                       for i, l in enumerate(layers)]
            return []
        except Exception:
            return []

    def sandbox_install_script(self, image, output_dir="/install/out"):
        # We pull and save the image as a tar
        return f"""
set -e
mkdir -p {output_dir}
docker pull {image}
docker save {image} -o {output_dir}/image.tar
"""

    def local_install(self, artifact_dir, extra_args=None):
        tar_path = os.path.join(artifact_dir, 'image.tar')
        if not os.path.exists(tar_path):
            return False
        r = subprocess.run(['docker', 'load', '-i', tar_path])
        return r.returncode == 0

    def check_binary_available(self, image):
        return True  # Docker images are always "binary"

    def scan_dockerfile(self, dockerfile_path):
        """Scan a Dockerfile for suspicious patterns."""
        suspicious = []
        try:
            with open(dockerfile_path) as f:
                content = f.read()
        except Exception:
            return suspicious

        # Dangerous patterns in Dockerfiles
        patterns = [
            (r'curl.*\|\s*(bash|sh)', 'Pipe curl to shell'),
            (r'wget.*\|\s*(bash|sh)', 'Pipe wget to shell'),
            (r'ADD\s+https?://', 'ADD from remote URL (prefer COPY)'),
            (r'--privileged', 'Privileged mode requested'),
            (r'-v\s+/:/|--volume\s+/:', 'Host root mount'),
            (r'docker\.sock', 'Docker socket access'),
            (r'--net[=\s]+host', 'Host network mode'),
            (r'--pid[=\s]+host', 'Host PID namespace'),
            (r'chmod\s+777', 'World-writable permissions'),
            (r'USER\s+root', 'Running as root'),
        ]

        import re
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                suspicious.append({
                    'line': line_num,
                    'pattern': desc,
                    'context': content.splitlines()[line_num - 1].strip(),
                })

        return suspicious

    def _direct_install(self, image, extra_args, wheel_only):
        cmd = ['docker', 'pull', image] + (extra_args or [])
        return subprocess.run(cmd).returncode == 0
