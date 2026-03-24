# Simulated Attack Payloads

These are SIMULATED supply chain attack payloads for testing safe-install's detection capabilities.

They reproduce the PATTERNS used in real-world attacks but are completely harmless:
- All network destinations point to localhost/127.0.0.1/example.com
- No actual credentials are read or exfiltrated
- No system modifications occur

## Attack simulations

| Directory | Real attack | Pattern |
|-----------|------------|---------|
| litellm_sim | litellm 1.82.8 (PyPI) | Read SSH keys + AWS creds, base64 encode, POST to C2 |
| ua_parser_sim | ua-parser-js (npm) | child_process exec, fs.readFileSync on secrets, https exfil |
| event_stream_sim | event-stream (npm) | Obfuscated require, base64 payload, conditional execution |
| rustdecimal_sim | rust_decimal (crates.io) | build.rs reads env vars + files, TcpStream to C2 |
| typosquat_sim | Generic typosquat | Subtle DNS exfiltration via socket.getaddrinfo |

Each directory should trigger CRITICAL or HIGH findings when scanned by safe-install.
