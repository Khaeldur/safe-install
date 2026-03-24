# Ecosystem Support

This document provides an honest, per-ecosystem capability matrix for safe-install.

## Capability Matrix

| Capability | pip | npm | cargo | go | gem | docker |
|------------|:---:|:---:|:-----:|:--:|:---:|:------:|
| Resolve full dep tree | Yes | Partial | No | No | Partial | N/A |
| Fetch package source | Yes | Yes | No* | Partial | Yes | N/A |
| Build in Docker isolation | Yes | Yes | Plausible | Plausible | Plausible | N/A |
| Suppress install hooks/scripts | Yes | Yes | N/A | N/A | No | N/A |
| Local install from inert artifact | Yes | Yes | No | No | Partial | Yes |
| Source pattern scanning | Comprehensive | Comprehensive | Basic | Basic | Basic | Basic** |
| Overall maturity | **Strong** | **Strong** | **Experimental** | **Experimental** | **Experimental** | **Experimental** |

`*` cargo adapter calls `cargo download` which is not a standard cargo subcommand.
`**` Dockerfile scanning exists but is not wired into the install flow.

---

## pip (Strong)

### What works

- **Dependency resolution**: Uses `pip install --dry-run --report` (JSON output) with fallback to text parsing of `Collecting` / `Would install` lines. Returns full transitive tree with names and versions.
- **Source download**: `pip download --no-deps --no-binary :all:` to get sdists. Falls back to `pip download --no-deps` if no sdist available.
- **Docker sandbox**: Downloads and builds wheels inside container using `pip download` + `pip wheel`. Copies `.whl` files out via `docker cp`.
- **Local install**: `pip install --no-deps --no-build-isolation --force-reinstall *.whl`. This just unzips wheels; no code executes.
- **Binary-only mode**: `--only-binary :all:` flag to refuse source distributions entirely.
- **Source scanning**: Comprehensive Python pattern set covering setup.py, __init__.py, conftest.py with patterns for HTTP requests, subprocess calls, env access, file reads, dynamic execution, base64 obfuscation, native library loading, credential collection.
- **Direct install fallback**: Standard `pip install` with credential vault protection.

### Current limitations

- Dep resolution can time out for very large dependency trees (120s timeout).
- Source scanning is regex-based and bypassable by obfuscation.
- Binary analysis of compiled `.so`/`.dll` files in wheels is a stub.
- No integration with pip's `--require-hashes` for lockfile enforcement.

---

## npm (Strong)

### What works

- **Dependency resolution**: `npm view <package> dependencies --json`. Returns direct dependencies with version constraints.
- **Source download**: `npm pack <package>` to get tarball.
- **Docker sandbox**: Runs `npm pack` inside container, copies `.tgz` out.
- **Local install**: `npm install --ignore-scripts *.tgz`. The `--ignore-scripts` flag is critical; it prevents preinstall/postinstall hooks.
- **Script detection**: Checks for dangerous install scripts via `npm view <package> scripts --json`. Warns if preinstall/postinstall/install/prepare scripts exist.
- **Source scanning**: Comprehensive JavaScript pattern set covering child_process, fs reads, process.env, HTTP/fetch/axios, socket/net, eval/Function, WebSocket, crypto.

### Current limitations

- Dep resolution is shallow: only direct deps from `npm view`, not the full transitive tree. This means transitive dependencies are not individually audited.
- No `package-lock.json` parsing for more accurate resolution.
- `--ignore-scripts` prevents install hooks but does not prevent import-time execution.
- No support for scoped registries or private npm registries in the sandbox.

---

## cargo (Experimental)

### What works

- **Source scanning**: Basic Rust patterns for build.rs, lib.rs, main.rs covering Command execution, network connections, env/fs access.
- **Docker sandbox script**: Plausible `cargo fetch` approach, but untested against real crate builds.

### What does NOT work

- **Dependency resolution**: Calls `cargo search --limit 1` which only confirms the crate exists. Does not resolve transitive dependencies. Full resolution requires a Cargo.toml context.
- **Source download**: Calls `cargo download` which is NOT a standard cargo subcommand. This will fail silently.
- **Local install**: Prints a message directing the user to manual steps. Does not actually install anything.
- **Binary availability check**: Always returns False (conservative, but uninformative).

### What needs fixing

- Replace `cargo download` with a working approach (e.g., download `.crate` from crates.io API).
- Implement real dep resolution (parse Cargo.lock or use `cargo metadata`).
- Provide meaningful local install (copy to local registry cache or vendor directory).

---

## go (Experimental)

### What works

- **Dependency resolution**: `go list -m -json <package>@latest` returns the top-level module info (name + version).
- **Source scanning**: Basic Go patterns for exec.Command, net.Dial, os.Getenv, file reads.
- **Docker sandbox script**: Plausible `go mod download` approach.

### What does NOT work

- **Dep resolution depth**: Only resolves the top-level module. Transitive dependencies are not enumerated.
- **Local install**: Prints a message. Does not actually populate the local module cache.
- **Source download**: Depends on `go mod download -x` which requires a go.mod context.

### What needs fixing

- Use `go mod graph` or `go list -m all` for transitive dep resolution (requires go.mod).
- Provide actual local cache population from sandbox artifacts.

---

## gem (Experimental)

### What works

- **Dependency resolution**: `gem dependency <package> --remote` returns direct dependencies.
- **Source download**: `gem fetch <package>` downloads the .gem file.
- **Docker sandbox script**: `gem fetch` inside container, copies .gem out.
- **Local install**: `gem install --local *.gem`. This is functional.
- **Source scanning**: Basic Ruby patterns for system/exec, Net::HTTP, ENV access, File.read.

### What does NOT work

- **Dep resolution depth**: Only direct dependencies, not transitive.
- **Hook suppression**: `gem install --local` still executes `extconf.rb` for gems with native extensions. There is no equivalent of pip's `--no-build-isolation` or npm's `--ignore-scripts`.
- **Binary check**: Checks for `extensions` keyword in gem spec, but this is a rough heuristic.

### What needs fixing

- Local install of gems with native extensions still runs arbitrary code. This is a fundamental limitation of the gem ecosystem. The only real defense is the Docker sandbox.
- Transitive dep resolution needs `bundler` integration.

---

## docker (Experimental)

### What works

- **Image layer inspection**: `docker manifest inspect` returns layer info.
- **Dockerfile scanning**: `scan_dockerfile()` method checks for curl-to-shell, privileged mode, host mounts, docker socket access, world-writable permissions.
- **Local install**: `docker load -i image.tar` works.

### What does NOT work

- **Dockerfile scanning is not wired in**: `scan_dockerfile()` exists as a method but is never called from the install or audit flows.
- **Sandbox concept is incoherent**: The Docker ecosystem adapter tries to run `docker pull + save` inside a Docker container. This requires Docker-in-Docker (DinD) and is not how the sandbox is configured.
- **Dep resolution**: Returns image layers, not meaningful dependency information.

### What needs fixing

- Wire `scan_dockerfile()` into the audit flow.
- Rethink the sandbox approach for Docker images (DinD or skip sandboxing for this ecosystem).
- Consider integrating with `docker scout` or `trivy` for real vulnerability scanning.
