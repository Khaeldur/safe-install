import os
import shutil
import subprocess
import sys

from ..core import c
from ..api import audit_package, log_finding, query_findings
from ..config import load_config

INSTALL_COMMANDS = {"install", "update", "add", "i"}

SEVERITY_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SEVERITY_COLORS = {
    "CLEAN": "green",
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "red",
}


def _find_real_binary(name):
    shim_dir = os.path.expanduser("~/.config/safe-install/shims")
    original_path = os.environ.get("PATH", "")
    cleaned = os.pathsep.join(
        p for p in original_path.split(os.pathsep)
        if os.path.normcase(os.path.normpath(p)) != os.path.normcase(os.path.normpath(shim_dir))
    )
    return shutil.which(name, path=cleaned)


def _extract_packages(args):
    packages = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in ("-r", "--requirement", "-e", "--editable", "-c", "--constraint",
                       "-i", "--index-url", "--extra-index-url", "-t", "--target",
                       "--prefix", "--root", "--src"):
                skip_next = True
            continue
        if arg.startswith("git+") or arg.startswith("http://") or arg.startswith("https://"):
            continue
        if os.path.exists(arg) or arg.endswith(".whl") or arg.endswith(".tar.gz"):
            continue
        name = arg.split("==")[0].split(">=")[0].split("<=")[0].split("!=")[0].split("~=")[0].split("[")[0]
        if name:
            packages.append(name)
    return packages


def _delegate(ecosystem, original_args):
    binary = _find_real_binary(ecosystem)
    if not binary:
        print(c(f"Error: could not find real {ecosystem}", "red"), file=sys.stderr)
        sys.exit(1)
    result = subprocess.run([binary] + original_args)
    sys.exit(result.returncode)


def main():
    if len(sys.argv) < 3:
        print(c("Usage: python -m safe_install.wrapper.intercept <ecosystem> <command> [args...]", "yellow"),
              file=sys.stderr)
        sys.exit(1)

    ecosystem = sys.argv[1]
    original_args = sys.argv[2:]
    command = original_args[0] if original_args else ""

    if command not in INSTALL_COMMANDS:
        _delegate(ecosystem, original_args)
        return

    config = load_config()
    has_force = "--force" in original_args or "-f" in original_args
    auto_mode = os.environ.get("SAFE_INSTALL_AUTO", "") == "1"

    install_args = original_args[1:]
    packages = _extract_packages(install_args)

    if not packages:
        _delegate(ecosystem, original_args)
        return

    print(c(f"safe-install: scanning {len(packages)} package(s)...", "cyan"))

    results = []
    max_severity = "CLEAN"

    for pkg in packages:
        existing = query_findings(package=pkg, since=3600, config=config)
        if existing:
            result = existing[0]
            dedup = True
        else:
            result = audit_package(pkg, ecosystem=ecosystem, config=config)
            dedup = result.get("_dedup", False)

        severity = result.get("severity", "CLEAN")
        color = SEVERITY_COLORS.get(severity, "reset")
        tag = " (cached)" if dedup else ""
        print(f"  {c(pkg, 'bold')}: {c(severity, color)}{tag}")

        if not dedup:
            log_finding({
                "package": pkg,
                "ecosystem": ecosystem,
                "severity": severity,
                "channel": "wrapper",
                "findings": result.get("findings", []),
                "typosquat": result.get("typosquat", {}),
            }, config=config)

        results.append(result)

        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = severity

    if max_severity in ("HIGH", "CRITICAL"):
        if has_force:
            print(c(f"WARNING: proceeding despite {max_severity} risk (--force)", "yellow"))
        else:
            print(c(f"BLOCKED: {max_severity} risk detected. Use --force to override.", "red"))
            sys.exit(1)
    elif max_severity == "MEDIUM":
        if not auto_mode:
            try:
                answer = input(c(f"MEDIUM risk detected. Proceed? [y/N] ", "yellow")).strip().lower()
                if answer not in ("y", "yes"):
                    print(c("Aborted.", "yellow"))
                    sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                print(c("\nAborted.", "yellow"))
                sys.exit(1)

    _delegate(ecosystem, original_args)


if __name__ == "__main__":
    main()
