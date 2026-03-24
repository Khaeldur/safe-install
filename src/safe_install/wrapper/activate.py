import os
import platform
import stat
import subprocess
import sys
from pathlib import Path

from ..core import c

MARKER_START = "# >>> safe-install wrapper >>>"
MARKER_END = "# <<< safe-install wrapper <<<"

PIP_SHIM_UNIX = """\
#!/bin/sh
SHIM_DIR="$HOME/.config/safe-install/shims"
case "$1" in
  install|update|add)
    python3 -m safe_install.wrapper.intercept pip "$@"
    ;;
  *)
    REAL_PIP="$(PATH="$(echo "$PATH" | sed "s|$SHIM_DIR:||g")" which pip)"
    exec "$REAL_PIP" "$@"
    ;;
esac
"""

NPM_SHIM_UNIX = """\
#!/bin/sh
SHIM_DIR="$HOME/.config/safe-install/shims"
case "$1" in
  install|update|add)
    python3 -m safe_install.wrapper.intercept npm "$@"
    ;;
  *)
    REAL_NPM="$(PATH="$(echo "$PATH" | sed "s|$SHIM_DIR:||g")" which npm)"
    exec "$REAL_NPM" "$@"
    ;;
esac
"""

PIP_SHIM_WINDOWS = """\
@echo off
if "%1"=="install" (
    python -m safe_install.wrapper.intercept pip %*
) else (
    set "SAFE_ORIG_PATH=%PATH%"
    set "PATH=%PATH:C:\\Users\\%USERNAME%\\.config\\safe-install\\shims;=%"
    pip %*
    set "PATH=%SAFE_ORIG_PATH%"
)
"""

NPM_SHIM_WINDOWS = """\
@echo off
if "%1"=="install" (
    python -m safe_install.wrapper.intercept npm %*
) else (
    set "SAFE_ORIG_PATH=%PATH%"
    set "PATH=%PATH:C:\\Users\\%USERNAME%\\.config\\safe-install\\shims;=%"
    npm %*
    set "PATH=%SAFE_ORIG_PATH%"
)
"""


def _get_shim_dir(config):
    base = config.get("wrapper", {}).get("shim_dir", "~/.config/safe-install/shims")
    return os.path.expanduser(base)


def _write_unix_shim(shim_dir, name, ecosystem):
    shim_path = os.path.join(shim_dir, name)
    content = PIP_SHIM_UNIX if ecosystem == "pip" else NPM_SHIM_UNIX
    with open(shim_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.chmod(shim_path, os.stat(shim_path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _write_windows_shim(shim_dir, name, ecosystem):
    shim_path = os.path.join(shim_dir, name + ".cmd")
    content = PIP_SHIM_WINDOWS if ecosystem == "pip" else NPM_SHIM_WINDOWS
    with open(shim_path, "w", encoding="utf-8") as f:
        f.write(content)


def _update_shell_profiles(shim_dir, add=True):
    home = Path.home()
    profiles = [home / ".bashrc", home / ".zshrc", home / ".profile"]
    block = f'{MARKER_START}\nexport PATH="$HOME/.config/safe-install/shims:$PATH"\n{MARKER_END}\n'

    for profile in profiles:
        if not profile.exists() and add:
            continue
        if not profile.exists():
            continue

        content = profile.read_text(encoding="utf-8", errors="replace")

        if add:
            if MARKER_START in content:
                continue
            with open(profile, "a", encoding="utf-8") as f:
                f.write("\n" + block)
            print(c(f"  Updated {profile}", "green"))
        else:
            if MARKER_START not in content:
                continue
            lines = content.splitlines(keepends=True)
            new_lines = []
            skip = False
            for line in lines:
                if MARKER_START in line:
                    skip = True
                    continue
                if MARKER_END in line:
                    skip = False
                    continue
                if not skip:
                    new_lines.append(line)
            profile.write_text("".join(new_lines), encoding="utf-8")
            print(c(f"  Cleaned {profile}", "yellow"))


def _update_windows_path(shim_dir, add=True):
    try:
        result = subprocess.run(
            ["reg", "query", "HKCU\\Environment", "/v", "Path"],
            capture_output=True, text=True, timeout=10,
        )
        current = ""
        for line in result.stdout.splitlines():
            if "Path" in line and "REG_" in line:
                current = line.split("    ")[-1].strip()
                break
    except Exception:
        current = ""

    shim_dir_norm = os.path.normpath(shim_dir)

    if add:
        if shim_dir_norm.lower() in current.lower():
            return
        new_path = shim_dir_norm + ";" + current if current else shim_dir_norm
        subprocess.run(
            ["setx", "Path", new_path],
            capture_output=True, text=True, timeout=10,
        )
        print(c(f"  Added to Windows User PATH", "green"))
    else:
        parts = [p for p in current.split(";") if p.strip().lower() != shim_dir_norm.lower()]
        new_path = ";".join(parts)
        subprocess.run(
            ["setx", "Path", new_path],
            capture_output=True, text=True, timeout=10,
        )
        print(c(f"  Removed from Windows User PATH", "yellow"))


def activate_wrapper(config, pip=True, npm=True):
    shim_dir = _get_shim_dir(config)
    os.makedirs(shim_dir, exist_ok=True)
    is_windows = platform.system() == "Windows"

    print(c("Activating safe-install wrapper...", "bold"))

    if pip:
        if is_windows:
            _write_windows_shim(shim_dir, "pip", "pip")
            _write_windows_shim(shim_dir, "pip3", "pip")
        else:
            _write_unix_shim(shim_dir, "pip", "pip")
            _write_unix_shim(shim_dir, "pip3", "pip")
        print(c("  pip shim installed", "green"))

    if npm:
        if is_windows:
            _write_windows_shim(shim_dir, "npm", "npm")
        else:
            _write_unix_shim(shim_dir, "npm", "npm")
        print(c("  npm shim installed", "green"))

    if is_windows:
        _update_windows_path(shim_dir, add=True)
    else:
        _update_shell_profiles(shim_dir, add=True)

    print(c("Wrapper active. Restart your shell or run: source ~/.bashrc", "cyan"))


def deactivate_wrapper(config):
    shim_dir = _get_shim_dir(config)
    is_windows = platform.system() == "Windows"

    print(c("Deactivating safe-install wrapper...", "bold"))

    if is_windows:
        _update_windows_path(shim_dir, add=False)
    else:
        _update_shell_profiles(shim_dir, add=False)

    if os.path.isdir(shim_dir):
        import shutil
        shutil.rmtree(shim_dir, ignore_errors=True)
        print(c(f"  Removed {shim_dir}", "yellow"))

    print(c("Wrapper deactivated.", "cyan"))
