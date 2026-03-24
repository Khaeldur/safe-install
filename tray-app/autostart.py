"""Enable/disable auto-start on login for the safe-install tray app."""

import os
import platform
import sys

_APP_NAME = "SafeInstall"
_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))


def _startup_path_windows():
    startup = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
        f"{_APP_NAME}.vbs",
    )
    return startup


def _startup_path_macos():
    return os.path.expanduser(f"~/Library/LaunchAgents/com.safe-install.tray.plist")


def _startup_path_linux():
    return os.path.expanduser(f"~/.config/autostart/{_APP_NAME}.desktop")


def enable_autostart():
    system = platform.system()
    python = sys.executable

    if system == "Windows":
        path = _startup_path_windows()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # VBS script to launch without a console window
        content = (
            f'Set WshShell = CreateObject("WScript.Shell")\n'
            f'WshShell.Run """{python}"" ""{_SCRIPT}""", 0, False\n'
        )
        with open(path, "w") as f:
            f.write(content)

    elif system == "Darwin":
        path = _startup_path_macos()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.safe-install.tray</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{_SCRIPT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        with open(path, "w") as f:
            f.write(plist)

    elif system == "Linux":
        path = _startup_path_linux()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        desktop = f"""[Desktop Entry]
Type=Application
Name=Safe Install
Exec={python} {_SCRIPT}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=Supply chain attack defense
"""
        with open(path, "w") as f:
            f.write(desktop)


def disable_autostart():
    system = platform.system()

    if system == "Windows":
        path = _startup_path_windows()
    elif system == "Darwin":
        path = _startup_path_macos()
    elif system == "Linux":
        path = _startup_path_linux()
    else:
        return

    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def is_autostart_enabled():
    system = platform.system()

    if system == "Windows":
        return os.path.exists(_startup_path_windows())
    elif system == "Darwin":
        return os.path.exists(_startup_path_macos())
    elif system == "Linux":
        return os.path.exists(_startup_path_linux())
    return False
