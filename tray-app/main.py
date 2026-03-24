#!/usr/bin/env python3
"""System tray app for safe-install — monitors package installs in real time."""

import os
import sys
import threading
import webbrowser

# Add safe-install src to path for imports
_src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if os.path.isdir(_src):
    sys.path.insert(0, _src)

try:
    from safe_install.config import load_config
    from safe_install.api import log_finding
except ImportError:
    def load_config():
        return {}
    def log_finding(f, config=None):
        return f

from process_monitor import ProcessMonitor
from notifier import notify
from autostart import is_autostart_enabled, enable_autostart, disable_autostart

# Try pystray + PIL for proper tray icon
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False

DASHBOARD_URL = "http://localhost:8899"

COLORS = {
    "clean": (76, 175, 80),
    "warning": (255, 193, 7),
    "critical": (244, 67, 54),
    "inactive": (158, 158, 158),
}


def _make_icon(color_name="clean", size=64):
    """Generate a colored shield icon, or a solid square as fallback."""
    color = COLORS.get(color_name, COLORS["clean"])
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape
    cx, cy = size // 2, size // 2
    top = int(size * 0.08)
    bottom = int(size * 0.92)
    mid_y = int(size * 0.55)
    left = int(size * 0.12)
    right = int(size * 0.88)

    points = [
        (cx, top),
        (right, int(size * 0.25)),
        (right, mid_y),
        (cx, bottom),
        (left, mid_y),
        (left, int(size * 0.25)),
    ]
    draw.polygon(points, fill=color)

    # Inner highlight
    inner_color = tuple(min(c + 40, 255) for c in color) + (120,)
    inner_points = [
        (cx, int(size * 0.18)),
        (int(size * 0.75), int(size * 0.32)),
        (int(size * 0.75), int(size * 0.50)),
        (cx, int(size * 0.78)),
        (int(size * 0.25), int(size * 0.50)),
        (int(size * 0.25), int(size * 0.32)),
    ]
    draw.polygon(inner_points, fill=inner_color)

    return img


class TrayApp:
    def __init__(self):
        self.config = load_config()
        self.active = True
        self.current_severity = "clean"
        self.monitor = None
        self.icon = None

    def on_detected(self, result):
        """Called by ProcessMonitor when a package install is detected."""
        severity = result.get("severity", "CLEAN")
        pkg = result.get("package", "unknown")
        eco = result.get("ecosystem", "?")

        result["channel"] = "tray"
        log_finding(result, self.config)

        if severity == "CRITICAL":
            self.current_severity = "critical"
            notify("CRITICAL: Supply Chain Risk",
                   f"{pkg} ({eco}) flagged as critical risk!", "critical")
        elif severity in ("HIGH", "MEDIUM"):
            if self.current_severity != "critical":
                self.current_severity = "warning"
            level = "warning" if severity == "HIGH" else "info"
            notify(f"{severity}: {pkg}",
                   f"{pkg} ({eco}) has {severity.lower()} risk findings.", level)
        else:
            notify(f"Scanned: {pkg}", f"{pkg} ({eco}) looks clean.", "info")

        self._update_icon()

    def _update_icon(self):
        if self.icon and HAS_PYSTRAY:
            color = self.current_severity if self.active else "inactive"
            self.icon.icon = _make_icon(color)

    def _toggle_protection(self, icon, item):
        self.active = not self.active
        if self.active:
            self.monitor.start()
        else:
            self.monitor.stop()
        self._update_icon()

    def _open_dashboard(self, icon, item):
        webbrowser.open(DASHBOARD_URL)

    def _open_settings(self, icon, item):
        try:
            from settings_ui import open_settings
            threading.Thread(target=open_settings, args=(self.config,), daemon=True).start()
        except Exception as e:
            notify("Settings Error", str(e), "warning")

    def _toggle_autostart(self, icon, item):
        if is_autostart_enabled():
            disable_autostart()
            notify("Safe Install", "Removed from startup.", "info")
        else:
            enable_autostart()
            notify("Safe Install", "Added to startup.", "info")

    def _quit(self, icon, item):
        if self.monitor:
            self.monitor.stop()
        icon.stop()

    def run(self):
        self.monitor = ProcessMonitor(
            on_detected=self.on_detected,
            config=self.config,
        )

        if not HAS_PYSTRAY:
            print("ERROR: pystray and Pillow are required for the tray app.")
            print("Install them with: pip install pystray Pillow")
            print()
            print("Running in headless mode (monitor only)...")
            self.monitor.start()
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                self.monitor.stop()
            return

        self.monitor.start()

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: "Protection: ON" if self.active else "Protection: OFF",
                self._toggle_protection,
            ),
            pystray.MenuItem("View Findings", self._open_dashboard),
            pystray.MenuItem("Settings", self._open_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Start on Login",
                self._toggle_autostart,
                checked=lambda item: is_autostart_enabled(),
            ),
            pystray.MenuItem("Quit", self._quit),
        )

        self.icon = pystray.Icon(
            "safe-install",
            _make_icon("clean"),
            "Safe Install",
            menu,
        )

        notify("Safe Install", "Protection active. Monitoring package installs.", "info")
        self.icon.run()


if __name__ == "__main__":
    app = TrayApp()
    app.run()
