"""Simple tkinter settings window for safe-install."""

import os
import tkinter as tk
from tkinter import ttk, messagebox

_CONFIG_PATH = os.path.expanduser("~/.config/safe-install/config.toml")


def _read_config():
    """Read existing config as raw text."""
    if os.path.exists(_CONFIG_PATH):
        with open(_CONFIG_PATH, "r") as f:
            return f.read()
    return ""


def _parse_bool(text, key, default=True):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key) and "=" in line:
            val = line.split("=", 1)[1].strip().lower()
            return val == "true"
    return default


def _parse_int(text, key, default=0):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key) and "=" in line:
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                pass
    return default


def _parse_string(text, key, default=""):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key) and "=" in line:
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            return val
    return default


def open_settings(config=None):
    raw = _read_config()

    root = tk.Tk()
    root.title("Safe Install - Settings")
    root.geometry("480x520")
    root.resizable(False, False)

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=8, pady=8)

    # --- General tab ---
    general = ttk.Frame(notebook, padding=12)
    notebook.add(general, text="General")

    var_sandbox = tk.BooleanVar(value=_parse_bool(raw, "enabled", True))
    ttk.Checkbutton(general, text="Enable sandbox for installs", variable=var_sandbox).pack(anchor="w", pady=4)

    var_auto_confirm = tk.BooleanVar(value=_parse_bool(raw, "auto_confirm_clean", True))
    ttk.Checkbutton(general, text="Auto-confirm clean packages", variable=var_auto_confirm).pack(anchor="w", pady=4)

    ttk.Label(general, text="Poll interval (seconds):").pack(anchor="w", pady=(12, 0))
    var_poll = tk.IntVar(value=_parse_int(raw, "poll_interval_seconds", 2))
    ttk.Spinbox(general, from_=1, to=30, textvariable=var_poll, width=8).pack(anchor="w")

    ttk.Label(general, text="Notification level:").pack(anchor="w", pady=(12, 0))
    var_notif = tk.StringVar(value=_parse_string(raw, "notification_level", "MEDIUM"))
    combo = ttk.Combobox(general, textvariable=var_notif, values=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                         state="readonly", width=12)
    combo.pack(anchor="w")

    ttk.Label(general, text="Dedup window (seconds):").pack(anchor="w", pady=(12, 0))
    var_dedup = tk.IntVar(value=_parse_int(raw, "dedup_window_seconds", 300))
    ttk.Spinbox(general, from_=0, to=3600, textvariable=var_dedup, width=8).pack(anchor="w")

    # --- Ecosystems tab ---
    eco_frame = ttk.Frame(notebook, padding=12)
    notebook.add(eco_frame, text="Ecosystems")

    eco_vars = {}
    for eco in ["pip", "npm", "cargo", "go", "gem", "docker"]:
        var = tk.BooleanVar(value=True)
        eco_vars[eco] = var
        ttk.Checkbutton(eco_frame, text=f"Enable {eco}", variable=var).pack(anchor="w", pady=3)

    # --- Advanced tab ---
    advanced = ttk.Frame(notebook, padding=12)
    notebook.add(advanced, text="Advanced")

    var_typosquat = tk.BooleanVar(value=_parse_bool(raw, "enabled", True))
    ttk.Checkbutton(advanced, text="Typosquat detection", variable=var_typosquat).pack(anchor="w", pady=4)

    var_intel = tk.BooleanVar(value=_parse_bool(raw, "enabled", True))
    ttk.Checkbutton(advanced, text="Package intelligence", variable=var_intel).pack(anchor="w", pady=4)

    var_binary = tk.BooleanVar(value=_parse_bool(raw, "enabled", True))
    ttk.Checkbutton(advanced, text="Binary analysis", variable=var_binary).pack(anchor="w", pady=4)

    ttk.Label(advanced, text="Max edit distance for typosquat:").pack(anchor="w", pady=(12, 0))
    var_max_dist = tk.IntVar(value=_parse_int(raw, "max_distance", 2))
    ttk.Spinbox(advanced, from_=1, to=5, textvariable=var_max_dist, width=8).pack(anchor="w")

    ttk.Label(advanced, text="Config file:").pack(anchor="w", pady=(12, 0))
    ttk.Label(advanced, text=_CONFIG_PATH, foreground="gray").pack(anchor="w")

    # --- Buttons ---
    btn_frame = ttk.Frame(root, padding=8)
    btn_frame.pack(fill="x")

    def save():
        os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)

        lines = [
            "[sandbox]",
            f'enabled = {"true" if var_sandbox.get() else "false"}',
            "",
            "[wrapper]",
            f'auto_confirm_clean = {"true" if var_auto_confirm.get() else "false"}',
            "",
            "[tray]",
            f"poll_interval_seconds = {var_poll.get()}",
            f'notification_level = "{var_notif.get()}"',
            "",
            "[coordination]",
            f"dedup_window_seconds = {var_dedup.get()}",
            "",
            "[typosquat]",
            f'enabled = {"true" if var_typosquat.get() else "false"}',
            f"max_distance = {var_max_dist.get()}",
            "",
            "[intelligence]",
            f'enabled = {"true" if var_intel.get() else "false"}',
            "",
            "[binary_analysis]",
            f'enabled = {"true" if var_binary.get() else "false"}',
            "",
        ]

        # Ecosystems
        for eco, var in eco_vars.items():
            lines.append(f"[ecosystems.{eco}]")
            lines.append(f'enabled = {"true" if var.get() else "false"}')
            lines.append("")

        with open(_CONFIG_PATH, "w") as f:
            f.write("\n".join(lines))

        messagebox.showinfo("Saved", f"Settings saved to:\n{_CONFIG_PATH}")
        root.destroy()

    ttk.Button(btn_frame, text="Save", command=save).pack(side="right", padx=4)
    ttk.Button(btn_frame, text="Cancel", command=root.destroy).pack(side="right", padx=4)

    root.mainloop()


if __name__ == "__main__":
    open_settings()
