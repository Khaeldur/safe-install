"""Cross-platform desktop notifications."""

import platform
import subprocess


def notify(title, message, severity="info"):
    system = platform.system()

    try:
        if system == "Windows":
            _notify_windows(title, message)
        elif system == "Darwin":
            _notify_macos(title, message)
        elif system == "Linux":
            _notify_linux(title, message)
        else:
            _notify_fallback(title, message)
    except Exception:
        _notify_fallback(title, message)


def _notify_windows(title, message):
    # PowerShell toast notification
    ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
$template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>{title}</text>
      <text>{message}</text>
    </binding>
  </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Safe Install").Show($toast)
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, timeout=10,
        )
        return
    except Exception:
        pass

    # Fallback: msg command
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
    except Exception:
        _notify_fallback(title, message)


def _notify_macos(title, message):
    subprocess.run(
        ["osascript", "-e",
         f'display notification "{message}" with title "{title}"'],
        capture_output=True, timeout=10,
    )


def _notify_linux(title, message):
    subprocess.run(
        ["notify-send", title, message, "--app-name=Safe Install"],
        capture_output=True, timeout=10,
    )


def _notify_fallback(title, message):
    print(f"[{title}] {message}")
