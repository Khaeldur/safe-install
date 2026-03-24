# safe-install installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/Khaeldur/safe-install/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  safe-install installer" -ForegroundColor White -NoNewline
Write-Host ""
Write-Host "  Supply chain attack defense for pip, npm, cargo, go, gem, and Docker"
Write-Host ""

# --- Check Python ---
Write-Info "Checking Python..."
$python = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -ge 3 -and $minor -ge 9) {
                $python = $cmd
                break
            }
        }
    } catch {
        continue
    }
}

if (-not $python) {
    Write-Fail "Python 3.9+ is required. Download from https://www.python.org/downloads/"
}

$pyVersion = & $python --version
Write-Ok "Python found: $pyVersion ($python)"

# --- Install safe-install ---
Write-Info "Installing safe-install via pip..."
try {
    & $python -m pip install safe-install
    if ($LASTEXITCODE -ne 0) { throw "pip failed" }
    Write-Ok "safe-install installed successfully"
} catch {
    Write-Warn "Trying with --user flag..."
    try {
        & $python -m pip install --user safe-install
        if ($LASTEXITCODE -ne 0) { throw "pip --user failed" }
        Write-Ok "safe-install installed (user mode)"
    } catch {
        Write-Fail "Installation failed. Try manually: pip install safe-install"
    }
}

# --- Activate wrapper ---
Write-Info "Activating pip/npm wrapper..."
try {
    & safe-install activate
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Wrapper activated"
    } else {
        Write-Warn "Wrapper activation skipped (run 'safe-install activate' manually)"
    }
} catch {
    Write-Warn "Wrapper activation skipped (run 'safe-install activate' manually)"
}

# --- Check environment ---
Write-Host ""
Write-Info "Checking your environment for exposed credentials..."
Write-Host ""
try {
    & safe-install check-env
} catch {
    # non-fatal
}

# --- Success ---
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host ""
Write-Host "    safe-install check-env        " -ForegroundColor Cyan -NoNewline
Write-Host "See what's exposed"
Write-Host "    safe-install install <pkg>    " -ForegroundColor Cyan -NoNewline
Write-Host "Install with protection"
Write-Host "    safe-install audit <pkg>      " -ForegroundColor Cyan -NoNewline
Write-Host "Audit before installing"
Write-Host "    safe-install scan .\           " -ForegroundColor Cyan -NoNewline
Write-Host "Scan local project"
Write-Host ""
Write-Host "  Optional:" -ForegroundColor White
Write-Host "    pip install safe-install[tray] " -ForegroundColor Cyan -NoNewline
Write-Host "System tray app"
Write-Host "    safe-install activate          " -ForegroundColor Cyan -NoNewline
Write-Host "Wrap pip/npm commands"
Write-Host ""
Write-Host "  Docs: https://github.com/Khaeldur/safe-install" -ForegroundColor Cyan
Write-Host ""
