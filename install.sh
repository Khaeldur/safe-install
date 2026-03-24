#!/usr/bin/env bash
set -euo pipefail

# safe-install universal installer
# Usage: curl -sSL https://raw.githubusercontent.com/Khaeldur/safe-install/main/install.sh | bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

echo ""
echo -e "${BOLD}  safe-install installer${NC}"
echo -e "  Supply chain attack defense for pip, npm, cargo, go, gem, and Docker"
echo ""

# --- Detect OS ---
info "Detecting operating system..."
OS="unknown"
case "$(uname -s)" in
    Linux*)   OS="linux";;
    Darwin*)  OS="macos";;
    CYGWIN*|MINGW*|MSYS*) OS="windows";;
esac

if [ "$OS" = "unknown" ]; then
    if grep -qi microsoft /proc/version 2>/dev/null; then
        OS="wsl"
    fi
fi

ok "OS detected: ${BOLD}$OS${NC}"

# --- Check Python ---
info "Checking Python..."
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        if [ -n "$version" ]; then
            major=$(echo "$version" | cut -d. -f1)
            minor=$(echo "$version" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
                PYTHON="$cmd"
                break
            fi
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.9+ is required but not found. Install Python from https://www.python.org/downloads/"
fi

ok "Python found: ${BOLD}$($PYTHON --version)${NC} ($PYTHON)"

# --- Install safe-install ---
info "Installing safe-install via pip..."
if $PYTHON -m pip install safe-install 2>&1; then
    ok "safe-install installed successfully"
else
    warn "pip install failed, trying with --user flag..."
    $PYTHON -m pip install --user safe-install || fail "Installation failed. Try: pip install safe-install"
    ok "safe-install installed (user mode)"
fi

# --- Activate wrapper ---
info "Activating pip/npm wrapper..."
if safe-install activate 2>&1; then
    ok "Wrapper activated"
else
    warn "Wrapper activation skipped (run 'safe-install activate' manually)"
fi

# --- Check environment ---
echo ""
info "Checking your environment for exposed credentials..."
echo ""
safe-install check-env || true

# --- Optional tray app ---
echo ""
if [ "${SAFE_INSTALL_TRAY:-}" = "1" ] || [ "${1:-}" = "--tray" ]; then
    info "Installing tray app dependencies..."
    $PYTHON -m pip install "safe-install[tray]" || warn "Tray app dependencies failed to install"
    ok "Tray app ready"
fi

# --- Success ---
echo ""
echo -e "${GREEN}${BOLD}  Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo ""
echo -e "    ${BLUE}safe-install check-env${NC}          See what's exposed"
echo -e "    ${BLUE}safe-install install <pkg>${NC}      Install with protection"
echo -e "    ${BLUE}safe-install audit <pkg>${NC}        Audit before installing"
echo -e "    ${BLUE}safe-install scan ./${NC}             Scan local project"
echo ""
echo -e "  ${BOLD}Optional:${NC}"
echo -e "    ${BLUE}pip install safe-install[tray]${NC}  System tray app"
echo -e "    ${BLUE}safe-install activate${NC}           Wrap pip/npm commands"
echo ""
echo -e "  Docs: ${BLUE}https://github.com/Khaeldur/safe-install${NC}"
echo ""
