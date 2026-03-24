#!/bin/bash
# Verify safe-install integrity by hashing installed package files.
#
# This script computes a SHA256 hash of all .py files in the installed
# safe_install package. It attempts to compare against a published hash
# from GitHub releases, but NOTE: release artifacts with SHA256SUMS do
# not yet exist. Until releases are established, this script only
# computes and displays the local hash for manual verification.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Khaeldur/safe-install/main/bootstrap_verify.sh | bash
#   # or: bash bootstrap_verify.sh

set -euo pipefail

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BOLD='\033[1m'
RESET='\033[0m'

HASH_URL="https://github.com/Khaeldur/safe-install/releases/latest/download/SHA256SUMS"

info()  { printf "${BOLD}%s${RESET}\n" "$*"; }
pass()  { printf "${GREEN}${BOLD}PASS${RESET} %s\n" "$*"; }
fail()  { printf "${RED}${BOLD}FAIL${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}${BOLD}WARN${RESET} %s\n" "$*"; }

info "=== safe-install bootstrap verification ==="
echo

# 1. Check if safe-install is installed
info "Checking installation..."
if ! pip show safe-install >/dev/null 2>&1; then
    fail "safe-install is not installed"
    echo "  Install with: pip install safe-install"
    exit 1
fi

PKG_DIR=$(python3 -c "from pathlib import Path; import safe_install; print(Path(safe_install.__file__).resolve().parent)")
if [ -z "$PKG_DIR" ] || [ ! -d "$PKG_DIR" ]; then
    fail "could not locate safe_install package directory"
    exit 1
fi
pass "safe-install found at $PKG_DIR"

# 2. Hash the installed package
info "Computing installed package hash..."
INSTALLED_HASH=$(python3 -c "
import hashlib, sys
from pathlib import Path

pkg = Path('$PKG_DIR')
py_files = sorted(pkg.rglob('*.py'))

h = hashlib.sha256()
for f in py_files:
    rel = f.relative_to(pkg).as_posix()
    h.update(rel.encode('utf-8'))
    h.update(f.read_bytes())

print(h.hexdigest())
")

if [ -z "$INSTALLED_HASH" ]; then
    fail "could not compute package hash"
    exit 1
fi
echo "  Installed hash: ${INSTALLED_HASH:0:16}..."

# 3. Attempt to download published hash (may not exist yet)
info "Fetching published hash from GitHub releases..."
HTTP_CODE=$(curl -sL -w "%{http_code}" -o /tmp/safe-install-sha256sums "$HASH_URL" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" != "200" ]; then
    warn "No published release hash available (HTTP $HTTP_CODE)"
    echo
    warn "Release artifacts with SHA256SUMS are not yet established."
    warn "This is expected for pre-release versions of safe-install."
    echo
    info "Your installed package hash (for manual comparison):"
    echo "  $INSTALLED_HASH"
    echo
    info "To verify manually:"
    echo "  1. Clone the repo: git clone https://github.com/Khaeldur/safe-install.git"
    echo "  2. Compare your installed files against the repo source"
    echo "  3. Or compare this hash with a trusted copy"
    exit 0
fi

PUBLISHED_HASH=$(grep -i "safe" /tmp/safe-install-sha256sums 2>/dev/null | awk '{print $1}')
if [ -z "$PUBLISHED_HASH" ]; then
    # Try single-line hash file
    PUBLISHED_HASH=$(head -1 /tmp/safe-install-sha256sums | awk '{print $1}')
fi
rm -f /tmp/safe-install-sha256sums

if [ -z "$PUBLISHED_HASH" ]; then
    fail "could not parse SHA256SUMS file"
    exit 1
fi
echo "  Published hash: ${PUBLISHED_HASH:0:16}..."

# 4. Compare
echo
if [ "$INSTALLED_HASH" = "$PUBLISHED_HASH" ]; then
    pass "safe-install integrity verified"
    exit 0
else
    fail "HASH MISMATCH - installed package may be tampered with"
    echo "  Installed: $INSTALLED_HASH"
    echo "  Published: $PUBLISHED_HASH"
    echo
    echo "  Recommended: pip install --force-reinstall safe-install"
    exit 1
fi
