#!/bin/bash
set -euo pipefail

DEP_PATTERNS=(
  "requirements*.txt"
  "setup.py"
  "setup.cfg"
  "pyproject.toml"
  "package.json"
  "package-lock.json"
  "Cargo.toml"
  "Cargo.lock"
  "go.mod"
  "go.sum"
  "Gemfile"
  "Gemfile.lock"
)

changed_files=""

if [ "${SCAN_ALL:-false}" = "true" ]; then
  for pattern in "${DEP_PATTERNS[@]}"; do
    while IFS= read -r f; do
      [ -f "$f" ] && changed_files="${changed_files}${f}"$'\n'
    done < <(find . -name "$pattern" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
  done
elif [ -n "${GITHUB_BASE_REF:-}" ]; then
  git fetch origin "$GITHUB_BASE_REF" --depth=1 2>/dev/null || true
  diff_output=$(git diff --name-only "origin/$GITHUB_BASE_REF"...HEAD 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || echo "")

  for file in $diff_output; do
    basename=$(basename "$file")
    for pattern in "${DEP_PATTERNS[@]}"; do
      # fnmatch-style check
      case "$basename" in
        $pattern) changed_files="${changed_files}${file}"$'\n' ;;
      esac
    done
  done
else
  # Not a PR — scan all dep files
  for pattern in "${DEP_PATTERNS[@]}"; do
    while IFS= read -r f; do
      [ -f "$f" ] && changed_files="${changed_files}${f}"$'\n'
    done < <(find . -name "$pattern" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
  done
fi

changed_files=$(echo "$changed_files" | sed '/^$/d' | sort -u)

if [ -z "$changed_files" ]; then
  echo "No dependency files changed."
  echo "CHANGED_FILES=" >> "$GITHUB_ENV"
else
  count=$(echo "$changed_files" | wc -l)
  echo "Found $count changed dependency file(s):"
  echo "$changed_files" | while read -r f; do echo "  - $f"; done

  # Multi-line env var
  {
    echo "CHANGED_FILES<<EOF"
    echo "$changed_files"
    echo "EOF"
  } >> "$GITHUB_ENV"
fi
