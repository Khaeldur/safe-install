#!/bin/bash
set -euo pipefail

REPO="${GITHUB_REPOSITORY}"
MARKER="<!-- safe-install-report -->"

comment_body=$(python3 -c "
import json, glob, os

template_path = os.path.join(os.environ.get('GITHUB_ACTION_PATH', '.'), 'templates', 'pr-comment.md')

files = sorted(glob.glob('safe-install-reports/*.json'))
if not files:
    print('$MARKER\n## Safe Install Scan\n\nNo dependency files were scanned.')
    raise SystemExit(0)

total_findings = 0
total_packages = 0
overall_severity = 'CLEAN'
sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'CLEAN': 0}
file_rows = []
finding_rows = []
typosquat_rows = []

for f in files:
    try:
        data = json.load(open(f))
    except Exception:
        continue

    file_path = data.get('file', os.path.basename(f))
    eco = data.get('ecosystem', '?')
    sev = data.get('severity', 'CLEAN')
    pkgs = data.get('packages', [])
    pkg_count = len(pkgs)
    total_packages += pkg_count

    findings_in_file = sum(len(p.get('findings', [])) for p in pkgs)
    total_findings += findings_in_file

    if sev_rank.get(sev, 0) > sev_rank.get(overall_severity, 0):
        overall_severity = sev

    icon = {'CRITICAL': ':red_circle:', 'HIGH': ':orange_circle:', 'MEDIUM': ':yellow_circle:', 'LOW': ':white_circle:'}.get(sev, ':green_circle:')
    file_rows.append(f'| {icon} {sev} | \`{file_path}\` | {eco} | {pkg_count} | {findings_in_file} |')

    for pkg in pkgs:
        typo = pkg.get('typosquat', {})
        if typo.get('is_typosquat'):
            for w in typo.get('warnings', []):
                typosquat_rows.append(f\"| :warning: | \`{pkg.get('package','?')}\` | {w.get('popular','?')} | {w.get('reason','?')} |\")

        for finding in pkg.get('findings', []):
            fsev = finding.get('severity', 'LOW')
            ficon = {'CRITICAL': ':red_circle:', 'HIGH': ':orange_circle:', 'MEDIUM': ':yellow_circle:', 'LOW': ':white_circle:'}.get(fsev, ':white_circle:')
            desc = finding.get('description', 'N/A')[:100]
            finding_rows.append(f'| {ficon} {fsev} | \`{pkg.get(\"package\",\"?\")}\` | {desc} |')

status_icon = {'CRITICAL': ':red_circle:', 'HIGH': ':orange_circle:', 'MEDIUM': ':yellow_circle:', 'LOW': ':white_circle:'}.get(overall_severity, ':green_circle:')

lines = [
    '$MARKER',
    f'## {status_icon} Safe Install Scan',
    '',
    f'**Overall: {overall_severity}** | {total_packages} packages scanned | {total_findings} finding(s)',
    '',
    '### Files Scanned',
    '',
    '| Status | File | Ecosystem | Packages | Findings |',
    '|--------|------|-----------|----------|----------|',
]
lines.extend(file_rows)

if typosquat_rows:
    lines.extend([
        '',
        '### :warning: Typosquat Warnings',
        '',
        '| | Package | Did you mean? | Reason |',
        '|--|---------|---------------|--------|',
    ])
    lines.extend(typosquat_rows)

if finding_rows:
    lines.extend([
        '',
        '### Findings',
        '',
        '| Severity | Package | Description |',
        '|----------|---------|-------------|',
    ])
    lines.extend(finding_rows[:25])
    if len(finding_rows) > 25:
        lines.append(f'| | | *...and {len(finding_rows) - 25} more* |')

lines.extend([
    '',
    '---',
    '*Scanned by [safe-install](https://github.com/Khaeldur/safe-install)*',
])

print('\n'.join(lines))
")

# Find existing comment
existing_id=$(gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
  --jq ".[] | select(.body | contains(\"$MARKER\")) | .id" \
  2>/dev/null | head -1)

if [ -n "$existing_id" ]; then
  gh api "repos/${REPO}/issues/comments/${existing_id}" \
    --method PATCH \
    --field body="$comment_body" \
    > /dev/null
  echo "Updated existing PR comment #${existing_id}"
else
  gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    --method POST \
    --field body="$comment_body" \
    > /dev/null
  echo "Created new PR comment"
fi
