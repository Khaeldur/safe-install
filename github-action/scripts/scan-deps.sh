#!/bin/bash
set -euo pipefail

mkdir -p safe-install-reports

if [ -z "${CHANGED_FILES:-}" ]; then
  echo "No dependency files to scan."
  echo "severity=CLEAN" >> "$GITHUB_OUTPUT"
  echo "findings_count=0" >> "$GITHUB_OUTPUT"
  echo "report_path=safe-install-reports/" >> "$GITHUB_OUTPUT"
  echo "sarif_path=" >> "$GITHUB_OUTPUT"
  exit 0
fi

overall_severity="CLEAN"
total_findings=0
declare -A sev_rank=( [CRITICAL]=4 [HIGH]=3 [MEDIUM]=2 [LOW]=1 [CLEAN]=0 )

while IFS= read -r dep_file; do
  [ -z "$dep_file" ] && continue
  [ ! -f "$dep_file" ] && continue

  echo "::group::Scanning $dep_file"

  # Auto-detect ecosystem unless explicitly set
  eco_flag=""
  if [ "${ECOSYSTEM:-auto}" != "auto" ]; then
    eco_flag="-e $ECOSYSTEM"
  fi

  report_name=$(echo "$dep_file" | tr '/' '_' | tr '.' '_')
  report_json="safe-install-reports/${report_name}.json"

  if safe-install api scan-deps "$dep_file" $eco_flag > "$report_json" 2>&1; then
    file_severity=$(python3 -c "import json,sys; d=json.load(open('$report_json')); print(d.get('severity','CLEAN'))" 2>/dev/null || echo "CLEAN")
    file_findings=$(python3 -c "
import json,sys
d=json.load(open('$report_json'))
count=sum(len(p.get('findings',[])) for p in d.get('packages',[]))
print(count)
" 2>/dev/null || echo "0")

    echo "  Severity: $file_severity, Findings: $file_findings"
    total_findings=$((total_findings + file_findings))

    cur=${sev_rank[$file_severity]:-0}
    best=${sev_rank[$overall_severity]:-0}
    if [ "$cur" -gt "$best" ]; then
      overall_severity="$file_severity"
    fi
  else
    echo "::warning::Failed to scan $dep_file"
  fi

  echo "::endgroup::"
done <<< "$CHANGED_FILES"

# Generate SARIF if requested
if echo "${REPORT_FORMATS:-json}" | grep -q "sarif"; then
  sarif_path="safe-install-reports/safe-install.sarif"
  python3 -c "
import json, glob, sys

runs = []
for f in glob.glob('safe-install-reports/*.json'):
    try:
        data = json.load(open(f))
    except Exception:
        continue
    results = []
    rules = []
    rule_ids = set()
    for pkg in data.get('packages', []):
        for finding in pkg.get('findings', []):
            rule_id = finding.get('rule', 'supply-chain-risk')
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    'id': rule_id,
                    'shortDescription': {'text': finding.get('rule', 'Supply chain risk')},
                    'defaultConfiguration': {
                        'level': {'CRITICAL':'error','HIGH':'error','MEDIUM':'warning','LOW':'note'}.get(finding.get('severity','LOW'), 'note')
                    }
                })
            results.append({
                'ruleId': rule_id,
                'level': {'CRITICAL':'error','HIGH':'error','MEDIUM':'warning','LOW':'note'}.get(finding.get('severity','LOW'), 'note'),
                'message': {'text': finding.get('description', 'Supply chain risk detected')},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': data.get('file', f)},
                        'region': {'startLine': pkg.get('line', 1)}
                    }
                }]
            })
    if results:
        runs.append({
            'tool': {'driver': {'name': 'safe-install', 'version': '1.0.0', 'rules': rules}},
            'results': results
        })

if not runs:
    runs = [{'tool': {'driver': {'name': 'safe-install', 'version': '1.0.0', 'rules': []}}, 'results': []}]

sarif = {'\$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json', 'version': '2.1.0', 'runs': runs}
json.dump(sarif, open('$sarif_path', 'w'), indent=2)
print(f'SARIF written: {len(runs)} run(s)')
" 2>/dev/null || echo "::warning::SARIF generation failed"
  echo "sarif_path=$sarif_path" >> "$GITHUB_OUTPUT"
else
  echo "sarif_path=" >> "$GITHUB_OUTPUT"
fi

echo "severity=$overall_severity" >> "$GITHUB_OUTPUT"
echo "findings_count=$total_findings" >> "$GITHUB_OUTPUT"
echo "report_path=safe-install-reports/" >> "$GITHUB_OUTPUT"

echo ""
echo "=== Scan Summary ==="
echo "  Overall severity: $overall_severity"
echo "  Total findings:   $total_findings"
