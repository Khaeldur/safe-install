<!-- safe-install-report -->
## {{ status_icon }} Safe Install Scan

**Overall: {{ severity }}** | {{ total_packages }} packages scanned | {{ total_findings }} finding(s)

### Files Scanned

| Status | File | Ecosystem | Packages | Findings |
|--------|------|-----------|----------|----------|
{{ file_rows }}

{% if typosquat_rows %}
### :warning: Typosquat Warnings

| | Package | Did you mean? | Reason |
|--|---------|---------------|--------|
{{ typosquat_rows }}
{% endif %}

{% if finding_rows %}
### Findings

| Severity | Package | Description |
|----------|---------|-------------|
{{ finding_rows }}
{% endif %}

---
*Scanned by [safe-install](https://github.com/Khaeldur/safe-install)*
