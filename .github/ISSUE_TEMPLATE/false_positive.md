---
name: False Positive Report
about: Report a package incorrectly flagged as suspicious
title: "[FP] "
labels: false-positive
assignees: ''
---

## Package Details

- **Package name**:
- **Package version**:
- **Ecosystem**: (pip / npm / cargo / go / gem / docker)

## Finding That Was Flagged

Paste the safe-install output showing the finding. Include the full scan or audit output if possible.

```
<paste output here>
```

## Why This Is a False Positive

Explain why this finding is incorrect. For example:
- The flagged code is a legitimate use of networking/filesystem/subprocess
- The pattern matched a comment or string literal, not actual code
- The behavior is expected and documented for this package

## How to Verify

Steps a reviewer can take to confirm this is a false positive (e.g., link to the source code in question).
