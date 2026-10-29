---
description: Scan a file or stdin payload for secrets and PII before sending
allowed-tools: Read, Bash
argument-hint: [file]
---

Invoke the `privacy-scan` skill with this input: **$ARGUMENTS**

If $ARGUMENTS is empty, ask what the user wants and follow the skill.

Run `python3 skills/privacy-scan/scripts/scan_payload.py <file>` (or pipe
stdin). On findings, show each line:col with the suggested redaction, apply the
redaction, and RE-SCAN before proceeding. Exit 20 means findings exist.