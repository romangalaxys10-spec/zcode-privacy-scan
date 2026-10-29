---
description: Pre-send gate: scan a file or stdin payload for secrets and PII, redact, re-scan, only then proceed.
allowed-tools: Read, Bash, Write, Grep
argument-hint: [file or payload]
---
Invoke the `privacy-scan` skill with this input: **$ARGUMENTS**

- No arguments: ask what is about to be sent, then run
  `python3 skills/privacy-scan/scripts/scan_payload.py <file>` (or pipe stdin
  with `-`).
- With a file: scan it. CLEAN (exit 0) means the known patterns did not fire.
  REDACT (exit 20) means show each line:col finding, apply the suggested
  redaction to a copy, re-scan, and proceed only after the re-scan is clean.
