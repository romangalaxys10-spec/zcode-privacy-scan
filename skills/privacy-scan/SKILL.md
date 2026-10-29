---
name: privacy-scan
description: Pre-send gate for outbound payloads. Use before any large file paste into a prompt, before reading an env file into context, and before sending data to an external API. Scans the exact payload or file, reports secrets and PII as line:col with suggested redactions, and blocks the send until the redacted version scans clean.
---

# Privacy Scan

Gate every outbound payload: scan the exact thing that is about to be
transmitted, redact, re-scan, only then send.

## Pattern classes

- API keys: AWS access keys, OpenAI `sk-`, Anthropic `sk-ant-`, GitHub
  `gh_`, Slack `xox`, Stripe `sk_live_`.
- Private key blocks (PEM `-----BEGIN ... PRIVATE KEY-----`).
- JWTs.
- Connection strings with credentials embedded in the URL.
- PII: emails, phone numbers, national-ID-shaped numbers.
- `.env` content shapes: `KEY/TOKEN/SECRET/PASSWORD` style assignments.

## Workflow

### 1. SCAN

Before any large file paste into a prompt, any env file read into context, or
any external API send, run the scanner on the exact payload or file that will
be sent:

```
python3 skills/privacy-scan/scripts/scan_payload.py <file>
cat <payload> | python3 skills/privacy-scan/scripts/scan_payload.py -
python3 skills/privacy-scan/scripts/scan_payload.py <file> --json
```

Exit 0 = CLEAN. Exit 20 = findings. Never scan a copy of the payload instead
of the payload: the gate is only as good as the exact bytes about to leave.

### 2. Verdict: CLEAN or REDACT

- CLEAN (exit 0): proceed. Note in the reply that the payload passed the
  known-pattern scan.
- REDACT (exit 20): for each finding show `file:line:col [pattern]`, the
  masked value, and the suggested redaction (mask the middle, keep a short
  prefix). Build the redacted payload from the original: apply each
  suggestion, never print the full secret back into the conversation.

### 3. RE-SCAN

Run the scanner on the redacted payload. Only an exit 0 clears the gate. If
findings remain, stop, list the remainder, and do not transmit. The original
user file is only modified when the user asked for in-place redaction;
otherwise redact a copy.

### 4. SELF-TEST

After any edit to the pattern list, run
`python3 skills/privacy-scan/scripts/scan_payload.py --selftest`. It loads
built-in fixtures, one per pattern class, and fails if any class stops
firing. A scanner that passes its self-test and then quietly misses one of
its own fixtures is broken, not conservative.

## Hard rules

- Never transmit a payload that has not come back exit 0 from the re-scan.
- Never print full secret values in the report; the scanner masks them and so
  should you.
- A clean scan means the known patterns did not fire. It is not proof the
  payload is safe to publish. Say that plainly when the user is about to send
  something unusually sensitive.

## Script

`scripts/scan_payload.py` (Python 3 stdlib): file or stdin input, human or
JSON output, exit 0 clean / 20 findings, and a `--selftest` mode.
