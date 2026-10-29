#!/usr/bin/env python3
"""scan_payload.py: pre-send gate that catches secrets and PII in a payload.

Python 3, stdlib only. Scan a file (or stdin with -) for:

  secrets
    aws-access-key       AKIA... (16 chars)
    openai-key           sk- / sk-proj-
    anthropic-key        sk-ant-
    github-token         ghp_/gho_/ghu_/ghs_/ghr_
    slack-token          xoxb/xoxp/xoxa/xoxr/xoxs
    stripe-key           sk_live_ / pk_live_
    jwt                  three eyJ... segments
    private-key-block    PEM private key header
    connection-string    user:pass@ inside db-style URLs

  PII and env shapes (reported as info, not secrets)
    email
    phone
    national-id          SSN / national-ID-shaped digit groups
    env-assignment       NAME_KEY/NAME_TOKEN/... = value

Output (human):
  CLEAN: no known patterns fired          (exit 0)
  label:line:col [pattern] masked -> hint (one per finding, exit 20)

Output (--json): one JSON object with the finding list.

Masking: the scanner reports a value with its middle masked and a short
prefix kept. Never print the raw value back into a transcript.

Exit codes: 0 = clean, 20 = findings, 2 = unreadable input, 1 = self-test
failure, 0 = self-test pass.

Usage:
  python3 scan_payload.py <file>
  cat <payload> | python3 scan_payload.py -
  python3 scan_payload.py <file> --json
  python3 scan_payload.py --selftest
"""

import argparse
import json
import re
import sys

# Built from parts so this file does not self-flag as containing a key block.
PK_PREFIX = "-----BEGIN "
PK_SUFFIX = " PRIVATE KEY-----"
PK_BLOCK = PK_PREFIX + "RSA" + PK_SUFFIX

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|pk)_live_[A-Za-z0-9]{16,}\b")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("private-key-block", re.compile(re.escape(PK_BLOCK))),
    ("connection-string-creds", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[A-Za-z0-9]+:[^@\s]{6,}@", re.IGNORECASE)),
]

PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"\b\+?\d[\d\s().-]{8,}\d\b")),
    ("national-id", re.compile(r"\b\d{2}[-\s]?\d{2}[-\s]?\d{2}[-\s]?\d{4}\b")),
    ("env-assignment", re.compile(
        r"^[A-Z0-9_]{2,}_(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\s*=\s*\S{4,}",
        re.M | re.IGNORECASE)),
]


def mask(value):
    """Keep a short prefix and tail, mask the middle. Short values full mask."""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]


def scan(text):
    """Return findings sorted by line then col. Each finding carries the
    pattern name, position, masked value, severity, and redaction hint."""
    findings = []
    for name, pat in SECRET_PATTERNS + PII_PATTERNS:
        is_secret = name in {n for n, _ in SECRET_PATTERNS}
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            col = m.start() - (text.rfind("\n", 0, m.start()) + 1) + 1
            findings.append({
                "pattern": name,
                "severity": "secret" if is_secret else "pii",
                "line": line,
                "col": col,
                "value": mask(m.group(0)),
                "suggestion": "mask the middle, keep a short prefix",
            })
    findings.sort(key=lambda f: (f["line"], f["col"], f["pattern"]))
    return findings


SELFTESTS = [
    ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
    ("openai-key", "sk-proj-AbC123xyz456AbC123xyz456"),
    ("anthropic-key", "sk-ant-api03-AbC123xyz456AbC123xyz456"),
    ("github-token", "ghp_AbC123xyz456AbC123xyz456"),
    ("slack-token", "xoxb-123456789-AbC123xyz456"),
    ("stripe-key", "sk_live_AbC123xyz456AbC1"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N0XgL0n3I9P"),
    ("private-key-block", PK_BLOCK),
    ("connection-string-creds", "postgres://admin:s3cretpw@db.example.com/x"),
    ("env-assignment", "STRIPE_SECRET_KEY=whsec_AbC123xyz456"),
    ("email", "jane.doe@example.com"),
    ("phone", "+1 (415) 555-2671"),
    ("national-id", "ID issued to 12-34-56-7890 holder"),
]


def selftest():
    """Fire every fixture; a missing class means the scanner is broken."""
    blob = "\n".join(f for _, f in SELFTESTS) + "\nplain text line\n"
    found = {f["pattern"] for f in scan(blob)}
    missing = [n for n, _ in SELFTESTS if n not in found]
    report = {
        "selftest": True,
        "pattern_classes": len(SELFTESTS),
        "fired": sorted(found & {n for n, _ in SELFTESTS}),
        "missing": missing,
        "ok": not missing,
    }
    print(json.dumps(report, indent=2))
    if missing:
        print("self-test FAILED: pattern classes that did not fire: %s"
              % ", ".join(missing), file=sys.stderr)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Scan a payload (file or stdin) for secrets and PII "
                    "before it is transmitted. Exit 0 clean, 20 findings.")
    ap.add_argument("file", nargs="?",
                    help="file to scan; '-' or omitted reads stdin")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    ap.add_argument("--selftest", action="store_true",
                    help="run built-in fixtures; prove each pattern class fires")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.file and args.file != "-":
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print("cannot read %s: %s" % (args.file, e), file=sys.stderr)
            return 2
        label = args.file
    else:
        text = sys.stdin.read()
        label = "<stdin>"

    findings = scan(text)
    if args.as_json:
        print(json.dumps({
            "file": label,
            "verdict": "REDACT" if findings else "CLEAN",
            "count": len(findings),
            "findings": findings,
        }, indent=2))
    else:
        if not findings:
            print("CLEAN: no known secret/PII patterns fired in %s." % label)
        for f in findings:
            print("%s:%d:%d [%s] %s (%s) -> %s"
                  % (label, f["line"], f["col"], f["pattern"], f["value"],
                     f["severity"], f["suggestion"]))
        if findings:
            print("REDACT: %d findings. Redact, re-scan, only then proceed."
                  % len(findings))
    return 20 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
