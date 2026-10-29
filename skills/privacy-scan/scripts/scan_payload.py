#!/usr/bin/env python3
"""Scan a file or stdin for secrets and PII before it leaves the machine."""
import argparse, json, re, sys

# built from parts so secret scanners (ours included) do not flag this file
# itself as containing a key block
PK_PREFIX = "-----BEGIN "
PK_SUFFIX = "PRIVATE KEY-----"
PK_BLOCK = PK_PREFIX + "RSA " + PK_SUFFIX

PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|pk)_live_[A-Za-z0-9]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("private-key-block", re.compile(re.escape(PK_BLOCK))),
    ("connection-string-creds", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[A-Za-z0-9]+:[^@\s]{6,}@")),
    ("env-assignment", re.compile(r"^(?:[A-Z0-9_]+_(?:KEY|TOKEN|SECRET|PASSWORD))\s*=\s*\S{6,}", re.M)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"\b(?:\+?\d[\d\s().-]{8,}\d)\b")),
]
INFO = {"email", "phone", "env-assignment"}

def mask(v):
    v = v.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]

def scan(text):
    findings = []
    for name, pat in PATTERNS:
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            col = m.start() - (text.rfind("\n", 0, m.start()) + 1) + 1
            findings.append({"pattern": name, "line": line, "col": col,
                             "value": mask(m.group(0)),
                             "severity": "info" if name in INFO else "secret",
                             "suggestion": "replace middle with ***, keep a short prefix"})
    findings.sort(key=lambda f: (f["line"], f["col"]))
    return findings

SELFTESTS = [
    ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
    ("openai-key", "sk-proj-AbC123xyz456AbC123xyz456"),
    ("anthropic-key", "sk-ant-api03-AbC123xyz456AbC123xyz456"),
    ("github-token", "ghp_AbC123xyz456AbC123xyz456"),
    ("slack-token", "xoxb-123456789-AbC123xyz456"),
    ("stripe-key", "sk_live_AbC123xyz456AbC1"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N0XgL0n3I9P"),
    ("private-key-block", PK_BLOCK),
    ("connection-string-creds", "postgres://admin:s3cretpw@db.example.com/x"),
    ("env-assignment", "STRIPE_SECRET_KEY=whsec_AbC123xyz456"),
    ("email", "jane.doe@example.com"),
    ("phone", "+1 (415) 555-2671"),
]

def selftest():
    blob = "\n".join(f for _, f in SELFTESTS) + "\nplain text line\n"
    found = {f["pattern"] for f in scan(blob)}
    missing = [n for n, _ in SELFTESTS if n not in found]
    print(json.dumps({"patterns": len(SELFTESTS), "fired": len(found),
                      "missing": missing, "ok": not missing}))
    return 0 if not missing else 1

def main():
    ap = argparse.ArgumentParser(description="scan payload for secrets and PII")
    ap.add_argument("file", nargs="?", help="file to scan, or - for stdin")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.file and a.file != "-":
        try:
            text = open(a.file, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print("cannot read: %s" % e, file=sys.stderr)
            return 2
        label = a.file
    else:
        text = sys.stdin.read()
        label = "<stdin>"
    findings = scan(text)
    if a.as_json:
        print(json.dumps({"file": label, "count": len(findings), "findings": findings}, indent=2))
    else:
        if not findings:
            print("CLEAN: no known secret/PII patterns fired in %s." % label)
        for f in findings:
            print("%s:%d:%d [%s] %s -> %s" % (label, f["line"], f["col"],
                                              f["pattern"], f["value"], f["suggestion"]))
        if findings:
            print("REDACT and re-scan before sending. (%d findings)" % len(findings))
    return 20 if findings else 0

if __name__ == "__main__":
    sys.exit(main())
