# Privacy Scan

The pre-send gate between your data and the model provider: it scans the exact
payload about to be transmitted for secrets and PII before a single byte
leaves.

## Why

Agents read env files, config, and database dumps into context, and every
byte of context can end up in an API call. One pasted .env is all it takes.
Privacy Scan makes the check a gate: scan the exact payload, redact, re-scan,
only then send.

## How it works

| Step | What happens |
|---|---|
| SCAN | file or stdin; API keys (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe), private key blocks, JWTs, credentialed connection strings, emails, phone numbers, national-ID shapes, .env content shapes |
| Verdict | CLEAN or REDACT with exact line:col, masked value, suggested redaction |
| RE-SCAN | redacted payload must come back clean before anything is transmitted |
| Self-test | `--selftest` runs built-in fixtures proving each pattern class fires |

## Install

**Option A: self-installable marketplace** (recommended)

1. Download or clone this repo anywhere.
2. In ZCode: Plugin Marketplace -> Add -> Add Plugin Marketplace.
3. Paste the folder path.
4. Install `privacy-scan`.

**Option B: manual copy**

Copy this directory into your workspace `plugins/` folder
(Example: `~/.zcode/workspace/default/plugins/privacy-scan/`) and restart
ZCode.

## Try it

```
/privacy-scan .env
```

Expected result: a findings list with line:col positions and redactions
(verdict REDACT, exit 20), or a clean line (exit 0) when nothing fired.

## Requirements

- Python 3 (stdlib only). No network access needed; the scanner is local.

## Honest limits

Regex detection is heuristic. A clean scan means the known patterns did not
fire, not that the payload is safe to publish. For high-stakes sends, eyeball
it too.

---

<p align="center">
  <a href="https://z.ai/subscribe?ic=R0K78RJKNW"><img alt="z.ai coding plans - 10% OFF coupon" src="https://img.shields.io/badge/z.ai%20coding%20plans-10%25%20OFF%20coupon-blueviolet" /></a>
  <a href="https://zcode.z.ai/invite/ALWM9JUA"><img alt="Try ZCode free" src="https://img.shields.io/badge/Try%20ZCode-free%20invite-0969da" /></a>
</p>

## License

MIT.
