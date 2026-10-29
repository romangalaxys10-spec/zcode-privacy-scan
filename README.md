# Privacy Scan

A gate between your data and the model provider: scans any payload for secrets
and PII before it leaves the machine.

## Why

Agents read env files, config, and database dumps into context, and every byte
of context can end up in an API call. One pasted .env is all it takes. Privacy
Scan makes the check a habit: scan, redact, re-scan, only then send.

## How it works

| Step | What happens |
|------|--------------|
| Scan | File or stdin; API keys (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe), private key blocks, JWTs, credentialed connection strings, emails, phone numbers, .env shapes |
| Report | Exact line:column, pattern name, masked value, suggested redaction |
| Gate | Exit 0 clean, exit 20 findings; the skill refuses to proceed on 20 |
| Self-test | `--selftest` proves every pattern class fires on built-in fixtures |

## Install

1. Clone or download this repo to a folder.
2. In ZCode: Plugin Marketplace, Add, Add Plugin Marketplace, paste that folder path.
3. Install *Privacy Scan*.

## Try it

```
/privacy-scan .env
```

Expected: a findings list with line numbers and redactions, exit code 20.

## Honest limits

Regex detection is heuristic. A clean scan means the known patterns did not
fire, not that the payload is safe to publish. For high-stakes sends, eyeball
it too.


<p align="center">
  <a href="https://z.ai/subscribe?ic=R0K78RJKNW"><img alt="z.ai coding plans - 10% OFF coupon" src="https://img.shields.io/badge/z.ai%20coding%20plans-10%25%20OFF%20coupon-blueviolet" /></a>
  <a href="https://zcode.z.ai/invite/ALWM9JUA"><img alt="Try ZCode free" src="https://img.shields.io/badge/Try%20ZCode-free%20invite-0969da" /></a>
</p>


## License

MIT.
