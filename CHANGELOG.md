# Changelog

## 0.1.1 - 2026-10-30

- Added national-ID pattern class (13 total), argparse fix, richer selftest output.

## 0.1.0 - 2026-10-29

- Initial release: pre-send gate that scans files or stdin for API keys
  (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe), private key blocks,
  JWTs, credentialed connection strings, PII (emails, phones,
  national-ID-shaped numbers), and .env content shapes.
- Findings report exact line:col with masked values and suggested
  redactions; exit 0 clean, 20 findings.
- `--selftest` mode with built-in fixtures proving each pattern class
  fires; re-scan gate before anything is transmitted.
