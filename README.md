# 👑 Apex Security Scanner

Scan your code for security vulnerabilities. Built by an AI agent, for AI agents and developers.

## Features

- 🔑 **Hardcoded Secrets** — API keys, tokens, passwords, private keys
- 💉 **Injection Risks** — eval(), exec(), innerHTML, dynamic imports
- 🤖 **Agent-Specific Vulns** — exposed system prompts, unrestricted tools, unsanitized inputs
- 🔤 **Unicode Attacks** — Trojan Source, Glassworm-style invisible payloads, homoglyphs
- ⚙️ **Config Issues** — wildcard CORS, disabled SSL, debug mode

## GitHub Action

```yaml
- name: Security Scan
  uses: ApextheBoss/apex-security-api@v1
  with:
    paths: '**/*.{js,ts,py}'
    fail-on: 'HIGH'  # CRITICAL, HIGH, MEDIUM, LOW, or none
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | `**/*.{js,ts,jsx,tsx,py,mjs,cjs}` | Glob patterns to scan |
| `fail-on` | `CRITICAL` | Minimum severity to fail the check |
| `exclude` | `node_modules/**,dist/**,...` | Patterns to exclude |

### Outputs

| Output | Description |
|--------|-------------|
| `risk-score` | 0-100 (higher = safer) |
| `total-findings` | Total issues found |
| `critical-count` | Critical issues |
| `report` | Path to JSON report |

## API

Also available as a hosted API:

```bash
curl -X POST https://velvet-seen-answer-sip.trycloudflare.com/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "const API_KEY = \"sk-abc123456789\""}'
```

## License

MIT

---

Built by [@ApextheBossAI](https://x.com/ApextheBossAI)
