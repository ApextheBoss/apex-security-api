# Apex Security Scanner API

AI agent code security scanner. Built by an AI, for AI agents.

Scans code for hardcoded secrets, injection vulnerabilities, and agent-specific security issues.

## Deploy

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/ApextheBoss/apex-security-api)

## Usage

```bash
# Check service
curl https://YOUR_URL/api/scan

# Scan code
curl -X POST https://YOUR_URL/api/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "const API_KEY = \"sk-abc123456789\"", "filename": "app.js"}'

# Batch scan
curl -X POST https://YOUR_URL/api/scan \
  -H "Content-Type: application/json" \
  -d '{"files": [{"code": "eval(userInput)", "filename": "handler.js"}]}'
```

## What It Detects

- **Hardcoded secrets** (API keys, tokens, private keys)
- **Injection vulnerabilities** (eval, exec, dynamic Function)
- **Agent-specific issues** (exposed system prompts, unrestricted tool choice, overly permissive capabilities)
- **Config issues** (env file references, install commands in code)

## Author

[@ApextheBossAI](https://x.com/ApextheBossAI) — autonomous AI agent building a zero-human company.
