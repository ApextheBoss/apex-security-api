import { Hono } from "hono";

const app = new Hono();

// Security scanning patterns
const PATTERNS = {
  hardcoded_secrets: [
    { regex: /(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: "CRITICAL", desc: "Hardcoded secret/API key" },
    { regex: /(?:sk-|pk_live_|sk_live_|ghp_|gho_|github_pat_|xoxb-|xoxp-|AKIA)[A-Za-z0-9_\-]{10,}/g, severity: "CRITICAL", desc: "Known API key pattern detected" },
    { regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, severity: "CRITICAL", desc: "Private key embedded in code" },
  ],
  injection: [
    { regex: /eval\s*\(/g, severity: "HIGH", desc: "eval() usage — potential code injection" },
    { regex: /new\s+Function\s*\(/g, severity: "HIGH", desc: "Dynamic Function constructor — code injection risk" },
    { regex: /child_process|exec\s*\(|execSync|spawn\s*\(/g, severity: "HIGH", desc: "Shell command execution — injection risk" },
    { regex: /innerHTML\s*=/g, severity: "MEDIUM", desc: "innerHTML assignment — XSS risk" },
    { regex: /document\.write/g, severity: "MEDIUM", desc: "document.write — XSS risk" },
  ],
  agent_specific: [
    { regex: /system[_\s]?prompt\s*[:=]/gi, severity: "HIGH", desc: "System prompt exposed in code" },
    { regex: /(?:OPENAI|ANTHROPIC|GOOGLE|COHERE)_API_KEY/g, severity: "CRITICAL", desc: "LLM API key reference in code" },
    { regex: /\.env(?:\.local|\.prod|\.dev)?/g, severity: "MEDIUM", desc: "Environment file reference — check .gitignore" },
    { regex: /tool_choice\s*[:=]\s*['"](?:auto|any|required)['"]/gi, severity: "MEDIUM", desc: "Unrestricted tool choice — agent may call unintended tools" },
    { regex: /(?:allow|permit|enable)[_\s]?(?:all|any)[_\s]?(?:tool|action|command)/gi, severity: "HIGH", desc: "Overly permissive agent capabilities" },
    { regex: /user[_\s]?input.*(?:directly|raw|unsanitized)/gi, severity: "HIGH", desc: "Unsanitized user input in agent pipeline" },
  ],
  dependency: [
    { regex: /require\s*\(\s*['"][^'"]*['"\s]*\+/g, severity: "HIGH", desc: "Dynamic require — dependency confusion risk" },
    { regex: /import\s*\(\s*['"][^'"]*['"\s]*\+/g, severity: "HIGH", desc: "Dynamic import — dependency confusion risk" },
    { regex: /npm install|pip install|cargo install/g, severity: "LOW", desc: "Install command in code — verify package names" },
  ],
  unicode_attacks: [
    { regex: /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu, severity: "CRITICAL", desc: "Invisible Unicode variation selectors — possible Glassworm-style payload" },
    { regex: /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, severity: "HIGH", desc: "Zero-width/invisible characters — may hide malicious code" },
    { regex: /[\u202A-\u202E\u2066-\u2069]/g, severity: "CRITICAL", desc: "Bidirectional control characters — Trojan Source attack vector" },
    { regex: /[\u0400-\u04FF](?=[a-zA-Z])|(?<=[a-zA-Z])[\u0400-\u04FF]/g, severity: "HIGH", desc: "Mixed Cyrillic/Latin chars — possible homoglyph attack" },
    { regex: /eval\s*\(\s*Buffer\.from\s*\(\s*s\s*\(\s*`/g, severity: "CRITICAL", desc: "Glassworm decoder pattern — invisible Unicode payload execution" },
  ],
  config: [
    { regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*/gi, severity: "MEDIUM", desc: "Wildcard CORS — any origin can access API" },
    { regex: /(?:verify|validate|check)\s*[:=]\s*false/gi, severity: "HIGH", desc: "Verification/validation disabled" },
    { regex: /https?\s*[:=]\s*false|ssl\s*[:=]\s*false|tls\s*[:=]\s*false/gi, severity: "HIGH", desc: "SSL/TLS verification disabled" },
    { regex: /debug\s*[:=]\s*true/gi, severity: "MEDIUM", desc: "Debug mode enabled — may leak sensitive info" },
  ],
};

interface Finding {
  severity: string;
  category: string;
  description: string;
  line: number;
  snippet: string;
}

function scanCode(code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split("\n");

  for (const [category, patterns] of Object.entries(PATTERNS)) {
    for (const pattern of patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          findings.push({
            severity: pattern.severity,
            category,
            description: pattern.desc,
            line: i + 1,
            snippet: lines[i].trim().substring(0, 120),
          });
        }
        // Reset regex lastIndex
        regex.lastIndex = 0;
      }
    }
  }

  // Sort by severity
  const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  return findings;
}

function generateReport(findings: Finding[], codeLength: number): object {
  const critical = findings.filter(f => f.severity === "CRITICAL").length;
  const high = findings.filter(f => f.severity === "HIGH").length;
  const medium = findings.filter(f => f.severity === "MEDIUM").length;
  const low = findings.filter(f => f.severity === "LOW").length;

  let riskScore = 100;
  riskScore -= critical * 25;
  riskScore -= high * 10;
  riskScore -= medium * 3;
  riskScore -= low * 1;
  riskScore = Math.max(0, Math.min(100, riskScore));

  return {
    scanner: "Apex Security Scanner v1.0",
    scanned_at: new Date().toISOString(),
    lines_scanned: codeLength,
    risk_score: riskScore,
    risk_level: riskScore >= 80 ? "LOW" : riskScore >= 60 ? "MEDIUM" : riskScore >= 40 ? "HIGH" : "CRITICAL",
    summary: { critical, high, medium, low, total: findings.length },
    findings,
  };
}

// Landing page
app.get("/", (c) => {
  return c.html(`<!DOCTYPE html>
<html><head><title>Apex Security Scanner API</title>
<meta name="description" content="AI agent security scanner. Scan code for vulnerabilities via API. Pay per scan with x402 (USDC).">
<style>
  body { background: #1a1a1a; color: #e0e0e0; font-family: system-ui; max-width: 800px; margin: 0 auto; padding: 40px 20px; }
  h1 { color: #D4621A; } h2 { color: #D4621A; margin-top: 2em; }
  a { color: #D4621A; } code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; }
  pre { background: #2a2a2a; padding: 16px; border-radius: 8px; overflow-x: auto; border-left: 3px solid #D4621A; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; margin: 2px; }
  .critical { background: #dc2626; color: white; } .high { background: #ea580c; color: white; }
  .medium { background: #ca8a04; color: black; } .low { background: #16a34a; color: white; }
</style></head><body>
<h1>👑 Apex Security Scanner</h1>
<p>Scan your code for security vulnerabilities. Built by an AI agent, for AI agents.</p>
<p>Detects: <span class="badge critical">Hardcoded Secrets</span> <span class="badge high">Injection Risks</span>
<span class="badge medium">Agent-Specific Vulns</span> <span class="badge low">Config Issues</span></p>

<h2>Free API</h2>
<pre>curl -X POST https://apex-security.deno.dev/scan \\
  -H "Content-Type: application/json" \\
  -d '{"code": "const API_KEY = \\"sk-abc123456789\\""}'</pre>

<h2>Scan a GitHub File</h2>
<pre>curl -X POST https://apex-security.deno.dev/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://raw.githubusercontent.com/owner/repo/main/index.js"}'</pre>

<h2>What It Scans</h2>
<ul>
<li><strong>Hardcoded secrets</strong> — API keys, tokens, passwords, private keys</li>
<li><strong>Code injection</strong> — eval(), exec(), innerHTML, dynamic imports</li>
<li><strong>Agent-specific</strong> — exposed system prompts, unrestricted tools, unsanitized inputs</li>
<li><strong>Dependencies</strong> — dynamic requires, dependency confusion patterns</li>
<li><strong>Configuration</strong> — wildcard CORS, disabled SSL, debug mode</li>
</ul>

<h2>Response</h2>
<pre>{
  "risk_score": 35,
  "risk_level": "HIGH",
  "summary": { "critical": 2, "high": 1, "medium": 0, "low": 0 },
  "findings": [...]
}</pre>

<p style="margin-top: 3em; color: #888;">Built by <a href="https://x.com/ApextheBossAI">@ApextheBossAI</a> — 
<a href="https://github.com/ApextheBoss">GitHub</a></p>
</body></html>`);
});

// Health check
app.get("/health", (c) => c.json({ status: "ok", version: "1.0.0" }));

// Main scan endpoint
app.post("/scan", async (c) => {
  try {
    const body = await c.req.json();
    let code = "";

    if (body.code) {
      code = body.code;
    } else if (body.url) {
      // Fetch code from URL (GitHub raw URLs, etc.)
      const resp = await fetch(body.url);
      if (!resp.ok) return c.json({ error: "Failed to fetch URL", status: resp.status }, 400);
      code = await resp.text();
      if (code.length > 500_000) return c.json({ error: "File too large (max 500KB)" }, 400);
    } else {
      return c.json({ error: "Provide 'code' (string) or 'url' (raw file URL)" }, 400);
    }

    if (!code.trim()) return c.json({ error: "Empty code" }, 400);

    const findings = scanCode(code);
    const report = generateReport(findings, code.split("\n").length);

    return c.json(report);
  } catch (e) {
    return c.json({ error: "Invalid request. Send JSON with 'code' or 'url' field." }, 400);
  }
});

// Batch scan
app.post("/scan/batch", async (c) => {
  try {
    const body = await c.req.json();
    if (!body.files || !Array.isArray(body.files)) {
      return c.json({ error: "Provide 'files' array of {name, code} or {name, url}" }, 400);
    }
    if (body.files.length > 20) return c.json({ error: "Max 20 files per batch" }, 400);

    const results: Record<string, object> = {};
    for (const file of body.files) {
      let code = file.code || "";
      if (!code && file.url) {
        const resp = await fetch(file.url);
        if (resp.ok) code = await resp.text();
      }
      if (code) {
        const findings = scanCode(code);
        results[file.name || file.url || "unnamed"] = generateReport(findings, code.split("\n").length);
      }
    }

    return c.json({ scanner: "Apex Security Scanner v1.0", batch: true, results });
  } catch {
    return c.json({ error: "Invalid request" }, 400);
  }
});

Deno.serve({ port: 8000 }, app.fetch);
