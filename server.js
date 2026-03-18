import http from 'http';

const PATTERNS = {
  hardcoded_secrets: [
    { regex: '(?:api[_-]?key|secret|token|password|passwd|pwd)\\s*[:=]\\s*[\'"][^\'"]{8,}[\'"]', flags: 'gi', severity: 'CRITICAL', desc: 'Hardcoded secret/API key' },
    { regex: '(?:sk-|pk_live_|sk_live_|ghp_|gho_|github_pat_|xoxb-|xoxp-|AKIA)[A-Za-z0-9_\\-]{10,}', flags: 'g', severity: 'CRITICAL', desc: 'Known API key pattern detected' },
    { regex: '-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', flags: 'g', severity: 'CRITICAL', desc: 'Private key embedded in code' },
  ],
  injection: [
    { regex: 'eval\\s*\\(', flags: 'g', severity: 'HIGH', desc: 'eval() usage — potential code injection' },
    { regex: 'new\\s+Function\\s*\\(', flags: 'g', severity: 'HIGH', desc: 'Dynamic Function constructor' },
    { regex: 'child_process|exec\\s*\\(|execSync|spawn\\s*\\(', flags: 'g', severity: 'HIGH', desc: 'Shell command execution' },
  ],
  agent_specific: [
    { regex: 'system[_\\s]?prompt\\s*[:=]', flags: 'gi', severity: 'HIGH', desc: 'System prompt exposed in code' },
    { regex: '(?:OPENAI|ANTHROPIC|GOOGLE|COHERE)_API_KEY', flags: 'g', severity: 'CRITICAL', desc: 'LLM API key reference' },
    { regex: 'tool_choice\\s*[:=]\\s*[\'"](?:auto|any|required)[\'"]', flags: 'gi', severity: 'MEDIUM', desc: 'Unrestricted tool choice' },
    { regex: '(?:allow|permit|enable)[_\\s]?(?:all|any)[_\\s]?(?:tool|action|command)', flags: 'gi', severity: 'HIGH', desc: 'Overly permissive agent capabilities' },
  ],
  config: [
    { regex: '\\.env(?:\\.local|\\.prod|\\.dev)?', flags: 'g', severity: 'MEDIUM', desc: 'Environment file reference' },
    { regex: 'npm install|pip install', flags: 'g', severity: 'LOW', desc: 'Install command in code' },
  ]
};

function scanCode(code, filename = 'unknown') {
  const findings = [];
  for (const [category, patterns] of Object.entries(PATTERNS)) {
    for (const p of patterns) {
      const re = new RegExp(p.regex, p.flags);
      let match;
      while ((match = re.exec(code)) !== null) {
        const line = code.substring(0, match.index).split('\n').length;
        findings.push({ severity: p.severity, category, description: p.desc, file: filename, line, match: match[0].substring(0, 100) });
      }
    }
  }
  return findings.sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }
  
  if (req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({
      service: 'Apex Security Scanner',
      version: '1.0.0',
      author: '@ApextheBossAI',
      description: 'AI agent code security scanner. Built by an AI, for AI agents.',
      usage: 'POST / with { "code": "your code here", "filename": "optional.js" }',
      batch: 'POST / with { "files": [{ "code": "...", "filename": "..." }] } (max 20)',
      pricing: 'Free during beta',
      wallet: '0x74075f7330f4A88758AC815fC7F779b4147c64EF',
      x: '@ApextheBossAI',
    }));
    return;
  }
  
  if (req.method !== 'POST') { res.writeHead(405); res.end(JSON.stringify({ error: 'Method not allowed' })); return; }
  
  let body = '';
  req.on('data', chunk => { body += chunk; if (body.length > 5e6) { res.writeHead(413); res.end(JSON.stringify({ error: 'Too large' })); } });
  req.on('end', () => {
    try {
      const data = JSON.parse(body);
      const { code, filename, files } = data;
      
      if (files && Array.isArray(files)) {
        if (files.length > 20) { res.writeHead(400); res.end(JSON.stringify({ error: 'Max 20 files' })); return; }
        const results = files.map(f => ({ filename: f.filename || 'unknown', findings: scanCode(f.code || '', f.filename) }));
        const total = results.reduce((s, r) => s + r.findings.length, 0);
        res.writeHead(200);
        res.end(JSON.stringify({ results, totalFindings: total, scannedFiles: files.length }));
        return;
      }
      
      if (!code) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing "code" field' })); return; }
      const findings = scanCode(code, filename);
      res.writeHead(200);
      res.end(JSON.stringify({
        filename: filename || 'unknown',
        findings,
        summary: {
          total: findings.length,
          critical: findings.filter(f => f.severity === 'CRITICAL').length,
          high: findings.filter(f => f.severity === 'HIGH').length,
          medium: findings.filter(f => f.severity === 'MEDIUM').length,
          low: findings.filter(f => f.severity === 'LOW').length,
        }
      }));
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    }
  });
});

const PORT = process.env.PORT || 3847;
server.listen(PORT, '0.0.0.0', () => console.log(`Apex Security Scanner running on port ${PORT}`));
