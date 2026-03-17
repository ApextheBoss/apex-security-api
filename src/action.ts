import * as core from '@actions/core';
import * as glob from '@actions/glob';
import * as fs from 'fs';
import * as path from 'path';

// Security scanning patterns
const PATTERNS: Record<string, Array<{regex: RegExp, severity: string, desc: string}>> = {
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
    { regex: /tool_choice\s*[:=]\s*['"](?:auto|any|required)['"]/gi, severity: "MEDIUM", desc: "Unrestricted tool choice" },
    { regex: /(?:allow|permit|enable)[_\s]?(?:all|any)[_\s]?(?:tool|action|command)/gi, severity: "HIGH", desc: "Overly permissive agent capabilities" },
    { regex: /user[_\s]?input.*(?:directly|raw|unsanitized)/gi, severity: "HIGH", desc: "Unsanitized user input in agent pipeline" },
  ],
  unicode_attacks: [
    { regex: /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, severity: "HIGH", desc: "Zero-width/invisible characters — may hide malicious code" },
    { regex: /[\u202A-\u202E\u2066-\u2069]/g, severity: "CRITICAL", desc: "Bidirectional control characters — Trojan Source attack" },
  ],
  config: [
    { regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*/gi, severity: "MEDIUM", desc: "Wildcard CORS" },
    { regex: /(?:verify|validate|check)\s*[:=]\s*false/gi, severity: "HIGH", desc: "Verification/validation disabled" },
    { regex: /https?\s*[:=]\s*false|ssl\s*[:=]\s*false|tls\s*[:=]\s*false/gi, severity: "HIGH", desc: "SSL/TLS verification disabled" },
  ],
};

interface Finding {
  file: string;
  severity: string;
  category: string;
  description: string;
  line: number;
  snippet: string;
}

function scanFile(filePath: string, code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split("\n");

  for (const [category, patterns] of Object.entries(PATTERNS)) {
    for (const pattern of patterns) {
      for (let i = 0; i < lines.length; i++) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        if (regex.test(lines[i])) {
          findings.push({
            file: filePath,
            severity: pattern.severity,
            category,
            description: pattern.desc,
            line: i + 1,
            snippet: lines[i].trim().substring(0, 120),
          });
        }
      }
    }
  }
  return findings;
}

async function run() {
  try {
    const pathsInput = core.getInput('paths') || '**/*.{js,ts,jsx,tsx,py,mjs,cjs}';
    const failOn = core.getInput('fail-on') || 'CRITICAL';
    const excludeInput = core.getInput('exclude') || 'node_modules/**,dist/**,build/**';

    const patterns = pathsInput.split(',').map(p => p.trim());
    const excludes = excludeInput.split(',').map(p => `!${p.trim()}`);

    const globber = await glob.create([...patterns, ...excludes].join('\n'));
    const files = await globber.glob();

    const allFindings: Finding[] = [];
    let filesScanned = 0;

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const relPath = path.relative(process.cwd(), file);
        const findings = scanFile(relPath, content);
        allFindings.push(...findings);
        filesScanned++;
      } catch {
        // skip binary/unreadable files
      }
    }

    // Sort by severity
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    allFindings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

    const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
    const high = allFindings.filter(f => f.severity === 'HIGH').length;
    const medium = allFindings.filter(f => f.severity === 'MEDIUM').length;
    const low = allFindings.filter(f => f.severity === 'LOW').length;

    let riskScore = 100;
    riskScore -= critical * 25;
    riskScore -= high * 10;
    riskScore -= medium * 3;
    riskScore -= low * 1;
    riskScore = Math.max(0, Math.min(100, riskScore));

    // Output summary
    core.setOutput('risk-score', riskScore.toString());
    core.setOutput('total-findings', allFindings.length.toString());
    core.setOutput('critical-count', critical.toString());

    // Write report
    const report = {
      scanner: 'Apex Security Scanner v1.0',
      scanned_at: new Date().toISOString(),
      files_scanned: filesScanned,
      risk_score: riskScore,
      risk_level: riskScore >= 80 ? 'LOW' : riskScore >= 60 ? 'MEDIUM' : riskScore >= 40 ? 'HIGH' : 'CRITICAL',
      summary: { critical, high, medium, low, total: allFindings.length },
      findings: allFindings,
    };

    const reportPath = path.join(process.cwd(), 'apex-security-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    core.setOutput('report', reportPath);

    // Log summary
    core.info(`\n👑 Apex Security Scanner Report`);
    core.info(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    core.info(`Files scanned: ${filesScanned}`);
    core.info(`Risk score: ${riskScore}/100 (${report.risk_level})`);
    core.info(`Findings: ${critical} critical, ${high} high, ${medium} medium, ${low} low`);

    // Annotate findings
    for (const f of allFindings) {
      const msg = `[${f.category}] ${f.description}\n${f.snippet}`;
      if (f.severity === 'CRITICAL') core.error(msg, { file: f.file, startLine: f.line });
      else if (f.severity === 'HIGH') core.warning(msg, { file: f.file, startLine: f.line });
      else core.notice(msg, { file: f.file, startLine: f.line });
    }

    // Fail check if needed
    if (failOn !== 'none') {
      const severityLevel = order[failOn] ?? 0;
      const shouldFail = allFindings.some(f => (order[f.severity] ?? 4) <= severityLevel);
      if (shouldFail) {
        core.setFailed(`Security scan found ${allFindings.length} issue(s) at ${failOn} severity or above`);
      }
    }

  } catch (error: any) {
    core.setFailed(`Scanner error: ${error.message}`);
  }
}

run();
