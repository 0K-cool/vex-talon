#!/usr/bin/env bun

/**
 * L5: Output Sanitizer - PostToolUse Hook
 *
 * Part of Vex-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Scan web files for unsafe DOM patterns after write.
 * Pattern: Sidecar Pattern (monitoring after tool execution)
 *
 * Maps to:
 * - OWASP LLM05 (Improper Output Handling)
 *
 * @version 0.1.0 (vex-talon)
 * @date 2026-02-04
 */

import { appendFileSync } from 'fs';
import { extname } from 'path';
import { ensureTalonDirs, getAuditLogPath } from './lib/talon-paths';

const HOOK_NAME = 'L5-output-sanitizer';

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface Finding {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  match: string;
}

// Web file extensions to scan
const WEB_EXTENSIONS = ['.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte'];
const WRITE_TOOLS = ['Write', 'Edit'];

// Unsafe DOM patterns (compiled at runtime to avoid false positive in source)
const UNSAFE_PATTERNS = [
  { name: 'Direct DOM injection', regex: '\\.innerHTML\\s*=', severity: 'CRITICAL' as const },
  { name: 'React unsafe HTML', regex: 'dangerouslySetInnerHTML', severity: 'CRITICAL' as const },
  { name: 'Vue unsafe HTML', regex: 'v-html\\s*=', severity: 'CRITICAL' as const },
  { name: 'Document write', regex: 'document\\.write\\s*\\(', severity: 'CRITICAL' as const },
  { name: 'Dynamic eval', regex: '\\beval\\s*\\(', severity: 'CRITICAL' as const },
  { name: 'Script URL', regex: 'href\\s*=\\s*["\']javascript:', severity: 'HIGH' as const },
  { name: 'jQuery HTML insert', regex: '\\$\\([^)]+\\)\\.html\\s*\\(', severity: 'HIGH' as const },
];

function scanContent(content: string): Finding[] {
  const findings: Finding[] = [];
  for (const p of UNSAFE_PATTERNS) {
    const regex = new RegExp(p.regex, 'i');
    const match = content.match(regex);
    if (match) {
      findings.push({ name: p.name, severity: p.severity, match: match[0].substring(0, 30) });
    }
  }
  return findings;
}

function logToAudit(entry: any): void {
  try {
    ensureTalonDirs();
    appendFileSync(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {}
}

function displayWarning(findings: Finding[], filePath: string): void {
  console.error('\n⚠️  TALON L5: Unsafe DOM patterns detected in ' + filePath);
  for (const f of findings.slice(0, 3)) {
    console.error(`   ${f.severity === 'CRITICAL' ? '🔴' : '🟠'} ${f.name}`);
  }
  console.error('   Consider using textContent or a sanitization library\n');
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);
    if (!data.tool_name || !WRITE_TOOLS.includes(data.tool_name)) process.exit(0);

    const filePath = data.tool_input?.file_path || '';
    const content = data.tool_input?.content || data.tool_input?.new_string || '';
    const ext = extname(filePath).toLowerCase();

    if (!WEB_EXTENSIONS.includes(ext) || content.length < 20) process.exit(0);

    const findings = scanContent(content);
    if (findings.length === 0) process.exit(0);

    logToAudit({
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      file_path: filePath,
      session_id: data.session_id,
      findings,
    });

    displayWarning(findings, filePath);

    // Output JSON with additionalContext so Claude/Vex is aware of XSS patterns
    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    const patternNames = findings.slice(0, 3).map(f => f.name).join(', ');

    console.log(JSON.stringify({
      continue: true,
      additionalContext: `⚠️ TALON L5: Unsafe DOM patterns detected in "${filePath}": ${patternNames}. ` +
        `${criticalFindings.length > 0 ? 'CRITICAL XSS risk! ' : ''}` +
        `Use textContent instead of innerHTML, or sanitize with DOMPurify. ` +
        `Do NOT use dangerouslySetInnerHTML or document.write with user input.`,
    }));

    process.exit(0);
  } catch {
    // PostToolUse: content already in context, blocking serves no purpose.
    // Fail-open is correct here (unlike PreToolUse hooks which fail-closed).
    process.exit(0);
  }
}

main();
