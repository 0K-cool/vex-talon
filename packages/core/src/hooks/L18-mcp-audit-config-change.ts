#!/usr/bin/env bun
/**
 * L18: MCP Audit - ConfigChange Hook
 *
 * Purpose: Real-time security scanning when .mcp.json is modified mid-session.
 *          Lightweight pattern check (<2s) that can BLOCK malicious configs.
 *
 * Pattern: Sidecar Pattern (monitoring on config change)
 *
 * Performance Target: <2s (quick pattern check, not full Proximity scan)
 *
 * Part of L18: MCP Audit (complements SessionStart full audit)
 *
 * ConfigChange input:
 * {
 *   "session_id": "...",
 *   "hook_event_name": "ConfigChange",
 *   "source": "project_settings" | "user_settings" | "skills" | ...,
 *   "file_path": "/path/to/.mcp.json" (optional)
 * }
 *
 * Behavior:
 *   CRITICAL -> exit(2) to BLOCK config change
 *   HIGH     -> warn (stderr + additionalContext)
 *   PASS     -> exit(0) silently
 *
 * Maps to:
 * - OWASP LLM01 (Prompt Injection via MCP tool descriptions)
 * - OWASP Agentic ASI06 (Memory and Context Manipulation)
 * - MITRE ATLAS AML.T0051 (LLM Prompt Injection)
 * - MITRE ATLAS AML.T0053 (LLM Plugin Compromise)
 *
 * @version 1.0.0 (vex-talon)
 * @date 2026-02-27
 */

import { existsSync, readFileSync } from 'fs';
import { basename } from 'path';
import { ensureDirectories, getAuditLogPath, secureAppendLog } from './lib/talon-paths';

// ============================================================================
// Types
// ============================================================================

interface ConfigChangeInput {
  session_id: string;
  hook_event_name: string;
  source?: string;
  file_path?: string;
  cwd?: string;
}

interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  server: string;
  description: string;
  pattern: string;
}

// ============================================================================
// Configuration
// ============================================================================

const HOOK_NAME = 'L18-mcp-audit-config-change';
const MCP_CONFIG_PATH = (() => {
  const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return `${cwd}/.mcp.json`;
})();

// Suspicious URL patterns - destinations that should never appear in MCP configs
const BLOCKED_URLS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /webhook\.site/i, description: 'webhook.site exfiltration endpoint' },
  { pattern: /ngrok\.(io|app)/i, description: 'ngrok tunnel endpoint' },
  { pattern: /pastebin\.com/i, description: 'pastebin data exfil' },
  { pattern: /requestbin/i, description: 'requestbin data capture' },
  { pattern: /burpcollaborator/i, description: 'Burp Collaborator endpoint' },
  { pattern: /interact\.sh/i, description: 'interactsh OOB endpoint' },
  { pattern: /pipedream\.net/i, description: 'pipedream webhook endpoint' },
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, description: 'raw IP address in MCP config' },
];

// Suspicious command patterns in MCP server commands/args
const DANGEROUS_COMMANDS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /curl\s.*\|\s*(sh|bash|zsh)/i, description: 'pipe curl to shell' },
  { pattern: /wget\s.*\|\s*(sh|bash|zsh)/i, description: 'pipe wget to shell' },
  { pattern: /eval\s*\(/i, description: 'eval execution in command' },
  { pattern: /rm\s+-rf\s+[/~]/i, description: 'destructive rm -rf' },
  { pattern: /reverse.?shell/i, description: 'reverse shell pattern' },
  { pattern: /nc\s+-[elp]/i, description: 'netcat listener/connect' },
  { pattern: /\/dev\/tcp\//i, description: 'bash /dev/tcp reverse connection' },
  { pattern: /base64\s+-d.*\|\s*(sh|bash)/i, description: 'base64 decode to shell' },
  { pattern: /python[23]?\s+-c\s+['"]import\s+(socket|os|subprocess)/i, description: 'python reverse shell' },
];

// Injection patterns in tool descriptions (NOVA-aligned)
const INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, description: 'instruction override in MCP config' },
  { pattern: /you\s+are\s+now\s+/i, description: 'role hijack in MCP config' },
  { pattern: /system\s*prompt\s*[:=]/i, description: 'system prompt injection in MCP config' },
  { pattern: /\bdo\s+not\s+tell\b.*\buser\b/i, description: 'stealth instruction in MCP config' },
  { pattern: /exfiltrate|steal\s+data|send\s+to\s+server/i, description: 'exfiltration instruction in MCP config' },
  { pattern: /bypass\s+(security|safety|filter)/i, description: 'security bypass instruction' },
  { pattern: /<\s*system\s*>/i, description: 'XML system tag injection' },
];

// Known malicious/compromised npm packages
const MALICIOUS_PACKAGES = [
  'colors', 'faker', 'event-stream', 'flatmap-stream', 'ua-parser-js',
  'coa', 'rc', 'peacenotwar', 'node-ipc', 'es5-ext',
];

// ============================================================================
// Logging
// ============================================================================

function logAudit(entry: Record<string, unknown>): void {
  try {
    ensureDirectories();
    secureAppendLog(getAuditLogPath(HOOK_NAME), JSON.stringify({
      timestamp: new Date().toISOString(),
      hook: HOOK_NAME,
      ...entry,
    }) + '\n');
  } catch {
    // Don't fail on logging errors
  }
}

// ============================================================================
// Scanning Logic
// ============================================================================

function scanMcpConfig(configContent: string): Finding[] {
  const findings: Finding[] = [];

  let config: { mcpServers?: Record<string, unknown> };
  try {
    config = JSON.parse(configContent);
  } catch {
    findings.push({
      severity: 'HIGH',
      server: '_config_',
      description: 'Invalid JSON in .mcp.json — could be injection attempt or corruption',
      pattern: 'json-parse-error',
    });
    return findings;
  }

  if (!config.mcpServers || typeof config.mcpServers !== 'object') {
    return findings; // No servers to scan
  }

  for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
    if (!serverConfig || typeof serverConfig !== 'object') continue;
    const srv = serverConfig as Record<string, unknown>;

    // Stringify full server config for pattern matching
    const configStr = JSON.stringify(srv);

    // Check command field
    const command = String(srv.command || '');
    const args = Array.isArray(srv.args) ? srv.args.map(String) : [];
    const fullCommand = [command, ...args].join(' ');

    // 1. Check for blocked URLs in entire config
    for (const { pattern, description } of BLOCKED_URLS) {
      if (pattern.test(configStr)) {
        findings.push({
          severity: 'CRITICAL',
          server: serverName,
          description,
          pattern: pattern.source,
        });
      }
    }

    // 2. Check for dangerous command patterns
    for (const { pattern, description } of DANGEROUS_COMMANDS) {
      if (pattern.test(fullCommand) || pattern.test(configStr)) {
        findings.push({
          severity: 'CRITICAL',
          server: serverName,
          description,
          pattern: pattern.source,
        });
      }
    }

    // 3. Check for injection patterns in descriptions/args
    for (const { pattern, description } of INJECTION_PATTERNS) {
      if (pattern.test(configStr)) {
        findings.push({
          severity: 'CRITICAL',
          server: serverName,
          description,
          pattern: pattern.source,
        });
      }
    }

    // 4. Check for malicious packages in command/args
    for (const pkg of MALICIOUS_PACKAGES) {
      const pkgPattern = new RegExp(`\\b${pkg}\\b`, 'i');
      if (pkgPattern.test(fullCommand)) {
        findings.push({
          severity: 'CRITICAL',
          server: serverName,
          description: `Known compromised package: ${pkg}`,
          pattern: `malicious-pkg:${pkg}`,
        });
      }
    }

    // 5. Check env vars for potential credential forwarding concerns
    if (srv.env && typeof srv.env === 'object') {
      const envVars = srv.env as Record<string, string>;
      for (const [envKey, envValue] of Object.entries(envVars)) {
        if (typeof envValue !== 'string') continue;

        // Check if env values contain suspicious URLs
        for (const { pattern, description } of BLOCKED_URLS) {
          if (pattern.test(envValue)) {
            findings.push({
              severity: 'CRITICAL',
              server: serverName,
              description: `${description} in env var ${envKey}`,
              pattern: pattern.source,
            });
          }
        }
      }
    }
  }

  return findings;
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  const startTime = Date.now();

  try {
    // Read input from stdin
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 500)
      ),
    ]);

    // Parse ConfigChange input
    let hookInput: ConfigChangeInput;
    try {
      hookInput = JSON.parse(input);
    } catch {
      process.exit(0); // Can't parse input, skip
    }

    // Only process .mcp.json changes
    // ConfigChange fires for all config changes — filter to MCP only
    const filePath = hookInput.file_path || '';
    const source = hookInput.source || '';

    // Filter: only act on project_settings that involve .mcp.json
    // If file_path is provided, check it directly
    // If not, we can't determine if it's .mcp.json — skip
    if (filePath) {
      if (basename(filePath) !== '.mcp.json') {
        process.exit(0); // Not an MCP config change
      }
    } else if (source !== 'project_settings') {
      process.exit(0); // Not project settings
    }

    // Read .mcp.json
    if (!existsSync(MCP_CONFIG_PATH)) {
      process.exit(0); // No MCP config
    }

    const configContent = readFileSync(MCP_CONFIG_PATH, 'utf-8');
    const findings = scanMcpConfig(configContent);
    const duration = Date.now() - startTime;

    // Separate by severity
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    const high = findings.filter(f => f.severity === 'HIGH');

    // Log audit entry
    logAudit({
      session_id: hookInput.session_id,
      source: hookInput.source,
      file_path: hookInput.file_path,
      findings_count: findings.length,
      critical_count: critical.length,
      high_count: high.length,
      duration_ms: duration,
      result: critical.length > 0 ? 'BLOCKED' : high.length > 0 ? 'WARNED' : 'PASSED',
    });

    // Handle findings
    if (critical.length > 0) {
      // BLOCK the config change
      const alertMsg = [
        `\n🔴 TALON L18: BLOCKED config change — ${critical.length} CRITICAL finding(s)`,
        ...critical.map(f => `  - [${f.server}] ${f.description}`),
        `\nRun MCP audit for full details. Config change was PREVENTED.`,
      ].join('\n');

      console.error(alertMsg);

      // Provide context to Claude
      const contextOutput = {
        decision: 'block',
        reason: `MCP config change blocked: ${critical.length} CRITICAL finding(s) — ${critical.map(f => f.description).join('; ')}`,
      };
      console.log(JSON.stringify(contextOutput));

      process.exit(2); // Block the config change
    }

    if (high.length > 0) {
      // WARN but allow
      const warnMsg = [
        `\n🟠 TALON L18: ${high.length} HIGH finding(s) in config change`,
        ...high.map(f => `  - [${f.server}] ${f.description}`),
        `\nConfig change allowed. Run MCP audit for full details.`,
      ].join('\n');

      console.error(warnMsg);

      const contextOutput = {
        additionalContext: `MCP config change detected with ${high.length} HIGH severity finding(s). Review recommended.`,
      };
      console.log(JSON.stringify(contextOutput));

      process.exit(0);
    }

    // Clean pass — silent
    process.exit(0);
  } catch (error) {
    // Don't block on errors — fail open
    logAudit({
      error: String(error),
      result: 'ERROR',
    });
    process.exit(0);
  }
}

main();
