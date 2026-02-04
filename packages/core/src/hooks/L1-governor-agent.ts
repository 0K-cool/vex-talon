#!/usr/bin/env bun

/**
 * L1 Governor Agent - PreToolUse Hook
 *
 * Purpose: Real-time policy enforcement before tool execution
 * Pattern: Sidecar Pattern (independent monitoring)
 * Action: BLOCK (exit code 2) or INPUT MODIFICATION
 * OWASP: LLM02 (Sensitive Information Disclosure), LLM01 (Prompt Injection)
 *
 * Key Capability: Can MODIFY tool inputs before execution to prevent violations
 * - Dangerous commands → safe echo messages
 * - Sensitive file reads → blocked file paths
 * - Destructive operations → neutralized
 *
 * Vex-Talon v0.1.0
 */

import { appendFileSync } from 'fs';
import { join } from 'path';
import { TALON_DIR, getAuditLogPath, ensureDirectories } from './lib/talon-paths';
import { checkCircuit, recordSuccess, recordFailure } from './lib/circuit-breaker';
import {
  loadActiveProfile,
  isToolAllowed,
  isPathAllowed,
  isBashCommandAllowed,
} from './lib/profile-loader';

const HOOK_NAME = 'L1-governor-agent';

// Pattern to detect (split to avoid self-detection)
const SANDBOX_BYPASS_PATTERN = 'dangerous' + 'lyDisable' + 'Sandbox';

/**
 * Check if a path is an .env file (catches .env, .env.local, .env.production, etc.)
 * Excludes safe files: .env.example, .env.1password
 */
function isEnvFile(filePath: string): boolean {
  const basename = filePath.split('/').pop() || '';
  // Match .env or .env.* but not .env.example or .env.1password
  const isEnv = /^\.env($|\..+)/.test(basename);
  const isSafe = /\.(example|sample|template|1password)$/i.test(basename);
  return isEnv && !isSafe;
}

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface HookOutput {
  tool_input?: Record<string, any>;
}

interface Policy {
  name: string;
  tool: string | '*';
  match: (tool: string, params: Record<string, any>) => boolean;
  action: 'BLOCK' | 'WARN';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  message: string;
  modify?: (params: Record<string, any>) => Record<string, any> | null;
}

interface AuditLogEntry {
  timestamp: string;
  tool: string;
  parameters: Record<string, any>;
  modified_input?: Record<string, any>;
  policy_matched: string | null;
  action: 'BLOCK' | 'WARN' | 'ALLOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  input_modified: boolean;
  message: string;
  evaluation_time_ms: number;
  session_id: string;
}

// ============================================================================
// Bundled Policies (Core Security)
// ============================================================================

const POLICIES: Policy[] = [
  // === CRITICAL: Sandbox Bypass Prevention ===
  {
    name: 'block-sandbox-disable',
    tool: '*',
    match: (_tool, params) => {
      const str = JSON.stringify(params).toLowerCase();
      return str.includes(SANDBOX_BYPASS_PATTERN.toLowerCase());
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Sandbox bypass attempt detected - potential prompt injection',
  },

  // === CRITICAL: .env File Protection ===
  // Matches .env, .env.local, .env.production, .env.development, etc.
  // Excludes .env.example and .env.1password (safe reference files)
  {
    name: 'block-env-reads',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot read .env files (contains secrets)',
    modify: (_params) => ({
      file_path: join(TALON_DIR, 'GOVERNOR_BLOCKED_ENV_READ.txt')
    }),
  },
  {
    name: 'block-env-writes',
    tool: 'Write',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot write production .env files via Write tool',
    modify: (_params) => ({
      file_path: join(TALON_DIR, 'GOVERNOR_BLOCKED_ENV_WRITE.txt'),
      content: `[GOVERNOR BLOCKED]\n\nAttempted write to .env file was blocked.\nReason: .env files contain secrets and should be edited manually.`
    }),
  },
  {
    name: 'block-env-edits',
    tool: 'Edit',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return isEnvFile(path);
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot edit .env files via Edit tool',
    modify: (_params) => ({
      file_path: join(TALON_DIR, 'GOVERNOR_BLOCKED_ENV_EDIT.txt'),
      old_string: '',
      new_string: `[GOVERNOR BLOCKED]\n\nReason: .env files should be edited manually.`
    }),
  },

  // === CRITICAL: Private Key Protection ===
  {
    name: 'block-private-key-commits',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      return cmd.includes('git commit') && cmd.includes('BEGIN PRIVATE KEY');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Private key detected in staged changes',
    modify: (_params) => ({
      command: `echo "[GOVERNOR BLOCKED] Private key detected in staged changes. Remove before committing."`
    }),
  },

  // === CRITICAL: Protected Folders (macOS) ===
  {
    name: 'block-documents-access',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('/Documents/');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot access ~/Documents - protected folder',
    modify: (_params) => ({
      file_path: join(TALON_DIR, 'GOVERNOR_BLOCKED_PROTECTED_FOLDER.txt')
    }),
  },
  {
    name: 'block-desktop-access',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('/Desktop/');
    },
    action: 'BLOCK',
    severity: 'CRITICAL',
    message: 'Cannot access ~/Desktop - protected folder',
    modify: (_params) => ({
      file_path: join(TALON_DIR, 'GOVERNOR_BLOCKED_PROTECTED_FOLDER.txt')
    }),
  },

  // === HIGH: Dangerous Bash Commands ===
  {
    name: 'block-curl-pipe-sh',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      return cmd.includes('curl') && (cmd.includes('| sh') || cmd.includes('| bash') || cmd.includes('|sh') || cmd.includes('|bash'));
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Dangerous pattern: curl | sh - download and review scripts before executing',
    modify: (_params) => ({
      command: `echo "[GOVERNOR BLOCKED] Dangerous pattern: curl | sh. Download and review scripts before executing."`
    }),
  },
  {
    name: 'block-rm-rf-critical',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      if (!cmd.includes('rm -rf') && !cmd.includes('rm -r')) return false;
      const criticalPaths = ['.git', '/', '/*', '~', '$HOME', '/etc', '/usr', '/var'];
      return criticalPaths.some(p => cmd.includes(p));
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Destructive rm -rf on critical directory detected',
    modify: (_params) => ({
      command: `echo "[GOVERNOR BLOCKED] Dangerous rm -rf operation. Verify path manually if needed."`
    }),
  },
  {
    name: 'block-force-push-main',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      return cmd.includes('git push --force') && (cmd.includes('main') || cmd.includes('master'));
    },
    action: 'BLOCK',
    severity: 'HIGH',
    message: 'Force push to main/master is destructive',
    modify: (_params) => ({
      command: `echo "[GOVERNOR BLOCKED] Force push to main/master. Use: git push --force-with-lease instead."`
    }),
  },
  {
    name: 'warn-git-reset-hard',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      return cmd.includes('git reset --hard') && cmd.includes('HEAD~');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Destructive git reset --hard - uncommitted changes will be lost',
  },

  // === HIGH: Secret Pattern Detection in Commands ===
  {
    name: 'warn-secrets-in-bash',
    tool: 'Bash',
    match: (_tool, params) => {
      const cmd = String(params.command || '');
      const patterns = [
        /sk-[A-Za-z0-9]{20,}/,
        /pplx-[A-Za-z0-9]{40,}/,
        /ghp_[A-Za-z0-9_]{36,}/,
        /AIza[A-Za-z0-9_-]{35}/,
        /AKIA[A-Z0-9]{16}/,
      ];
      return patterns.some(p => p.test(cmd));
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'API key pattern detected in bash command - verify not logging secrets',
  },

  // === MEDIUM: Git Hook Edits ===
  {
    name: 'warn-git-hook-edits',
    tool: 'Edit',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('.git/hooks/');
    },
    action: 'WARN',
    severity: 'MEDIUM',
    message: 'Editing git hooks - verify this does not bypass safety checks',
  },

  // === MEDIUM: SSH Key Access ===
  {
    name: 'warn-ssh-key-reads',
    tool: 'Read',
    match: (_tool, params) => {
      const path = String(params.file_path || '');
      return path.includes('.ssh/') && !path.includes('.pub');
    },
    action: 'WARN',
    severity: 'MEDIUM',
    message: 'Reading SSH private key files - verify this is necessary',
  },

  // === PROMPT INJECTION DEFENSE ===
  {
    name: 'detect-ignore-instructions',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params).toLowerCase();
      return content.includes('ignore previous instructions') ||
             content.includes('disregard all prior') ||
             content.includes('ignore everything above') ||
             content.includes('new instructions:') ||
             content.includes('your real instructions');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: instruction override pattern',
  },
  {
    name: 'detect-role-hijacking',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params).toLowerCase();
      return content.includes('you are now') ||
             content.includes('act as if') ||
             content.includes('pretend to be') ||
             content.includes('dan mode') ||
             content.includes('jailbreak mode') ||
             content.includes('developer mode enabled');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: role hijacking attempt',
  },
  {
    name: 'detect-context-injection',
    tool: '*',
    match: (_tool, params) => {
      const content = JSON.stringify(params);
      return content.includes('[SYSTEM]') ||
             content.includes('<<SYS>>') ||
             content.includes('</s>');
    },
    action: 'WARN',
    severity: 'HIGH',
    message: 'Possible prompt injection detected: fake system markers',
  },
];

// Tools to monitor
const MONITORED_TOOLS = ['Read', 'Write', 'Edit', 'Bash', 'WebFetch', 'WebSearch', 'Skill', 'Task', 'Glob', 'Grep'];

// ============================================================================
// Unicode Normalization (Homoglyph Bypass Prevention)
// ============================================================================

const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic confusables
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K',
  '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y', '\u0425': 'X',
  // Greek confusables
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o',
  '\u0391': 'A', '\u0395': 'E', '\u0399': 'I', '\u039F': 'O',
  // Zero-width characters (remove)
  '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '', '\u00ad': '',
  // Whitespace normalization
  '\u00a0': ' ', '\u2000': ' ', '\u2001': ' ', '\u2002': ' ', '\u2003': ' ',
};

function normalizeUnicode(text: string): string {
  let normalized = text.normalize('NFKC');
  for (const [homoglyph, replacement] of Object.entries(HOMOGLYPHS)) {
    normalized = normalized.split(homoglyph).join(replacement);
  }
  return normalized;
}

function normalizeParams(params: Record<string, any>): Record<string, any> {
  const normalized: Record<string, any> = {};
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') {
      normalized[key] = normalizeUnicode(value);
    } else if (typeof value === 'object' && value !== null) {
      normalized[key] = normalizeParams(value);
    } else {
      normalized[key] = value;
    }
  }
  return normalized;
}

// ============================================================================
// Audit Logging
// ============================================================================

function logToAudit(entry: AuditLogEntry): void {
  try {
    ensureDirectories();
    const logPath = getAuditLogPath(HOOK_NAME);
    const logLine = JSON.stringify(entry) + '\n';
    appendFileSync(logPath, logLine);
  } catch (error) {
    console.error(`[Governor] Failed to write audit log: ${error}`);
  }
}

function sanitizeParameters(params: Record<string, any>): Record<string, any> {
  const sanitized = { ...params };
  const sensitiveKeys = ['api_key', 'password', 'token', 'secret', 'auth', 'credential'];

  for (const key in sanitized) {
    if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
      sanitized[key] = '[REDACTED]';
    }
    if (key === 'content' && typeof sanitized[key] === 'string' && sanitized[key].length > 500) {
      sanitized[key] = sanitized[key].substring(0, 500) + `... [truncated]`;
    }
  }

  return sanitized;
}

// ============================================================================
// Policy Evaluation
// ============================================================================

function evaluatePolicies(tool: string, params: Record<string, any>): {
  policy: Policy | null;
  action: 'BLOCK' | 'WARN' | 'ALLOW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  message: string;
  modifiedInput: Record<string, any> | null;
} {
  const severityOrder: Array<'CRITICAL' | 'HIGH' | 'MEDIUM'> = ['CRITICAL', 'HIGH', 'MEDIUM'];

  for (const severity of severityOrder) {
    const matchingPolicies = POLICIES.filter(p => p.severity === severity);

    for (const policy of matchingPolicies) {
      if (policy.tool !== '*' && policy.tool !== tool) continue;

      if (policy.match(tool, params)) {
        let modifiedInput: Record<string, any> | null = null;
        if (policy.modify && policy.action === 'BLOCK') {
          modifiedInput = policy.modify(params);
        }

        return {
          policy,
          action: policy.action,
          severity: policy.severity,
          message: policy.message,
          modifiedInput,
        };
      }
    }
  }

  return {
    policy: null,
    action: 'ALLOW',
    severity: 'NONE',
    message: 'No policy violations detected',
    modifiedInput: null,
  };
}

// ============================================================================
// Main Hook Logic
// ============================================================================

async function main() {
  const circuit = checkCircuit(HOOK_NAME);
  if (!circuit.shouldExecute) {
    console.error(`⚡ [Governor] Circuit ${circuit.state}: Skipping execution`);
    process.exit(0);
  }

  const startTime = Date.now();

  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), 400)
      )
    ]);

    if (!input || input.trim() === '') {
      process.exit(0);
    }

    const data: HookInput = JSON.parse(input);

    if (!data.tool_name || !MONITORED_TOOLS.includes(data.tool_name)) {
      process.exit(0);
    }

    const params = data.tool_input || {};
    // Normalize Unicode to prevent homoglyph bypass attacks
    const normalizedParams = normalizeParams(params);

    // ========== L12 PROFILE ENFORCEMENT ==========
    // Load active profile set by L12 SessionStart hook
    const activeProfile = loadActiveProfile();
    if (activeProfile && activeProfile.name !== 'dev') {
      // Check if tool is allowed by profile
      const toolCheck = isToolAllowed(data.tool_name, activeProfile);
      if (!toolCheck.allowed) {
        console.error(`\n🔒 [Governor L1] BLOCKED by '${activeProfile.name}' profile`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Reason: ${toolCheck.reason}`);
        console.error(`    Change profile: VEX_TALON_PROFILE=dev claude\n`);

        // Log the profile violation
        logToAudit({
          timestamp: new Date().toISOString(),
          tool: data.tool_name,
          parameters: sanitizeParameters(params),
          policy_matched: `profile:${activeProfile.name}:tool-block`,
          action: 'BLOCK',
          severity: 'HIGH',
          input_modified: false,
          message: toolCheck.reason,
          evaluation_time_ms: Date.now() - startTime,
          session_id: data.session_id,
        });

        // Output block decision
        console.log(JSON.stringify({
          decision: 'block',
          reason: `🔒 L12 Profile Violation: ${toolCheck.reason}`,
        }));
        process.exit(2);
      }

      // Check path restrictions for Read/Write/Edit tools
      if (['Read', 'Write', 'Edit'].includes(data.tool_name)) {
        const filePath = String(normalizedParams.file_path || '');
        const operation = data.tool_name === 'Read' ? 'read' : 'write';
        const pathCheck = isPathAllowed(filePath, operation, activeProfile);
        if (!pathCheck.allowed) {
          console.error(`\n🔒 [Governor L1] PATH BLOCKED by '${activeProfile.name}' profile`);
          console.error(`    Path: ${filePath}`);
          console.error(`    Operation: ${operation}`);
          console.error(`    Reason: ${pathCheck.reason}\n`);

          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: sanitizeParameters(params),
            policy_matched: `profile:${activeProfile.name}:path-block`,
            action: 'BLOCK',
            severity: 'HIGH',
            input_modified: false,
            message: pathCheck.reason,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });

          console.log(JSON.stringify({
            decision: 'block',
            reason: `🔒 L12 Profile Violation: ${pathCheck.reason}`,
          }));
          process.exit(2);
        }
      }

      // Check bash command restrictions
      if (data.tool_name === 'Bash') {
        const command = String(normalizedParams.command || '');
        const bashCheck = isBashCommandAllowed(command, activeProfile);
        if (!bashCheck.allowed) {
          console.error(`\n🔒 [Governor L1] BASH BLOCKED by '${activeProfile.name}' profile`);
          console.error(`    Command: ${command.substring(0, 80)}...`);
          console.error(`    Reason: ${bashCheck.reason}\n`);

          logToAudit({
            timestamp: new Date().toISOString(),
            tool: data.tool_name,
            parameters: sanitizeParameters(params),
            policy_matched: `profile:${activeProfile.name}:bash-block`,
            action: 'BLOCK',
            severity: 'HIGH',
            input_modified: false,
            message: bashCheck.reason,
            evaluation_time_ms: Date.now() - startTime,
            session_id: data.session_id,
          });

          console.log(JSON.stringify({
            decision: 'block',
            reason: `🔒 L12 Profile Violation: ${bashCheck.reason}`,
          }));
          process.exit(2);
        }
      }
    }
    // ========== END L12 PROFILE ENFORCEMENT ==========

    const result = evaluatePolicies(data.tool_name, normalizedParams);
    const evaluationTime = Date.now() - startTime;

    const auditEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      tool: data.tool_name,
      parameters: sanitizeParameters(params),
      modified_input: result.modifiedInput ? sanitizeParameters(result.modifiedInput) : undefined,
      policy_matched: result.policy?.name || null,
      action: result.action,
      severity: result.severity,
      input_modified: result.modifiedInput !== null,
      message: result.message,
      evaluation_time_ms: evaluationTime,
      session_id: data.session_id,
    };
    logToAudit(auditEntry);

    if (result.severity === 'CRITICAL' || result.severity === 'HIGH') {
      if (result.modifiedInput) {
        console.error(`\n🛡️  [Governor L1] ${result.severity} violation INTERCEPTED`);
        console.error(`    Policy: ${result.policy?.name}`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Action: Input modified for safety`);
        console.error(`    Message: ${result.message}`);
        console.error('');
      } else {
        console.error(`\n⚠️  [Governor L1] ${result.severity} policy violation detected`);
        console.error(`    Policy: ${result.policy?.name}`);
        console.error(`    Tool: ${data.tool_name}`);
        console.error(`    Message: ${result.message}`);
        console.error('');
      }
    }

    if (result.modifiedInput) {
      const output: HookOutput = {
        tool_input: result.modifiedInput
      };
      console.log(JSON.stringify(output));
    }

    recordSuccess(HOOK_NAME);
    process.exit(0);

  } catch (error) {
    recordFailure(HOOK_NAME, String(error));
    console.error(`[Governor L1] Error: ${error}`);
    // Fail-closed: block operation if hook crashes (security-first)
    process.exit(2);
  }
}

main();
