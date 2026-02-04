#!/usr/bin/env node
/**
 * Vex-Talon Secure Code Enforcer - PreToolUse Hook (L0)
 *
 * Purpose: Enforce secure coding practices BEFORE writing security-sensitive code.
 *          BLOCKS CRITICAL vulnerabilities (SQL injection, command injection, secrets).
 *          WARNS on HIGH/MEDIUM vulnerabilities.
 *
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * @version 0.1.0
 * @date 2026-02-03
 */

import { appendFileSync, mkdirSync, existsSync } from 'fs';
import { join, extname, dirname } from 'path';
// Note: config-loader available but using bundled defaults for reliability
// import { loadCodeEnforcerConfig, compilePattern } from '../lib/config-loader';

// ============================================================================
// Types
// ============================================================================

interface HookInput {
  session_id: string;
  transcript_path: string;
  hook_event_name: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
}

type CodeType = 'SECURITY_SENSITIVE' | 'SAFE' | 'UNKNOWN';
type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface ClassificationResult {
  type: CodeType;
  riskLevel: RiskLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  triggers: string[];
  suggestReview: boolean;
}

interface AuditEntry {
  timestamp: string;
  tool: string;
  file_path: string;
  language: string;
  classification: CodeType;
  risk_level: RiskLevel;
  confidence: string;
  triggers: string[];
  suggested_review: boolean;
  session_id: string;
  blocked: boolean;
  block_reason?: string;
}

// ============================================================================
// Configuration
// ============================================================================

const WRITE_TOOLS = ['Write', 'Edit'];

const CODE_EXTENSIONS: Record<string, string> = {
  '.py': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.sh': 'shell',
  '.bash': 'shell',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.php': 'php',
  '.java': 'java',
  '.sql': 'sql',
};

// ============================================================================
// Security Patterns (Hardcoded Defaults)
// ============================================================================

// CRITICAL: SQL Injection vectors
const SQL_PATTERNS = {
  injection: [
    /f["'].*SELECT.*WHERE.*\{/i,
    /f["'].*INSERT.*VALUES.*\{/i,
    /f["'].*UPDATE.*SET.*\{/i,
    /f["'].*DELETE.*WHERE.*\{/i,
    /\.format\(.*\).*SELECT/i,
    /`.*SELECT.*\$\{/i,
    /\+\s*["'].*SELECT/i,
    /["'].*SELECT.*["']\s*\+/i,
    /execute\s*\(\s*f["']/i,
    /query\s*=\s*f["']/i,
  ],
  keywords: /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b/i,
};

// CRITICAL: Command Injection vectors
const COMMAND_PATTERNS = {
  injection: [
    /subprocess\.run\(.*shell\s*=\s*True/i,
    /subprocess\.call\(.*shell\s*=\s*True/i,
    /subprocess\.Popen\(.*shell\s*=\s*True/i,
    /os\.system\s*\(/i,
    /os\.popen\s*\(/i,
    /exec\s*\(\s*f["']/i,
    /eval\s*\(/i,
    /child_process\.exec\s*\(/i,
    /execSync\s*\(/i,
    /spawn\s*\(.*shell:\s*true/i,
  ],
  keywords: /\b(subprocess|os\.system|os\.popen|exec|eval|child_process|spawn|execSync)\b/,
};

// CRITICAL: Hardcoded Secrets
const SECRET_PATTERNS = {
  apiKeys: [
    /["']sk-[a-zA-Z0-9]{20,}["']/,          // OpenAI
    /["']pplx-[a-zA-Z0-9]{20,}["']/,        // Perplexity
    /["']ghp_[a-zA-Z0-9]{36}["']/,          // GitHub PAT
    /["']gho_[a-zA-Z0-9]{36}["']/,          // GitHub OAuth
    /["']AKIA[A-Z0-9]{16}["']/,             // AWS Access Key
  ],
  passwords: [
    /password\s*=\s*["'][^"']+["']/i,
    /passwd\s*=\s*["'][^"']+["']/i,
    /secret\s*=\s*["'][^"']+["']/i,
    /api_key\s*=\s*["'][^"']+["']/i,
    /apiKey\s*=\s*["'][^"']+["']/i,
  ],
};

// HIGH: Path Traversal
const FILE_PATTERNS = {
  traversal: [
    /open\s*\(\s*f["']/i,
    /open\s*\(.*\+/i,
    /readFile\s*\(.*\+/i,
    /writeFile\s*\(.*\+/i,
    /\.\.\/|\.\.\\/ ,
  ],
};

// HIGH: Unsafe Deserialization
const DESERIALIZATION_PATTERNS = {
  unsafe: [
    /pickle\.load/i,
    /pickle\.loads/i,
    /yaml\.load\s*\([^)]*(?!Loader)/i,
    /yaml\.unsafe_load/i,
    /marshal\.load/i,
  ],
};

// HIGH: Prompt Injection (LLM)
const PROMPT_PATTERNS = {
  injection: [
    /f["'].*\{user/i,
    /f["'].*\{input/i,
    /f["'].*\{query/i,
    /`.*\$\{.*user/i,
    /prompt\s*=\s*f["']/i,
  ],
};

// MEDIUM: XSS vectors
const XSS_PATTERNS = {
  vectors: [
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /document\.write\s*\(/i,
    /dangerouslySetInnerHTML/i,
  ],
};

// MEDIUM: Weak Crypto
const CRYPTO_PATTERNS = {
  weak: [
    /hashlib\.md5/i,
    /hashlib\.sha1/i,
    /MD5\s*\(/i,
    /SHA1\s*\(/i,
    /DES\s*\(/i,
  ],
};

// ============================================================================
// Helper Functions
// ============================================================================

function getLanguageFromPath(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  return CODE_EXTENSIONS[ext] || 'unknown';
}

function isCodeFile(filePath: string): boolean {
  const ext = extname(filePath).toLowerCase();
  return ext in CODE_EXTENSIONS;
}

function normalizeContent(content: string): string {
  // Basic Unicode normalization for security scanning
  return content.normalize('NFKC');
}

// ============================================================================
// Code Classification
// ============================================================================

function classifyCode(content: string, _language: string): ClassificationResult {
  const normalizedContent = normalizeContent(content);
  const triggers: string[] = [];

  // Check CRITICAL patterns first (these will BLOCK)

  // SQL Injection (CRITICAL)
  if (SQL_PATTERNS.keywords.test(normalizedContent)) {
    for (const pattern of SQL_PATTERNS.injection) {
      if (pattern.test(normalizedContent)) {
        triggers.push('SQL injection vector detected');
        return {
          type: 'SECURITY_SENSITIVE',
          riskLevel: 'CRITICAL',
          confidence: 'HIGH',
          reason: 'SQL injection vulnerability: Use parameterized queries instead',
          triggers,
          suggestReview: true,
        };
      }
    }
  }

  // Command Injection (CRITICAL)
  if (COMMAND_PATTERNS.keywords.test(normalizedContent)) {
    for (const pattern of COMMAND_PATTERNS.injection) {
      if (pattern.test(normalizedContent)) {
        triggers.push('Command injection vector detected');
        return {
          type: 'SECURITY_SENSITIVE',
          riskLevel: 'CRITICAL',
          confidence: 'HIGH',
          reason: 'Command injection vulnerability: Use subprocess with arg list, not shell=True',
          triggers,
          suggestReview: true,
        };
      }
    }
  }

  // Hardcoded Secrets (CRITICAL)
  for (const pattern of SECRET_PATTERNS.apiKeys) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Hardcoded API key detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'CRITICAL',
        confidence: 'HIGH',
        reason: 'Hardcoded secret: Use environment variables or secret manager',
        triggers,
        suggestReview: true,
      };
    }
  }

  for (const pattern of SECRET_PATTERNS.passwords) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Hardcoded password/secret detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'CRITICAL',
        confidence: 'HIGH',
        reason: 'Hardcoded secret: Use environment variables or secret manager',
        triggers,
        suggestReview: true,
      };
    }
  }

  // Check HIGH patterns (warn but allow)

  // Path Traversal (HIGH)
  for (const pattern of FILE_PATTERNS.traversal) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Path traversal risk detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'HIGH',
        confidence: 'MEDIUM',
        reason: 'Path traversal risk: Validate and sanitize file paths',
        triggers,
        suggestReview: true,
      };
    }
  }

  // Unsafe Deserialization (HIGH)
  for (const pattern of DESERIALIZATION_PATTERNS.unsafe) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Unsafe deserialization detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'HIGH',
        confidence: 'HIGH',
        reason: 'Unsafe deserialization: Use safe alternatives with explicit loaders',
        triggers,
        suggestReview: true,
      };
    }
  }

  // Prompt Injection (HIGH)
  for (const pattern of PROMPT_PATTERNS.injection) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Prompt injection risk detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'HIGH',
        confidence: 'MEDIUM',
        reason: 'Prompt injection risk: Sanitize user input before including in prompts',
        triggers,
        suggestReview: true,
      };
    }
  }

  // Check MEDIUM patterns (warn)

  // XSS (MEDIUM)
  for (const pattern of XSS_PATTERNS.vectors) {
    if (pattern.test(normalizedContent)) {
      triggers.push('XSS vector detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'MEDIUM',
        confidence: 'HIGH',
        reason: 'XSS risk: Use safe DOM methods or sanitize HTML',
        triggers,
        suggestReview: true,
      };
    }
  }

  // Weak Crypto (MEDIUM)
  for (const pattern of CRYPTO_PATTERNS.weak) {
    if (pattern.test(normalizedContent)) {
      triggers.push('Weak cryptography detected');
      return {
        type: 'SECURITY_SENSITIVE',
        riskLevel: 'MEDIUM',
        confidence: 'HIGH',
        reason: 'Weak crypto: Use SHA-256 or stronger for hashing',
        triggers,
        suggestReview: true,
      };
    }
  }

  // No security issues detected
  return {
    type: 'SAFE',
    riskLevel: 'LOW',
    confidence: 'LOW',
    reason: 'No obvious security-sensitive patterns detected',
    triggers: [],
    suggestReview: false,
  };
}

// ============================================================================
// Audit Logging
// ============================================================================

function logAudit(entry: AuditEntry, logPath: string): void {
  try {
    const logDir = dirname(logPath);
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true });
    }
    appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch (error) {
    // Fail silently for audit logging
    console.error(`[SecureCodeEnforcer] Audit log error: ${error}`);
  }
}

// ============================================================================
// Main Hook Handler
// ============================================================================

async function main(): Promise<void> {
  const input = await Bun.stdin.text();
  const hookInput: HookInput = JSON.parse(input);

  const { tool_name, tool_input, session_id, cwd } = hookInput;

  // Only process Write/Edit tools
  if (!tool_name || !WRITE_TOOLS.includes(tool_name)) {
    console.log(JSON.stringify({ decision: 'approve' }));
    return;
  }

  // Extract file path and content
  const filePath = tool_input?.file_path as string;
  const content = (tool_input?.content || tool_input?.new_string) as string;

  if (!filePath || !content) {
    console.log(JSON.stringify({ decision: 'approve' }));
    return;
  }

  // Skip non-code files
  if (!isCodeFile(filePath)) {
    console.log(JSON.stringify({ decision: 'approve' }));
    return;
  }

  const language = getLanguageFromPath(filePath);

  // Classify the code
  const classification = classifyCode(content, language);

  // Determine log path
  const logPath = cwd
    ? join(cwd, '.vex-talon', 'logs', 'secure-code-enforcer.jsonl')
    : join(process.cwd(), '.vex-talon', 'logs', 'secure-code-enforcer.jsonl');

  // Prepare audit entry
  const auditEntry: AuditEntry = {
    timestamp: new Date().toISOString(),
    tool: tool_name,
    file_path: filePath,
    language,
    classification: classification.type,
    risk_level: classification.riskLevel,
    confidence: classification.confidence,
    triggers: classification.triggers,
    suggested_review: classification.suggestReview,
    session_id,
    blocked: false,
  };

  // Handle CRITICAL findings - BLOCK
  if (classification.riskLevel === 'CRITICAL') {
    auditEntry.blocked = true;
    auditEntry.block_reason = classification.reason;
    logAudit(auditEntry, logPath);

    console.log(JSON.stringify({
      decision: 'block',
      reason: `🛡️ [L0 Secure Code Enforcer] BLOCKED: ${classification.reason}\n\n` +
        `Triggers: ${classification.triggers.join(', ')}\n\n` +
        `Fix the vulnerability and try again.`,
    }));
    return;
  }

  // Handle HIGH findings - warn but allow
  if (classification.riskLevel === 'HIGH') {
    logAudit(auditEntry, logPath);

    console.log(JSON.stringify({
      decision: 'approve',
      additionalContext: `⚠️ [L0 Secure Code Enforcer] WARNING: ${classification.reason}\n` +
        `Triggers: ${classification.triggers.join(', ')}\n` +
        `Consider running secure-code-review before committing.`,
    }));
    return;
  }

  // Handle MEDIUM findings - log only
  if (classification.riskLevel === 'MEDIUM') {
    logAudit(auditEntry, logPath);
  }

  // Default: approve
  console.log(JSON.stringify({ decision: 'approve' }));
}

// Run
main().catch((error) => {
  console.error(`[SecureCodeEnforcer] Fatal error: ${error}`);
  console.log(JSON.stringify({ decision: 'approve' })); // Fail open
  process.exit(1);
});
