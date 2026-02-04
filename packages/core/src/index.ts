/**
 * @vex-talon/core - Security hooks and policies
 *
 * This package contains the 20-layer defense-in-depth architecture for Vex-Talon.
 *
 * PORTED LAYERS (13 hooks):
 * - L0:   Secure Code Enforcer    PreToolUse     BLOCK     Blocks CRITICAL vulnerabilities
 * - L1:   Governor Agent          PreToolUse     BLOCK     Policy enforcement + input modification
 * - L2:   Secure Code Linter      PostToolUse    ALERT     Post-write security analysis
 * - L3:   Memory Validation       PreToolUse     ALERT     Memory poisoning detection
 * - L4:   Injection Scanner       PostToolUse    ALERT     Prompt injection detection
 * - L5:   Output Sanitizer        PostToolUse    WARN      XSS/DOM injection detection
 * - L7:   Image Safety Scanner    PostToolUse    ALERT     Steganography detection
 * - L9:   Egress Scanner          PreToolUse     BLOCK     Data exfiltration prevention
 * - L12:  Least Privilege         SessionStart   LOG       Permission profiles
 * - L14:  Supply Chain Scanner    PostToolUse    WARN      Malicious package detection
 * - L17:  Spend Alerting          PostToolUse    ALERT     Cost threshold alerts
 * - L19:  Skill Scanner           PreToolUse     BLOCK     Skill security scanning
 * - STOP: Security Report         Stop           REPORT    Session-end security report
 *
 * DOCUMENTATION LAYERS (5 - setup guides):
 * - L6:   Git Pre-commit          Git Hook                 Pre-commit secret scanning
 * - L8:   Evaluator Agent         Git Hook                 Post-commit validation
 * - L10:  Native Sandbox          Built-in                 Claude Code sandbox
 * - L15:  RAG Security Scanner    Pre-index                RAG poisoning (vex-rag)
 * - L16:  Human Decision          Built-in                 Human-in-the-loop authority
 *
 * OPTIONAL LAYERS (3 - require external tools):
 * - L11:  Leash Kernel Sandbox    External                 Requires Leash binary
 * - L13:  Strawberry Hallucination MCP                     Requires hallucination-detector
 * - L18:  MCP Audit               External                 Requires Proximity scanner
 *
 * FRAMEWORK COVERAGE:
 * - OWASP LLM Top 10 2025: 9/10
 * - OWASP Agentic Top 10 2026: Full
 * - MITRE ATLAS: 16+ techniques
 *
 * @version 0.1.0
 */

export const VERSION = '0.1.0';

// Export library utilities
export * from './lib';

// Export hook configuration
export * from './hooks';

// Re-export key types for consumers
export type {
  InjectionPattern,
  InjectionCategory,
  InjectionSeverity,
  ScanResult,
  ExtendedScanResult,
} from './lib/injection-patterns';

export type {
  SecurityConfig,
  ConfigMetadata,
  VulnerabilityPattern,
  MaliciousPackage,
} from './lib/config-loader';
