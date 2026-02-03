/**
 * @vex-talon/core - Security hooks and policies
 *
 * This package contains the 20-layer defense-in-depth architecture for Vex-Talon.
 *
 * Layers implemented:
 * - L0: Secure Code Enforcer (PreToolUse)
 * - L4: Injection Scanner (PostToolUse)
 *
 * Layers coming soon:
 * - L1: Governor Agent (PreToolUse)
 * - L2: Secure Code Linter (PostToolUse)
 * - L3: Memory Validation (Pre+PostToolUse)
 * - L5: Output Sanitizer (PostToolUse)
 * - L6: Git Pre-commit (Git Hook)
 * - L7: Image Safety Scanner (PostToolUse)
 * - L8: Evaluator Agent (Git Hook)
 * - L9: Egress Scanner (PreToolUse)
 * - L10: Native Sandbox (Built-in)
 * - L11: Leash Kernel Sandbox (External)
 * - L12: Least Privilege Profiles (SessionStart)
 * - L13: Strawberry Hallucination (MCP)
 * - L14: Supply Chain Scanner (PostToolUse)
 * - L15: RAG Security Scanner (Pre-index)
 * - L16: Human (Decision Authority)
 * - L17: Spend Alerting (PostToolUse)
 * - L18: MCP Audit (SessionStart)
 * - L19: Skill Scanner (PreToolUse+SessionStart)
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
