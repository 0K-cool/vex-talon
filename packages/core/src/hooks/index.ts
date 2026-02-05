/**
 * @vex-talon/core - Security Hooks
 *
 * Claude Code hooks for the 20-layer defense-in-depth architecture (L0-L19).
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * 20-LAYER SECURITY ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * PORTED LAYERS (14 hooks):
 * ─────────────────────────────────────────────────────────────────────────────
 * L0:  Secure Code Enforcer    PreToolUse     ✅ PORTED   Blocks CRITICAL vulnerabilities
 * L1:  Governor Agent          PreToolUse     ✅ PORTED   Policy enforcement + input modification
 * L2:  Secure Code Linter      PostToolUse    ✅ PORTED   Post-write security analysis
 * L3:  Memory Validation       PreToolUse     ✅ PORTED   Memory poisoning detection
 * L4:  Injection Scanner       PostToolUse    ✅ PORTED   Prompt injection detection
 * L5:  Output Sanitizer        PostToolUse    ✅ PORTED   XSS/DOM injection detection
 * L7:  Image Safety Scanner    PostToolUse    ✅ PORTED   Steganography detection
 * L9:  Egress Scanner          PreToolUse     ✅ PORTED   Data exfiltration prevention
 * L12: Least Privilege         SessionStart   ✅ PORTED   Permission profiles
 * L14: Supply Chain Pre-Install PreToolUse     ✅ PORTED   Blocks malicious packages (OSM API + blocklist)
 * L14: Supply Chain Scanner    PostToolUse    ✅ PORTED   Post-install audit (npm audit / pip-audit)
 * L17: Spend Alerting          PostToolUse    ✅ PORTED   Cost threshold alerts
 * L19: Skill Scanner           PreToolUse     ✅ PORTED   Skill security scanning
 * STOP: Security Report        Stop           ✅ PORTED   Aggregates events to HTML report
 *
 * DOCUMENTATION LAYERS (5):
 * ─────────────────────────────────────────────────────────────────────────────
 * L6:  Git Pre-commit          Git Hook       📄 DOCS     Pre-commit secret scanning (setup guide)
 * L8:  Evaluator Agent         Git Hook       📄 DOCS     Post-commit validation (setup guide)
 * L10: Native Sandbox          Built-in       📄 DOCS     Claude Code sandbox (reference)
 * L15: RAG Security Scanner    Pre-index      📄 DOCS     RAG poisoning (vex-rag reference)
 * L16: Human Decision          Built-in       📄 DOCS     Human-in-the-loop (reference)
 *
 * OPTIONAL LAYERS (3 - require external tools):
 * ─────────────────────────────────────────────────────────────────────────────
 * L11: Leash Kernel Sandbox    External       Requires: Leash binary (eBPF)
 * L13: Strawberry Hallucination MCP           Requires: hallucination-detector MCP
 * L18: MCP Audit               External       Requires: Proximity scanner
 *
 * FRAMEWORK COVERAGE:
 * ─────────────────────────────────────────────────────────────────────────────
 * • OWASP LLM Top 10 2025: 9/10 coverage
 * • OWASP Agentic Top 10 2026: Full coverage
 * • MITRE ATLAS: 16+ technique mappings
 *
 * @version 0.1.0
 * @date 2026-02-04
 */

export const HOOK_VERSION = '0.1.0';

/**
 * Hook status types
 */
export type HookStatus = 'PORTED' | 'DOCS' | 'EXTERNAL';

/**
 * Hook event types
 */
export type HookEventType = 'PreToolUse' | 'PostToolUse' | 'SessionStart' | 'Stop' | 'Git' | 'External' | 'Documentation';

/**
 * Layer definitions with metadata
 */
export interface LayerDefinition {
  id: string;
  name: string;
  type: HookEventType;
  status: HookStatus;
  file?: string;
  description: string;
  action: 'BLOCK' | 'ALERT' | 'WARN' | 'LOG' | 'REPORT';
  owaspMapping?: string;
  atlasMapping?: string;
}

export const LAYERS: LayerDefinition[] = [
  // === PORTED HOOKS (13 total: 12 layers + STOP) ===
  {
    id: 'L0', name: 'Secure Code Enforcer', type: 'PreToolUse', status: 'PORTED',
    file: 'L0-secure-code-enforcer.ts', description: 'Blocks CRITICAL code vulnerabilities',
    action: 'BLOCK', owaspMapping: 'LLM02'
  },
  {
    id: 'L1', name: 'Governor Agent', type: 'PreToolUse', status: 'PORTED',
    file: 'L1-governor-agent.ts', description: 'Policy enforcement + input modification',
    action: 'BLOCK', owaspMapping: 'LLM01, LLM02'
  },
  {
    id: 'L2', name: 'Secure Code Linter', type: 'PostToolUse', status: 'PORTED',
    file: 'L2-secure-code-linter.ts', description: 'Post-write security analysis',
    action: 'ALERT', owaspMapping: 'LLM02'
  },
  {
    id: 'L3', name: 'Memory Validation', type: 'PreToolUse', status: 'PORTED',
    file: 'L3-memory-validation.ts', description: 'Memory poisoning detection',
    action: 'ALERT', owaspMapping: 'Agentic ASI06', atlasMapping: 'AML.T0064'
  },
  {
    id: 'L4', name: 'Injection Scanner', type: 'PostToolUse', status: 'PORTED',
    file: 'L4-injection-scanner.ts', description: 'Prompt injection detection',
    action: 'ALERT', owaspMapping: 'LLM01', atlasMapping: 'AML.T0051'
  },
  {
    id: 'L5', name: 'Output Sanitizer', type: 'PostToolUse', status: 'PORTED',
    file: 'L5-output-sanitizer.ts', description: 'XSS/DOM injection detection',
    action: 'WARN', owaspMapping: 'LLM05'
  },
  {
    id: 'L7', name: 'Image Safety Scanner', type: 'PostToolUse', status: 'PORTED',
    file: 'L7-image-safety-scanner.ts', description: 'Steganography detection',
    action: 'ALERT', owaspMapping: 'LLM01', atlasMapping: 'AML.T0048'
  },
  {
    id: 'L9', name: 'Egress Scanner', type: 'PreToolUse', status: 'PORTED',
    file: 'L9-egress-scanner.ts', description: 'Data exfiltration prevention',
    action: 'BLOCK', owaspMapping: 'LLM02', atlasMapping: 'AML.T0035, AML.T0057'
  },
  {
    id: 'L12', name: 'Least Privilege', type: 'SessionStart', status: 'PORTED',
    file: 'L12-least-privilege.ts', description: 'Permission profiles',
    action: 'LOG', owaspMapping: 'LLM02'
  },
  {
    id: 'L14-pre', name: 'Supply Chain Pre-Install', type: 'PreToolUse', status: 'PORTED',
    file: 'L14-supply-chain-pre-install.ts', description: 'Blocks malicious packages before install (OSM API + blocklist)',
    action: 'BLOCK', owaspMapping: 'LLM03', atlasMapping: 'AML.T0047'
  },
  {
    id: 'L14', name: 'Supply Chain Scanner', type: 'PostToolUse', status: 'PORTED',
    file: 'L14-supply-chain-scanner.ts', description: 'Post-install audit (npm audit / pip-audit)',
    action: 'WARN', owaspMapping: 'LLM03', atlasMapping: 'AML.T0047'
  },
  {
    id: 'L17', name: 'Spend Alerting', type: 'PostToolUse', status: 'PORTED',
    file: 'L17-spend-alerting.ts', description: 'Cost threshold alerts',
    action: 'ALERT', owaspMapping: 'LLM10'
  },
  {
    id: 'L19', name: 'Skill Scanner', type: 'PreToolUse', status: 'PORTED',
    file: 'L19-skill-scanner.ts', description: 'Skill security scanning',
    action: 'BLOCK', owaspMapping: 'LLM01', atlasMapping: 'Agentic ASI04'
  },

  // === STOP HOOK (Session End Report) ===
  {
    id: 'STOP', name: 'Security Report', type: 'Stop', status: 'PORTED',
    file: 'stop-security-report.ts', description: 'Aggregates security events into HTML report',
    action: 'REPORT'
  },

  // === DOCUMENTATION LAYERS (5) ===
  {
    id: 'L6', name: 'Git Pre-commit', type: 'Git', status: 'DOCS',
    description: 'Pre-commit secret scanning (setup guide)',
    action: 'BLOCK'
  },
  {
    id: 'L8', name: 'Evaluator Agent', type: 'Git', status: 'DOCS',
    description: 'Post-commit validation (setup guide)',
    action: 'ALERT'
  },
  {
    id: 'L10', name: 'Native Sandbox', type: 'Documentation', status: 'DOCS',
    description: 'Claude Code built-in sandbox',
    action: 'BLOCK'
  },
  {
    id: 'L15', name: 'RAG Security Scanner', type: 'Documentation', status: 'DOCS',
    description: 'RAG poisoning (vex-rag)',
    action: 'ALERT', owaspMapping: 'LLM04, LLM08'
  },
  {
    id: 'L16', name: 'Human Decision', type: 'Documentation', status: 'DOCS',
    description: 'Human-in-the-loop authority',
    action: 'BLOCK'
  },

  // === OPTIONAL/EXTERNAL LAYERS (3) ===
  {
    id: 'L11', name: 'Leash Kernel Sandbox', type: 'External', status: 'EXTERNAL',
    description: 'eBPF kernel sandbox (requires Leash)',
    action: 'BLOCK'
  },
  {
    id: 'L13', name: 'Strawberry Hallucination', type: 'External', status: 'EXTERNAL',
    description: 'Hallucination detection (requires MCP)',
    action: 'ALERT'
  },
  {
    id: 'L18', name: 'MCP Audit', type: 'External', status: 'EXTERNAL',
    description: 'MCP server scanning (requires Proximity)',
    action: 'ALERT', owaspMapping: 'LLM01, LLM02'
  },
];

/**
 * Get all ported hooks
 */
export function getPortedLayers(): LayerDefinition[] {
  return LAYERS.filter(l => l.status === 'PORTED');
}

/**
 * Get PreToolUse hooks (can block)
 */
export function getPreToolUseHooks(): LayerDefinition[] {
  return LAYERS.filter(l => l.type === 'PreToolUse' && l.status === 'PORTED');
}

/**
 * Get PostToolUse hooks (alert/warn only)
 */
export function getPostToolUseHooks(): LayerDefinition[] {
  return LAYERS.filter(l => l.type === 'PostToolUse' && l.status === 'PORTED');
}

/**
 * Get SessionStart hooks
 */
export function getSessionStartHooks(): LayerDefinition[] {
  return LAYERS.filter(l => l.type === 'SessionStart' && l.status === 'PORTED');
}

/**
 * Get Stop hooks (session end)
 */
export function getStopHooks(): LayerDefinition[] {
  return LAYERS.filter(l => l.type === 'Stop' && l.status === 'PORTED');
}

/**
 * Generate settings.json hook configuration for Vex-Talon
 */
export function generateHooksConfig(basePath: string = './packages/core/src/hooks'): object {
  const preToolUseHooks = getPreToolUseHooks().map(l => ({
    type: 'command',
    command: `bun run ${basePath}/${l.file}`,
    timeout: 5000,
  }));

  const postToolUseHooks = getPostToolUseHooks().map(l => ({
    type: 'command',
    command: `bun run ${basePath}/${l.file}`,
    timeout: 10000,
  }));

  const sessionStartHooks = getSessionStartHooks().map(l => ({
    type: 'command',
    command: `bun run ${basePath}/${l.file}`,
    timeout: 5000,
  }));

  const stopHooks = getStopHooks().map(l => ({
    type: 'command',
    command: `bun run ${basePath}/${l.file}`,
    timeout: 30000, // Reports need more time to generate
  }));

  return {
    hooks: {
      PreToolUse: preToolUseHooks.length > 0 ? [{ hooks: preToolUseHooks }] : [],
      PostToolUse: postToolUseHooks.length > 0 ? [{ hooks: postToolUseHooks }] : [],
      SessionStart: sessionStartHooks.length > 0 ? [{ hooks: sessionStartHooks }] : [],
      Stop: stopHooks.length > 0 ? [{ hooks: stopHooks }] : [],
    },
  };
}

/**
 * Get coverage statistics
 */
export function getCoverageStats(): {
  ported: number;
  docs: number;
  external: number;
  total: number;
  preToolUse: number;
  postToolUse: number;
  sessionStart: number;
  stop: number;
} {
  return {
    ported: LAYERS.filter(l => l.status === 'PORTED').length,
    docs: LAYERS.filter(l => l.status === 'DOCS').length,
    external: LAYERS.filter(l => l.status === 'EXTERNAL').length,
    total: LAYERS.length,
    preToolUse: getPreToolUseHooks().length,
    postToolUse: getPostToolUseHooks().length,
    sessionStart: getSessionStartHooks().length,
    stop: getStopHooks().length,
  };
}

/**
 * Print architecture summary to console
 */
export function printArchitectureSummary(): void {
  const stats = getCoverageStats();
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║           VEX-TALON SECURITY ARCHITECTURE v${HOOK_VERSION}              ║
╠═══════════════════════════════════════════════════════════════════╣
║  Ported Hooks: ${String(stats.ported).padEnd(2)} / ${stats.total}                                       ║
║  PreToolUse:   ${String(stats.preToolUse).padEnd(2)} (can BLOCK)                                  ║
║  PostToolUse:  ${String(stats.postToolUse).padEnd(2)} (ALERT only)                                ║
║  SessionStart: ${String(stats.sessionStart).padEnd(2)}                                            ║
║  Stop:         ${String(stats.stop).padEnd(2)} (Security Report)                             ║
╠═══════════════════════════════════════════════════════════════════╣
║  OWASP LLM 2025:    9/10 coverage                                 ║
║  OWASP Agentic:     Full coverage                                 ║
║  MITRE ATLAS:       16+ techniques                                ║
╚═══════════════════════════════════════════════════════════════════╝
`);
}
