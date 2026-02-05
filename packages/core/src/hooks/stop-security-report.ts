#!/usr/bin/env bun

/**
 * Vex-Talon Security Report Generator - Stop Hook (Full v2)
 *
 * Ported from PAI Security Report Generator (SessionEnd Hook Enhanced v2)
 * to Vex-Talon plugin architecture.
 *
 * Purpose: Generate an interactive HTML security report at the end of each session
 *          summarizing Governor violations, injection scans, and security events.
 *
 * Pattern: Stop Hook (runs when session ends)
 * Output: ~/.vex-talon/reports/security-report-{timestamp}.html
 *
 * Data Sources:
 * - L0-secure-code-enforcer-audit.jsonl
 * - L1-governor-agent-audit.jsonl
 * - L2-secure-code-linter-audit.jsonl
 * - L3-memory-validation-audit.jsonl
 * - L4-injection-scanner-audit.jsonl
 * - L7-image-safety-scanner-audit.jsonl
 * - L8-evaluator-agent-audit.jsonl
 * - leash-events.jsonl
 * - errors.jsonl
 * - Session transcript (for conversation trace)
 *
 * Features:
 * - Dark theme (GitHub style), professional styling
 * - Collapsible sections with smooth animations
 * - Severity filtering
 * - Fully self-contained (no external dependencies)
 * - Works offline
 * - Auto-opens report in browser when security events detected
 * - SVG tool icons for visual identification (inspired by NOVA)
 * - Activity metrics (tokens, duration, tool calls)
 * - Conversation trace with timeline navigation
 * - Expandable event cards with full input/output
 * - Tab-based navigation
 * - Interactive filtering by severity
 * - MITRE ATLAS + OWASP LLM 2025 + OWASP Agentic 2026 mapping
 * - Haiku-powered executive summary
 *
 * Date: February 4, 2026 (Ported from PAI to Vex-Talon)
 * Credits: Inspired by fr0gger/nova-claude-code-protector report generator
 *
 * @version 1.0.0 (vex-talon full port)
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { execSync } from 'child_process';
import { TALON_DIR, LOGS_DIR, ensureDirectories } from './lib/talon-paths';

// ============================================================================
// SVG Tool Icons (inspired by NOVA)
// ============================================================================

const TOOL_ICONS: Record<string, string> = {
  Read: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
  Write: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  Edit: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`,
  Bash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  Glob: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>`,
  Grep: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><line x1="8" y1="11" x2="14" y2="11"/></svg>`,
  WebFetch: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  WebSearch: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M21 21l-4.35-4.35"/><line x1="2" y1="12" x2="22" y2="12"/></svg>`,
  Task: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>`,
  TodoWrite: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`,
  Skill: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  MCP: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
  default: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
};

// ============================================================================
// MITRE ATLAS & OWASP LLM Mapping
// ============================================================================

interface ATLASMapping {
  layer: string;
  layerName: string;
  description: string;
  atlasIds: string[];
  atlasNames: string[];
  owaspIds: string[];
  owaspNames: string[];
  owaspAgenticIds: string[];
  owaspAgenticNames: string[];
  status: 'active' | 'partial' | 'planned' | 'not_installed';
  source: 'plugin' | 'external' | 'builtin';
  setupHint?: string;
}

// Hardcoded layer mappings using sequential L0-L19 numbering
// (No YAML loading needed - plugin uses these directly)
const ATLAS_MAPPINGS: ATLASMapping[] = [
  {
    layer: '0',
    layerName: 'Secure Code Enforcer',
    description: 'PreToolUse hook blocks CRITICAL patterns (SQL injection, command injection, hardcoded secrets)',
    atlasIds: ['AML.T0057'],
    atlasNames: ['LLM Data Leakage'],
    owaspIds: ['LLM02'],
    owaspNames: ['Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI05'],
    owaspAgenticNames: ['Unexpected Code Execution'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '1',
    layerName: 'Governor Agent',
    description: 'PreToolUse hook with 43 policies (7 CRITICAL, 11 HIGH) - monitors all tool calls',
    atlasIds: ['AML.T0053', 'AML.T0062', 'AML.T0066'],
    atlasNames: ['LLM Plugin Compromise', 'Exfiltration via Agent Tools', 'Modify AI Agent Configuration'],
    owaspIds: ['LLM06', 'LLM02'],
    owaspNames: ['Excessive Agency', 'Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI02', 'ASI03', 'ASI07', 'ASI08', 'ASI10'],
    owaspAgenticNames: ['Tool Misuse & Exploitation', 'Identity & Privilege Abuse', 'Insecure Inter-Agent Communication', 'Cascading Failures', 'Rogue Agents'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '2',
    layerName: 'Secure Code Linter',
    description: 'PostToolUse 3-tier analysis with auto-revert on ERROR findings',
    atlasIds: ['AML.T0057'],
    atlasNames: ['LLM Data Leakage'],
    owaspIds: ['LLM02'],
    owaspNames: ['Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI05', 'ASI08'],
    owaspAgenticNames: ['Unexpected Code Execution', 'Cascading Failures'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '3',
    layerName: 'Memory Validation',
    description: 'PreToolUse + PostToolUse validates MCP Memory operations and alerts on poisoning',
    atlasIds: ['AML.T0064'],
    atlasNames: ['Memory Manipulation'],
    owaspIds: [],
    owaspNames: [],
    owaspAgenticIds: ['ASI06'],
    owaspAgenticNames: ['Memory & Context Poisoning'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '4',
    layerName: 'Injection Scanner',
    description: 'PostToolUse scans for prompt injection patterns in tool outputs (89 patterns)',
    atlasIds: ['AML.T0051', 'AML.T0051.001', 'AML.T0051.002', 'AML.T0056', 'AML.T0063', 'AML.T0065'],
    atlasNames: ['LLM Prompt Injection', 'Direct Prompt Injection', 'Indirect Prompt Injection', 'LLM Meta Prompt Extraction', 'AI Agent Context Poisoning', 'Thread Injection'],
    owaspIds: ['LLM01'],
    owaspNames: ['Prompt Injection'],
    owaspAgenticIds: ['ASI01'],
    owaspAgenticNames: ['Agent Goal Hijack'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '5',
    layerName: 'Output Sanitizer',
    description: 'PostToolUse scans web code for XSS vectors and improper output handling',
    atlasIds: [],
    atlasNames: [],
    owaspIds: ['LLM05', 'LLM02'],
    owaspNames: ['Improper Output Handling', 'Sensitive Information Disclosure'],
    owaspAgenticIds: [],
    owaspAgenticNames: [],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '6',
    layerName: 'Git Pre-commit',
    description: 'Git hook runs Governor policy checks before commits - BLOCKS on CRITICAL violations',
    atlasIds: ['AML.T0057', 'AML.T0066'],
    atlasNames: ['LLM Data Leakage', 'Modify AI Agent Configuration'],
    owaspIds: ['LLM02'],
    owaspNames: ['Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI02'],
    owaspAgenticNames: ['Tool Misuse & Exploitation'],
    status: 'active',
    source: 'external',
    setupHint: 'Add git pre-commit hook: .git/hooks/pre-commit',
  },
  {
    layer: '7',
    layerName: 'Image Safety Scanner',
    description: 'PostToolUse scans images for visual prompt injection, steganography, and adversarial content',
    atlasIds: ['AML.T0048', 'AML.T0051.002'],
    atlasNames: ['Adversarial Example', 'Indirect Prompt Injection'],
    owaspIds: ['LLM01'],
    owaspNames: ['Prompt Injection'],
    owaspAgenticIds: ['ASI01'],
    owaspAgenticNames: ['Agent Goal Hijack'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '8',
    layerName: 'Evaluator Agent',
    description: 'Post-commit git hook validates committed changes for secrets, PII, client data',
    atlasIds: ['AML.T0057'],
    atlasNames: ['LLM Data Leakage'],
    owaspIds: ['LLM02'],
    owaspNames: ['Sensitive Information Disclosure'],
    owaspAgenticIds: [],
    owaspAgenticNames: [],
    status: 'active',
    source: 'external',
    setupHint: 'Add git post-commit hook: .git/hooks/post-commit',
  },
  {
    layer: '9',
    layerName: 'Egress Scanner',
    description: 'PreToolUse scans WebFetch/WebSearch/Bash for secrets, PII, bulk exfiltration',
    atlasIds: ['AML.T0035', 'AML.T0062', 'AML.T0057', 'AML.T0067'],
    atlasNames: ['Exfiltration via ML Inference API', 'Exfiltration via Agent Tools', 'LLM Data Leakage', 'RAG Credential Harvesting'],
    owaspIds: ['LLM02', 'LLM06'],
    owaspNames: ['Sensitive Information Disclosure', 'Excessive Agency'],
    owaspAgenticIds: [],
    owaspAgenticNames: [],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '10',
    layerName: 'Native Sandbox',
    description: 'Claude Code OS-level sandbox (Seatbelt/bubblewrap) - fast, zero config',
    atlasIds: ['AML.T0053', 'AML.T0062'],
    atlasNames: ['LLM Plugin Compromise', 'Exfiltration via Agent Tools'],
    owaspIds: ['LLM06'],
    owaspNames: ['Excessive Agency'],
    owaspAgenticIds: ['ASI05'],
    owaspAgenticNames: ['Unexpected Code Execution'],
    status: 'active',
    source: 'builtin',
  },
  {
    layer: '11',
    layerName: 'Leash Kernel Sandbox',
    description: 'eBPF LSM + MITM Proxy for high-security sessions - NO escape hatch',
    atlasIds: ['AML.T0053', 'AML.T0062', 'AML.T0051.002', 'AML.T0035'],
    atlasNames: ['LLM Plugin Compromise', 'Exfiltration via Agent Tools', 'Indirect Prompt Injection', 'Exfiltration via ML Inference API'],
    owaspIds: ['LLM01', 'LLM06', 'LLM02'],
    owaspNames: ['Prompt Injection', 'Excessive Agency', 'Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI05'],
    owaspAgenticNames: ['Unexpected Code Execution'],
    status: 'active',
    source: 'external',
    setupHint: 'Install Leash kernel sandbox and set VEX_LEASH_ACTIVE=true',
  },
  {
    layer: '12',
    layerName: 'Least Privilege Profiles',
    description: 'Role-based tool access (dev, audit, client-work profiles)',
    atlasIds: ['AML.T0062', 'AML.T0053'],
    atlasNames: ['Exfiltration via Agent Tools', 'LLM Plugin Compromise'],
    owaspIds: ['LLM06'],
    owaspNames: ['Excessive Agency'],
    owaspAgenticIds: ['ASI02', 'ASI03'],
    owaspAgenticNames: ['Tool Misuse & Exploitation', 'Identity & Privilege Abuse'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '13',
    layerName: 'Strawberry Hallucination Detection',
    description: 'KL divergence-based procedural hallucination detection - catches ignored evidence',
    atlasIds: [],
    atlasNames: [],
    owaspIds: ['LLM09'],
    owaspNames: ['Misinformation'],
    owaspAgenticIds: ['ASI09'],
    owaspAgenticNames: ['Human-Agent Trust Exploitation'],
    status: 'active',
    source: 'external',
    setupHint: 'Add hallucination-detector MCP server to .mcp.json',
  },
  {
    layer: '14',
    layerName: 'Supply Chain Scanner',
    description: 'PostToolUse monitors npm/pip/yarn/cargo/go installs and runs vulnerability audits',
    atlasIds: ['AML.T0047'],
    atlasNames: ['ML Supply Chain Compromise'],
    owaspIds: ['LLM03'],
    owaspNames: ['Supply Chain'],
    owaspAgenticIds: ['ASI04'],
    owaspAgenticNames: ['Supply Chain Vulnerabilities'],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '15',
    layerName: 'RAG Security Scanner',
    description: 'Pre-indexing security - injection detection, unicode normalization, provenance tracking',
    atlasIds: ['AML.T0048', 'AML.T0068'],
    atlasNames: ['Adversarial Example', 'RAG Poisoning'],
    owaspIds: ['LLM04', 'LLM08'],
    owaspNames: ['Data and Model Poisoning', 'Vector and Embedding Weaknesses'],
    owaspAgenticIds: [],
    owaspAgenticNames: [],
    status: 'active',
    source: 'external',
    setupHint: 'Install vex-rag plugin with RAG security module',
  },
  {
    layer: '16',
    layerName: 'Human',
    description: 'User reviews and approves critical decisions - final authority in defense-in-depth',
    atlasIds: [],
    atlasNames: [],
    owaspIds: [],
    owaspNames: [],
    owaspAgenticIds: ['ASI09'],
    owaspAgenticNames: ['Human-Agent Trust Exploitation'],
    status: 'active',
    source: 'builtin',
  },
  {
    layer: '17',
    layerName: 'Spend Alerting',
    description: 'PostToolUse tracks cumulative session costs and warns at $5/$10/$20 thresholds',
    atlasIds: [],
    atlasNames: [],
    owaspIds: ['LLM10'],
    owaspNames: ['Unbounded Consumption'],
    owaspAgenticIds: [],
    owaspAgenticNames: [],
    status: 'active',
    source: 'plugin',
  },
  {
    layer: '18',
    layerName: 'MCP Audit',
    description: 'Pre-deployment scanning of MCP servers using Proximity + NOVA rules (22 detection patterns)',
    atlasIds: ['AML.T0051', 'AML.T0053'],
    atlasNames: ['LLM Prompt Injection', 'LLM Plugin Compromise'],
    owaspIds: ['LLM01', 'LLM02'],
    owaspNames: ['Prompt Injection', 'Sensitive Information Disclosure'],
    owaspAgenticIds: ['ASI06'],
    owaspAgenticNames: ['Memory and Context Manipulation'],
    status: 'active',
    source: 'external',
    setupHint: 'Install Proximity scanner: ~/tools/proximity/',
  },
  {
    layer: '19',
    layerName: 'Skill Scanner',
    description: 'Pre-invocation security scanning of skills with 45 patterns (injection, dangerous commands, credentials)',
    atlasIds: ['AML.T0051', 'AML.T0053'],
    atlasNames: ['LLM Prompt Injection', 'LLM Plugin Compromise'],
    owaspIds: ['LLM01', 'LLM06'],
    owaspNames: ['Prompt Injection', 'Excessive Agency'],
    owaspAgenticIds: ['ASI01', 'ASI02'],
    owaspAgenticNames: ['Agent Goal Hijack', 'Tool Misuse & Exploitation'],
    status: 'active',
    source: 'plugin',
  },
];

// ============================================================================
// Runtime Layer Detection
// ============================================================================

/**
 * Check if an MCP server is configured in .mcp.json (project or user level).
 */
function checkMcpServer(serverName: string): boolean {
  const mcpPaths = [
    join(process.cwd(), '.mcp.json'),
    join(homedir(), '.claude', '.mcp.json'),
  ];
  for (const p of mcpPaths) {
    try {
      const content = readFileSync(p, 'utf-8');
      if (content.includes(serverName)) return true;
    } catch {
      // File doesn't exist or not readable
    }
  }
  return false;
}

/**
 * Detect runtime status of external layers.
 * Plugin and builtin layers are always active.
 * External layers are probed via filesystem/env checks.
 */
function detectLayerStatus(): void {
  const cwd = process.cwd();

  for (const mapping of ATLAS_MAPPINGS) {
    if (mapping.source === 'plugin' || mapping.source === 'builtin') {
      mapping.status = 'active';
      continue;
    }

    // External layer detection
    switch (mapping.layer) {
      case '6': // Git Pre-commit
        mapping.status = existsSync(join(cwd, '.git/hooks/pre-commit')) ? 'active' : 'not_installed';
        break;
      case '8': // Evaluator Agent
        mapping.status = existsSync(join(cwd, '.git/hooks/post-commit')) ? 'active' : 'not_installed';
        break;
      case '11': // Leash Kernel Sandbox
        mapping.status = (
          process.env.VEX_LEASH_ACTIVE === 'true' ||
          existsSync('/opt/homebrew/bin/leash') ||
          existsSync(join(cwd, '.claude/scripts/vex-sandboxed'))
        ) ? 'active' : 'not_installed';
        break;
      case '13': // Strawberry Hallucination Detection
        mapping.status = checkMcpServer('hallucination-detector') ? 'active' : 'not_installed';
        break;
      case '15': // RAG Security Scanner
        mapping.status = checkMcpServer('vex-knowledge-base') ? 'active' : 'not_installed';
        break;
      case '18': // MCP Audit (Proximity)
        mapping.status = existsSync(join(homedir(), 'tools/proximity')) ? 'active' : 'not_installed';
        break;
    }
  }
}

// OWASP LLM Top 10 2025 Reference
// Updated January 28, 2026 to reflect official 2025 names
const OWASP_LLM_2025: Record<string, { name: string; severity: string; color: string }> = {
  LLM01: { name: 'Prompt Injection', severity: 'CRITICAL', color: '#f85149' },
  LLM02: { name: 'Sensitive Information Disclosure', severity: 'HIGH', color: '#f0883e' },
  LLM03: { name: 'Supply Chain', severity: 'HIGH', color: '#f0883e' },
  LLM04: { name: 'Data and Model Poisoning', severity: 'HIGH', color: '#f0883e' },
  LLM05: { name: 'Improper Output Handling', severity: 'MEDIUM', color: '#d29922' },
  LLM06: { name: 'Excessive Agency', severity: 'CRITICAL', color: '#f85149' },
  LLM07: { name: 'System Prompt Leakage', severity: 'HIGH', color: '#f0883e' },
  LLM08: { name: 'Vector and Embedding Weaknesses', severity: 'HIGH', color: '#f0883e' },
  LLM09: { name: 'Misinformation', severity: 'MEDIUM', color: '#d29922' },
  LLM10: { name: 'Unbounded Consumption', severity: 'MEDIUM', color: '#d29922' },
};

// OWASP Agentic 2026 Reference (for agentic AI systems)
// Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
// Coverage is calculated dynamically by calculateAgenticCoverage() based on active layers
const OWASP_AGENTIC_2026: Record<string, { name: string; severity: string; color: string; coverage: string }> = {
  ASI01: { name: 'Agent Goal Hijack', severity: 'CRITICAL', color: '#f85149', coverage: 'gap' },
  ASI02: { name: 'Tool Misuse & Exploitation', severity: 'CRITICAL', color: '#f85149', coverage: 'gap' },
  ASI03: { name: 'Identity & Privilege Abuse', severity: 'HIGH', color: '#f0883e', coverage: 'gap' },
  ASI04: { name: 'Supply Chain Vulnerabilities', severity: 'HIGH', color: '#f0883e', coverage: 'gap' },
  ASI05: { name: 'Unexpected Code Execution', severity: 'CRITICAL', color: '#f85149', coverage: 'gap' },
  ASI06: { name: 'Memory & Context Poisoning', severity: 'HIGH', color: '#f0883e', coverage: 'gap' },
  ASI07: { name: 'Insecure Inter-Agent Communication', severity: 'MEDIUM', color: '#d29922', coverage: 'gap' },
  ASI08: { name: 'Cascading Failures', severity: 'MEDIUM', color: '#d29922', coverage: 'gap' },
  ASI09: { name: 'Human-Agent Trust Exploitation', severity: 'HIGH', color: '#f0883e', coverage: 'gap' },
  ASI10: { name: 'Rogue Agents', severity: 'CRITICAL', color: '#f85149', coverage: 'gap' },
};

/**
 * Calculate OWASP Agentic 2026 coverage dynamically based on which layers are active.
 * - 2+ active layers covering an ASI → 'covered'
 * - 1 active layer covering an ASI → 'partial'
 * - 0 active layers covering an ASI → 'gap'
 * Special case: ASI06 is always 'partial' when active (detection-only due to Claude Code bug)
 */
function calculateAgenticCoverage(): void {
  for (const id of Object.keys(OWASP_AGENTIC_2026)) {
    const entry = OWASP_AGENTIC_2026[id];
    if (!entry) continue;
    const coveringLayers = ATLAS_MAPPINGS.filter(
      m => m.status === 'active' && m.owaspAgenticIds.includes(id)
    );
    if (coveringLayers.length >= 2) {
      entry.coverage = 'covered';
    } else if (coveringLayers.length === 1) {
      entry.coverage = 'partial';
    } else {
      entry.coverage = 'gap';
    }
  }
  // Special case: ASI06 is always 'partial' when L3 is active
  // L3 Memory Validation provides detection but cannot block due to Claude Code bugs #3514/#4669
  const l3 = ATLAS_MAPPINGS.find(m => m.layer === '3');
  const asi06 = OWASP_AGENTIC_2026['ASI06'];
  if (l3?.status === 'active' && asi06 && asi06.coverage === 'covered') {
    asi06.coverage = 'partial';
  }
}

// Use hardcoded mappings directly (no YAML loading in plugin context)
const ATLAS_MAPPINGS_LOADED = ATLAS_MAPPINGS;
const MAPPINGS_METADATA = null;
const MAPPINGS_IS_STALE = false;
const MAPPINGS_DAYS_OLD = 0;
const TOTAL_RELEVANT_ATLAS = 16;

// ============================================================================
// Types
// ============================================================================

interface GovernorAuditEntry {
  timestamp: string;
  tool: string;
  parameters?: Record<string, any>;
  policy_matched: string | null;
  action: string;
  severity: string;
  message: string;
  input_modified?: boolean;
  modification_type?: string;
  session_id: string;
}

interface EvaluatorFinding {
  type: string;
  description: string;
  line: string;
  file: string;
}

interface EvaluatorAuditEntry {
  timestamp: string;
  commit: string;
  commit_short: string;
  author: string;
  message: string;
  files_changed: number;
  security_issues: number;
  quality_warnings: number;
  status: 'PASSED' | 'PASSED_WITH_WARNINGS' | 'FAILED';
  security_findings?: EvaluatorFinding[];
  quality_findings?: EvaluatorFinding[];
}

interface InjectionScanEntry {
  timestamp: string;
  tool: string;
  session_id: string;
  content_length: number;
  scan_duration_ms: number;
  injection_detected: boolean;
  severity: string | null;
  patterns_matched: string[];
  categories: string[];
  content_snippet: string;
  action: string;
}

interface ImageSafetyIndicator {
  type: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  evidence?: string;
}

interface ImageSafetyEntry {
  timestamp: string;
  file_path: string;
  result: {
    suspicious: boolean;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    confidence: 'high' | 'medium' | 'low';
    indicators: ImageSafetyIndicator[];
    executionTime: number;
  };
  action_taken: 'allowed' | 'warned' | 'blocked' | 'quarantined';
}

interface SecureCodeEntry {
  timestamp: string;
  tool: string;
  file_path: string;
  language: string;
  classification: string;
  risk_level: string;
  confidence: string;
  triggers: string[];
  suggested_review: boolean;
  session_id: string;
}

interface SecureCodeLinterEntry {
  timestamp: string;
  event_type: string;
  severity: string;
  tool: string;
  file_path: string;
  action: string;
  findings_count: number;
  error_count: number;
  warning_count: number;
  top_findings: string[];
  reverted: boolean;
  quarantine_path?: string;
  // LLM review fields (when LLM tier 3 was triggered)
  tier?: number;
  escalation_reason?: string;
  llm_verdict?: string;
  llm_confidence?: string;
  llm_latency_ms?: number;
  llm_vulnerabilities?: Array<{ vulnerability: string; severity: string; }>;
}

interface ErrorEntry {
  timestamp: string;
  error?: { message?: string };
  level: string;
  message: string;
  source?: string;
  session_id?: string;
}

interface LeashEvent {
  timestamp: string;
  session_id: string;
  source: 'leash';
  event_type: string;
  action: string;
  resource: string;
  decision: 'ALLOW' | 'DENY';
  policy_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: 'FILESYSTEM' | 'NETWORK' | 'PROCESS' | 'MCP';
  details: Record<string, unknown>;
}

interface MemorySecurityEntry {
  timestamp: string;
  hookType: 'PreToolUse' | 'PostToolUse';
  tool: string;
  operation: 'create_entities' | 'create_relations' | 'add_observations' | 'other';
  findings: Array<{
    patternId: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    matchedText: string;
    location: string;
  }>;
  action?: 'ALLOW' | 'WARN' | 'BLOCK';
  highestSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  operationSucceeded?: boolean;
  alertLevel?: 'CRITICAL_ALERT' | 'HIGH_ALERT' | 'MEDIUM_ALERT' | 'LOW_ALERT' | 'NONE';
  evaluationTimeMs: number;
  sessionId: string;
}

interface TranscriptEntry {
  type: string;
  timestamp?: string;
  message?: {
    role?: string;
    content?: Array<{ type: string; text?: string; name?: string; input?: any }>;
  };
  toolName?: string;
  toolInput?: any;
  toolOutput?: any;
}

interface ConversationEvent {
  id: number;
  timestamp: string;
  type: 'user' | 'assistant' | 'tool';
  toolName?: string;
  content: string;
  details?: any;
}

interface ReportData {
  sessionId: string;
  generatedAt: string;
  sessionStart?: string;
  sessionEnd?: string;
  governorEvents: GovernorAuditEntry[];
  evaluatorEvents: EvaluatorAuditEntry[];
  injectionScans: InjectionScanEntry[];
  imageSafetyEvents: ImageSafetyEntry[];
  secureCodeEvents: SecureCodeEntry[];
  secureCodeLinterEvents: SecureCodeLinterEntry[];
  leashEvents: LeashEvent[];
  memorySecurityEvents: MemorySecurityEntry[];
  errors: ErrorEntry[];
  conversationTrace: ConversationEvent[];
  leashActive: boolean;
  summary: {
    totalToolCalls: number;
    policyViolations: number;
    injectionDetections: number;
    imageSafetyDetections: number;
    securitySensitiveWrites: number;
    memoryPoisoningAttempts: number;
    codeReverts: number;
    leashBlocks: number;
    errors: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    estimatedTokens: number;
    sessionDurationMs: number;
    overallStatus: 'CLEAN' | 'WARNINGS' | 'DETECTED';
    severityBreakdown: {
      critical: { governor: number; injection: number; imageSafety: number; secureCode: number; linter: number; leash: number; memory: number };
      high: { governor: number; injection: number; imageSafety: number; secureCode: number; linter: number; leash: number; memory: number };
      medium: { governor: number; injection: number; imageSafety: number; secureCode: number; linter: number; leash: number; memory: number };
      low: { governor: number; injection: number; imageSafety: number; secureCode: number; linter: number; leash: number; memory: number };
    };
  };
  vexAnalysis?: string;
}

// ============================================================================
// Configuration (Vex-Talon paths)
// ============================================================================

const REPORTS_DIR = join(TALON_DIR, 'reports');
const GOVERNOR_LOG = join(LOGS_DIR, 'L1-governor-agent-audit.jsonl');
const EVALUATOR_LOG = join(LOGS_DIR, 'L8-evaluator-agent-audit.jsonl');
const INJECTION_LOG = join(LOGS_DIR, 'L4-injection-scanner-audit.jsonl');
const IMAGE_SAFETY_LOG = join(LOGS_DIR, 'L7-image-safety-scanner-audit.jsonl');
const SECURE_CODE_LOG = join(LOGS_DIR, 'L0-secure-code-enforcer-audit.jsonl');
const SECURE_CODE_LINTER_LOG = join(LOGS_DIR, 'L2-secure-code-linter-audit.jsonl');
const LEASH_LOG = join(LOGS_DIR, 'leash-events.jsonl');
const MEMORY_SECURITY_LOG = join(LOGS_DIR, 'L3-memory-validation-audit.jsonl');
const ERRORS_LOG = join(LOGS_DIR, 'errors.jsonl');

// Only include events from last 4 hours (typical session length)
const MAX_AGE_HOURS = 4;

// ============================================================================
// Browser Integration
// ============================================================================

function openReportInBrowser(filepath: string): void {
  try {
    const { execFileSync } = require('child_process');
    const platform = process.platform;
    const openCmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    execFileSync(openCmd, [filepath], { stdio: 'ignore' });
    console.error('   Report opened in browser');
  } catch (error) {
    console.error(`   Could not open report: ${error}`);
  }
}

// ============================================================================
// Log Parsing
// ============================================================================

function readJsonlFile<T>(filePath: string, sessionId?: string): T[] {
  if (!existsSync(filePath)) {
    return [];
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const cutoff = Date.now() - MAX_AGE_HOURS * 60 * 60 * 1000;

    return lines
      .map((line) => {
        try {
          return JSON.parse(line) as T & { timestamp?: string; session_id?: string };
        } catch {
          return null;
        }
      })
      .filter((entry): entry is T => {
        if (!entry) return false;
        const e = entry as any;

        // Filter by session if available
        if (e.session_id && e.session_id !== sessionId) {
          return false;
        }

        // Filter by time
        if (e.timestamp) {
          const entryTime = new Date(e.timestamp).getTime();
          if (entryTime < cutoff) {
            return false;
          }
        }

        return true;
      });
  } catch {
    return [];
  }
}

function readTranscript(transcriptPath: string): ConversationEvent[] {
  if (!transcriptPath || !existsSync(transcriptPath)) {
    return [];
  }

  try {
    const content = readFileSync(transcriptPath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const events: ConversationEvent[] = [];
    let eventId = 0;

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as TranscriptEntry;

        if (entry.type === 'user' && entry.message?.content) {
          const textContent = entry.message.content
            .filter((c) => c.type === 'text' && c.text)
            .map((c) => c.text || '')
            .join('\n')
            .trim();

          if (textContent && !textContent.startsWith('<system-reminder>')) {
            events.push({
              id: eventId++,
              timestamp: entry.timestamp || new Date().toISOString(),
              type: 'user',
              content: textContent.substring(0, 500),
            });
          }
        } else if (entry.type === 'assistant' && entry.message?.content) {
          // Extract tool uses from assistant messages
          for (const content of entry.message.content) {
            if (content.type === 'tool_use' && content.name) {
              events.push({
                id: eventId++,
                timestamp: entry.timestamp || new Date().toISOString(),
                type: 'tool',
                toolName: content.name,
                content: `Tool: ${content.name}`,
                details: content.input,
              });
            }
          }
        }
      } catch {
        // Skip invalid lines
      }
    }

    return events.slice(-100); // Limit to last 100 events
  } catch {
    return [];
  }
}

// ============================================================================
// Report Data Collection
// ============================================================================

function collectReportData(sessionId: string, transcriptPath?: string): ReportData {
  const governorEvents = readJsonlFile<GovernorAuditEntry>(GOVERNOR_LOG, sessionId);
  const injectionScans = readJsonlFile<InjectionScanEntry>(INJECTION_LOG, sessionId);
  const secureCodeEvents = readJsonlFile<SecureCodeEntry>(SECURE_CODE_LOG, sessionId);
  // Load linter events without session_id - filter by timestamp later (entries don't have session_id)
  const allSecureCodeLinterEvents = readJsonlFile<SecureCodeLinterEntry>(SECURE_CODE_LINTER_LOG);
  const leashEvents = readJsonlFile<LeashEvent>(LEASH_LOG, sessionId);
  const memorySecurityEvents = readJsonlFile<MemorySecurityEntry>(MEMORY_SECURITY_LOG, sessionId);
  const errors = readJsonlFile<ErrorEntry>(ERRORS_LOG, sessionId);
  const conversationTrace = transcriptPath ? readTranscript(transcriptPath) : [];

  // Load evaluator events (no session_id - filter by recent timestamp)
  const allEvaluatorEvents = readJsonlFile<EvaluatorAuditEntry>(EVALUATOR_LOG);

  // Load image safety events (no session_id - filter by recent timestamp)
  const allImageSafetyEvents = readJsonlFile<ImageSafetyEntry>(IMAGE_SAFETY_LOG);

  // Determine if Leash was active
  const leashActive = leashEvents.length > 0;

  // Calculate timestamps
  const allTimestamps = [
    ...governorEvents.map((e) => e.timestamp),
    ...injectionScans.map((e) => e.timestamp),
    ...conversationTrace.map((e) => e.timestamp),
  ].filter(Boolean).sort();

  const sessionStart = allTimestamps[0];
  const sessionEnd = allTimestamps[allTimestamps.length - 1];
  const sessionDurationMs = sessionStart && sessionEnd
    ? new Date(sessionEnd).getTime() - new Date(sessionStart).getTime()
    : 0;

  // Filter evaluator events to those during this session
  const evaluatorEvents = sessionStart && sessionEnd
    ? allEvaluatorEvents.filter((e) => {
        const ts = new Date(e.timestamp).getTime();
        const start = new Date(sessionStart).getTime();
        const end = new Date(sessionEnd).getTime() + 60000;
        return ts >= start && ts <= end;
      })
    : allEvaluatorEvents.slice(-10);

  // Filter image safety events to those during this session
  const imageSafetyEvents = sessionStart && sessionEnd
    ? allImageSafetyEvents.filter((e) => {
        const ts = new Date(e.timestamp).getTime();
        const start = new Date(sessionStart).getTime();
        const end = new Date(sessionEnd).getTime() + 60000;
        return ts >= start && ts <= end;
      })
    : allImageSafetyEvents.slice(-20);

  // Filter secure code linter events to those during this session
  const secureCodeLinterEvents = sessionStart && sessionEnd
    ? allSecureCodeLinterEvents.filter((e) => {
        const ts = new Date(e.timestamp).getTime();
        const start = new Date(sessionStart).getTime();
        const end = new Date(sessionEnd).getTime() + 60000;
        return ts >= start && ts <= end;
      })
    : allSecureCodeLinterEvents.slice(-20);

  // Calculate summary
  const policyViolations = governorEvents.filter(
    (e) => e.policy_matched && e.policy_matched !== 'none' && e.severity !== 'LOW'
  ).length;

  const injectionDetections = injectionScans.filter((e) => e.injection_detected).length;

  const imageSafetyDetections = imageSafetyEvents.filter((e) => e.result.suspicious).length;

  const securitySensitiveWrites = secureCodeEvents.filter(
    (e) => e.classification === 'SECURITY_SENSITIVE'
  ).length;

  const codeReverts = secureCodeLinterEvents.filter((e) => e.reverted).length;

  const leashBlocks = leashEvents.filter((e) => e.decision === 'DENY').length;

  const memoryPoisoningAttempts = memorySecurityEvents.filter(
    (e) => e.findings && e.findings.length > 0
  ).length;

  // Per-tab severity counts for breakdown tooltips
  const governorSeverities = sortBySeverity(governorEvents.filter((e) => e.policy_matched && e.policy_matched !== 'none')).slice(0, 50).map((e) => e.severity);
  const injectionSeverities = sortBySeverity(injectionScans.filter((e) => e.injection_detected)).slice(0, 30).map((e) => e.severity || 'MEDIUM');
  const imageSafetySeverities = sortBySeverity(imageSafetyEvents.filter((e) => e.result.suspicious)).slice(0, 30).map((e) => e.result.severity);
  const secureCodeSeverities = sortBySeverity(secureCodeEvents.filter((e) => e.classification === 'SECURITY_SENSITIVE')).slice(0, 30).map((e) => e.risk_level);
  const linterSeverities = sortBySeverity(secureCodeLinterEvents).slice(0, 30).map((e) => e.severity);
  const leashSeverities = sortBySeverity(leashEvents.filter((e) => e.decision === 'DENY')).slice(0, 50).map((e) => e.severity);
  const memorySeverities = memorySecurityEvents.filter((e) => e.findings && e.findings.length > 0).slice(0, 50).map((e) => e.highestSeverity);

  const allSeverities = [
    ...governorSeverities,
    ...injectionSeverities,
    ...imageSafetySeverities,
    ...secureCodeSeverities,
    ...linterSeverities,
    ...leashSeverities,
    ...memorySeverities,
  ];

  const criticalCount = allSeverities.filter((s) => s === 'CRITICAL').length;
  const highCount = allSeverities.filter((s) => s === 'HIGH').length;
  const mediumCount = allSeverities.filter((s) => s === 'MEDIUM').length;
  const lowCount = allSeverities.filter((s) => s === 'LOW').length;

  // Per-tab breakdown for tooltips
  const severityBreakdown = {
    critical: {
      governor: governorSeverities.filter((s) => s === 'CRITICAL').length,
      injection: injectionSeverities.filter((s) => s === 'CRITICAL').length,
      imageSafety: imageSafetySeverities.filter((s) => s === 'CRITICAL').length,
      secureCode: secureCodeSeverities.filter((s) => s === 'CRITICAL').length,
      linter: linterSeverities.filter((s) => s === 'CRITICAL').length,
      leash: leashSeverities.filter((s) => s === 'CRITICAL').length,
      memory: memorySeverities.filter((s) => s === 'CRITICAL').length,
    },
    high: {
      governor: governorSeverities.filter((s) => s === 'HIGH').length,
      injection: injectionSeverities.filter((s) => s === 'HIGH').length,
      imageSafety: imageSafetySeverities.filter((s) => s === 'HIGH').length,
      secureCode: secureCodeSeverities.filter((s) => s === 'HIGH').length,
      linter: linterSeverities.filter((s) => s === 'HIGH').length,
      leash: leashSeverities.filter((s) => s === 'HIGH').length,
      memory: memorySeverities.filter((s) => s === 'HIGH').length,
    },
    medium: {
      governor: governorSeverities.filter((s) => s === 'MEDIUM').length,
      injection: injectionSeverities.filter((s) => s === 'MEDIUM').length,
      imageSafety: imageSafetySeverities.filter((s) => s === 'MEDIUM').length,
      secureCode: secureCodeSeverities.filter((s) => s === 'MEDIUM').length,
      linter: linterSeverities.filter((s) => s === 'MEDIUM').length,
      leash: leashSeverities.filter((s) => s === 'MEDIUM').length,
      memory: memorySeverities.filter((s) => s === 'MEDIUM').length,
    },
    low: {
      governor: governorSeverities.filter((s) => s === 'LOW').length,
      injection: injectionSeverities.filter((s) => s === 'LOW').length,
      imageSafety: imageSafetySeverities.filter((s) => s === 'LOW').length,
      secureCode: secureCodeSeverities.filter((s) => s === 'LOW').length,
      linter: linterSeverities.filter((s) => s === 'LOW').length,
      leash: leashSeverities.filter((s) => s === 'LOW').length,
      memory: memorySeverities.filter((s) => s === 'LOW').length,
    },
  };

  // Estimate tokens (rough: 4 chars = 1 token)
  const estimatedTokens = conversationTrace.reduce((acc, e) => acc + Math.ceil(e.content.length / 4), 0);

  let overallStatus: 'CLEAN' | 'WARNINGS' | 'DETECTED' = 'CLEAN';
  if (criticalCount > 0 || codeReverts > 0 || leashBlocks > 0 || injectionDetections > 0 || imageSafetyDetections > 0 || memoryPoisoningAttempts > 0) {
    overallStatus = 'DETECTED';
  } else if (highCount > 0 || policyViolations > 2) {
    overallStatus = 'WARNINGS';
  }

  return {
    sessionId,
    generatedAt: new Date().toISOString(),
    sessionStart,
    sessionEnd,
    governorEvents,
    evaluatorEvents,
    injectionScans,
    imageSafetyEvents,
    secureCodeEvents,
    secureCodeLinterEvents,
    leashEvents,
    memorySecurityEvents,
    errors,
    conversationTrace,
    leashActive,
    summary: {
      totalToolCalls: governorEvents.length,
      policyViolations,
      injectionDetections,
      imageSafetyDetections,
      memoryPoisoningAttempts,
      securitySensitiveWrites,
      codeReverts,
      leashBlocks,
      errors: errors.filter((e) => e.level === 'error').length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      estimatedTokens,
      sessionDurationMs,
      overallStatus,
      severityBreakdown,
    },
  };
}

// ============================================================================
// HTML Generation (Enhanced Interactive)
// ============================================================================

function escapeHtml(str: string | null | undefined): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getToolIcon(toolName: string): string {
  // Handle MCP tools (mcp__server__tool format)
  if (toolName.startsWith('mcp__')) {
    return TOOL_ICONS.MCP;
  }
  return TOOL_ICONS[toolName] || TOOL_ICONS.default;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`;
}

function formatTime(timestamp: string): string {
  const d = new Date(timestamp);
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

// Sort events by severity (CRITICAL first) before slicing
const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
function sortBySeverity<T>(events: T[]): T[] {
  return [...events].sort((a, b) => {
    const aOrder = SEVERITY_ORDER[(a as any).severity || 'INFO'] ?? 5;
    const bOrder = SEVERITY_ORDER[(b as any).severity || 'INFO'] ?? 5;
    return aOrder - bOrder;
  });
}

// ============================================================================
// Vex-Talon Analysis (Haiku-powered Executive Summary)
// ============================================================================

async function generateVexAnalysis(data: ReportData): Promise<string> {
  try {
    // Build context for Haiku
    const securitySummary = {
      overallStatus: data.summary.overallStatus,
      criticalCount: data.summary.criticalCount,
      highCount: data.summary.highCount,
      mediumCount: data.summary.mediumCount,
      lowCount: data.summary.lowCount,
      policyViolations: data.summary.policyViolations,
      injectionDetections: data.summary.injectionDetections,
      codeReverts: data.summary.codeReverts,
      memoryPoisoningAttempts: data.summary.memoryPoisoningAttempts,
      errors: data.summary.errors,
      totalToolCalls: data.summary.totalToolCalls,
    };

    // Collect detailed findings from evaluator events
    const evaluatorFindings: string[] = [];
    for (const evt of data.evaluatorEvents) {
      if (evt.security_findings && evt.security_findings.length > 0) {
        for (const f of evt.security_findings) {
          evaluatorFindings.push(`[SECURITY] ${f.description}: ${f.line || f.file || 'no details'}`);
        }
      }
      if (evt.quality_findings && evt.quality_findings.length > 0) {
        for (const f of evt.quality_findings) {
          evaluatorFindings.push(`[QUALITY] ${f.description}: ${f.line || f.file || 'no details'}`);
        }
      }
    }

    // Collect linter events with severity
    const linterFindings = data.secureCodeLinterEvents
      .filter((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH')
      .slice(0, 5)
      .map((e) => `[${e.severity}] ${e.file_path}: ${e.top_findings?.slice(0, 2).join(', ') || 'code issue'}`);

    // Build the prompt (command-style - prevents Haiku from asking clarifying questions)
    const findingsSummary = [
      ...evaluatorFindings.slice(0, 3),
      ...linterFindings.slice(0, 2),
    ].join(', ') || 'none';

    const prompt = `Summarize this security monitoring data for a report dashboard. Apply security analyst judgment to distinguish real issues from noise. Plain text only, exactly 3 sentences.

Session Metrics:
- Status: ${securitySummary.overallStatus}
- Severity counts: ${securitySummary.criticalCount} critical, ${securitySummary.highCount} high, ${securitySummary.mediumCount} medium, ${securitySummary.lowCount} low
- Policy violations: ${securitySummary.policyViolations} (L1 Governor - blocked dangerous actions)
- Injection detections: ${securitySummary.injectionDetections} (L4 Injection Scanner - prompt injection attempts)
- Memory poisoning: ${securitySummary.memoryPoisoningAttempts} (L3 Memory Validation - knowledge graph attacks)
- Code reverts: ${securitySummary.codeReverts} (L2 Linter - auto-fixed insecure code)
- Findings: ${findingsSummary}

Defense-in-Depth Context (20 layers, L0-L19):
BLOCKING LAYERS (can prevent threats):
- L0 Secure Code Enforcer: Pre-write BLOCKING of vulnerable patterns
- L1 Governor: Pre-execution BLOCKING (43 policies)
- L6 Git Pre-commit: BLOCKS commits with secrets/PII
- L9 Egress Scanner: Pre-execution BLOCKING of exfiltration
- L10/L11 Sandboxes: OS-level PREVENTION of unauthorized syscalls
- L18 MCP Audit: Pre-deployment SCANNING of MCP servers
- L19 Skill Scanner: Pre-invocation BLOCKING of malicious skills (CRITICAL patterns)

DETECTION-ONLY LAYERS (alert after content is in context):
- L2 Secure Code Linter: Post-write detection, can auto-revert files but content already in context
- L3 Memory Validation: DETECTION ONLY (cannot block MCP tools due to Claude Code bug #3514/#4669)
- L4 Injection Scanner: Post-execution DETECTION of prompt injection
- L5 Output Sanitizer: Post-write DETECTION of XSS vectors
- L7 Image Safety: Post-read DETECTION of visual injection
- L8 Evaluator: Post-commit DETECTION of security/PII issues
- L14 Supply Chain: Post-install DETECTION of vulnerable packages
- L17 Spend Alerting: Post-execution DETECTION of cost overruns

INTERPRETATION RULES:
- Policy violations (L1) = dangerous action was BLOCKED before execution
- Injection detections (L4) = content reached context but was FLAGGED (not blocked)
- Memory poisoning (L3) = attack was DETECTED but entity may have been created (detection-only)
- Code reverts (L2) = insecure code DETECTED and auto-reverted after write
- Zero L1 violations + zero L6 blocks = controls working, nothing needed blocking
- L4/L3/L7 detections are alerts, not necessarily prevented attacks
- API key patterns in grep/search RESULTS are false positives (searching code, not exposing secrets)

Summary with expert judgment:
- Sentence 1: Assess actual security posture - distinguish what was BLOCKED (L0/L1/L6/L9) vs DETECTED (L2-L5/L7/L8/L14)
- Sentence 2: Identify false positives vs real findings. Detection-only alerts mean content reached context but was flagged.
- Sentence 3: Professional recommendation based on blocking/detection distinction

Write:`;

    // Call Haiku via claude CLI (uses Claude Code subscription - free)
    // Run from /tmp to avoid loading project context
    // Security: Write prompt to temp file to avoid shell injection via audit log content
    const { execFileSync } = await import('child_process');
    const { unlinkSync } = await import('fs');
    const tmpFile = join('/tmp', `vex-talon-prompt-${Date.now()}-${process.pid}.txt`);

    try {
      writeFileSync(tmpFile, prompt, { mode: 0o600 });
      const analysis = execFileSync('sh', ['-c', `cat "${tmpFile}" | claude -p --model haiku --no-session-persistence 2>/dev/null`], {
          cwd: '/tmp',
          encoding: 'utf-8',
          timeout: 60000, // 60 second timeout
          maxBuffer: 1024 * 1024, // 1MB buffer
        }
      ).trim();

      return analysis || 'No analysis generated';
    } catch (cliError) {
      console.error('Haiku CLI error:', cliError);
      return `Vex-Talon Analysis unavailable: CLI error`;
    } finally {
      try { unlinkSync(tmpFile); } catch { /* best effort cleanup */ }
    }
  } catch (error) {
    console.error('Error generating Vex-Talon analysis:', error);
    return `Vex-Talon Analysis unavailable: ${error instanceof Error ? error.message : 'Unknown error'}`;
  }
}

function generateHTML(data: ReportData): string {
  const statusConfig = {
    CLEAN: { emoji: '\u2705', color: '#3fb950', label: 'Clean Session' },
    WARNINGS: { emoji: '\u26a0\ufe0f', color: '#d29922', label: 'Warnings Detected' },
    DETECTED: { emoji: '\ud83d\udea8', color: '#f85149', label: 'Security Events Detected' },
  };

  const status = statusConfig[data.summary.overallStatus];

  // Pre-compute display-ready datasets with same filter+sort+slice as HTML generators
  const displayGovernorEvents = sortBySeverity(data.governorEvents.filter((e) => e.policy_matched && e.policy_matched !== 'none')).slice(0, 50);
  const displayInjectionScans = sortBySeverity(data.injectionScans.filter((e) => e.injection_detected)).slice(0, 30);
  const displayImageSafetyEvents = sortBySeverity(data.imageSafetyEvents.filter((e) => e.result.suspicious)).slice(0, 30);
  const displaySecureCodeEvents = sortBySeverity(data.secureCodeEvents.filter((e) => e.classification === 'SECURITY_SENSITIVE')).slice(0, 30);
  const displayLinterEvents = sortBySeverity(data.secureCodeLinterEvents).slice(0, 30);
  const displayLeashEvents = sortBySeverity(data.leashEvents.filter((e) => e.decision === 'DENY')).slice(0, 50);
  const displayEvaluatorEvents = sortBySeverity(data.evaluatorEvents).slice(0, 20);
  const displayMemoryEvents = data.memorySecurityEvents.filter((e) => e.findings && e.findings.length > 0).slice(0, 50);

  // Embed session data as JSON for JavaScript interactivity
  const sessionDataJson = JSON.stringify({
    sessionId: data.sessionId,
    summary: data.summary,
    leashActive: data.leashActive,
    governorEvents: displayGovernorEvents,
    injectionScans: displayInjectionScans,
    imageSafetyEvents: displayImageSafetyEvents,
    secureCodeEvents: displaySecureCodeEvents,
    secureCodeLinterEvents: displayLinterEvents,
    leashEvents: displayLeashEvents,
    evaluatorEvents: displayEvaluatorEvents,
    conversationTrace: data.conversationTrace.slice(-50),
    errors: data.errors.slice(0, 20),
  });

  // Generate timeline markers from all events with timestamps
  const allTimelineEvents: { timestamp: string; type: string; label: string; color: string }[] = [];

  // Add conversation trace tool events
  data.conversationTrace.filter((e) => e.type === 'tool').forEach((e) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'tool', label: e.toolName || 'Tool', color: 'var(--accent-purple)' });
  });

  // Add Governor events (violations only)
  data.governorEvents.filter((e) => e.policy_matched && e.policy_matched !== 'none').forEach((e) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'governor', label: `Governor: ${e.policy_matched}`, color: '#f778ba' });
  });

  // Add Memory poisoning events
  data.memorySecurityEvents.filter((e) => e.highestSeverity === 'CRITICAL').forEach((e) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'memory', label: 'Memory Poisoning', color: 'var(--accent-orange)' });
  });

  // Add Injection detections
  data.injectionScans.filter((e) => e.injection_detected).forEach((e) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'injection', label: 'Injection Detected', color: 'var(--accent-yellow)' });
  });

  // Add Errors
  data.errors.forEach((e) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'error', label: e.error?.message || 'Error', color: 'var(--accent-red)' });
  });

  // Add Evaluator events (sample)
  data.evaluatorEvents.slice(0, 10).forEach((e: any) => {
    allTimelineEvents.push({ timestamp: e.timestamp, type: 'evaluator', label: e.tool_name || 'Evaluator', color: 'var(--accent-green)' });
  });

  // Sort by timestamp and take last 30
  allTimelineEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  const timelineEvents = allTimelineEvents.slice(-30);

  const timelineMarkers = timelineEvents.length > 0
    ? timelineEvents.map((e) => `<div class="timeline-marker" data-event-type="${e.type}" title="${escapeHtml(e.label)}" style="background: ${e.color};"></div>`).join('')
    : '<div style="flex: 1; text-align: center; color: var(--text-muted); font-size: 11px;">No events to display</div>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vex-Talon Security Report - ${data.sessionId.substring(0, 8)}</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --bg-hover: #30363d;
      --text-primary: #f0f6fc;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --border-color: #30363d;
      --accent-blue: #58a6ff;
      --accent-green: #3fb950;
      --accent-yellow: #d29922;
      --accent-red: #f85149;
      --accent-purple: #a371f7;
      --accent-orange: #f0883e;
    }

    /* Custom scrollbar - dark theme */
    * {
      scrollbar-width: thin;
      scrollbar-color: var(--bg-hover) var(--bg-secondary);
    }

    *::-webkit-scrollbar { width: 8px; height: 8px; }
    *::-webkit-scrollbar-track { background: var(--bg-secondary); border-radius: 4px; }
    *::-webkit-scrollbar-thumb { background: var(--bg-hover); border-radius: 4px; border: 2px solid var(--bg-secondary); }
    *::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
    *::-webkit-scrollbar-corner { background: var(--bg-secondary); }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 20px;
    }

    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    header {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .header-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
    .header-title { display: flex; align-items: center; gap: 12px; }
    .header-title .logo { font-size: 36px; }
    .header-title h1 { font-size: 24px; font-weight: 600; }

    .status-badge { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; font-weight: 600; font-size: 14px; }
    .status-clean { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
    .status-warnings { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
    .status-detected { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }

    .header-meta { display: flex; flex-wrap: wrap; gap: 24px; color: var(--text-secondary); font-size: 14px; }
    .header-meta span { display: flex; align-items: center; gap: 6px; }
    .leash-badge { background: var(--accent-green); color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }

    /* Activity Metrics */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .metric-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; text-align: center; transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s; position: relative; }
    .metric-card[data-navigate] { cursor: pointer; }
    .metric-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
    .metric-card[data-navigate]:hover { box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3); }
    .metric-card[data-navigate]:active { transform: translateY(0); }
    .metric-value { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
    .metric-label { color: var(--text-secondary); font-size: 13px; }
    .metric-card.critical .metric-value { color: var(--accent-red); }
    .metric-card.high .metric-value { color: var(--accent-orange); }
    .metric-card.medium .metric-value { color: var(--accent-yellow); }
    .metric-card.low .metric-value { color: var(--accent-blue); }
    .metric-card.safe .metric-value { color: var(--accent-green); }

    /* Severity Tooltip */
    .severity-tooltip { display: none; position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%); background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; min-width: 160px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); z-index: 100; text-align: left; font-size: 12px; }
    .severity-tooltip::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 6px solid transparent; border-top-color: var(--border-color); }
    .metric-card:hover .severity-tooltip { display: block; }
    .metric-card.direct-navigate:hover .severity-tooltip { display: none; }
    .metric-card.no-events:hover .severity-tooltip { display: none; }
    .tooltip-title { font-weight: 600; color: var(--text-primary); margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid var(--border-color); }
    .tooltip-row { display: flex; justify-content: space-between; padding: 4px 6px; margin: 2px -6px; border-radius: 4px; color: var(--text-secondary); }
    .tooltip-row.has-events { color: var(--text-primary); font-weight: 500; cursor: pointer; }
    .tooltip-row.has-events:hover { background: var(--bg-hover); }
    .tooltip-row .tab-name { display: flex; align-items: center; gap: 6px; }
    .tooltip-row .count { font-weight: 600; }

    /* Tabs */
    .tabs { display: flex; gap: 4px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 4px; margin-bottom: 24px; overflow-x: auto; }
    .tab { padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--text-secondary); transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 6px; white-space: nowrap; flex: 1; }
    .tab:hover { background: var(--bg-tertiary); color: var(--text-primary); }
    .tab.active { background: var(--accent-blue); color: white; }
    .tab .count { background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 10px; font-size: 12px; }
    .tab.active .count { background: rgba(255,255,255,0.3); }

    /* Tab Content */
    .tab-content { display: none; }
    .tab-content.active { display: block; }

    /* Timeline */
    .timeline-container { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
    .timeline-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .timeline-header h3 { font-size: 14px; font-weight: 600; color: var(--text-secondary); }
    .timeline-track { display: flex; align-items: center; justify-content: space-between; height: 40px; background: var(--bg-tertiary); border-radius: 4px; padding: 0 12px; }
    .timeline-marker { width: 8px; height: 8px; background: var(--accent-purple); border-radius: 50%; cursor: pointer; transition: transform 0.2s, background 0.2s; flex-shrink: 0; }
    .timeline-marker:hover { transform: scale(1.5); background: var(--accent-blue); }

    /* Event Cards */
    .events-container { display: flex; flex-direction: column; gap: 12px; }
    .event-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; transition: border-color 0.2s; }
    .event-card:hover { border-color: var(--border-color); }
    .event-card.severity-critical { border-left: 4px solid var(--accent-red); }
    .event-card.severity-high { border-left: 4px solid var(--accent-orange); }
    .event-card.severity-medium { border-left: 4px solid var(--accent-yellow); }
    .event-card.severity-low { border-left: 4px solid var(--accent-blue); }

    .event-header { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; transition: background 0.2s; }
    .event-header:hover { background: var(--bg-hover); }
    .event-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: var(--bg-tertiary); border-radius: 6px; color: var(--accent-purple); }
    .event-icon svg { width: 18px; height: 18px; }
    .event-title { flex: 1; font-weight: 500; }
    .event-badges { display: flex; gap: 8px; align-items: center; }

    .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge-severity { color: white; }
    .badge-critical { background: var(--accent-red); }
    .badge-high { background: var(--accent-orange); }
    .badge-medium { background: var(--accent-yellow); color: #000; }
    .badge-low { background: var(--accent-blue); }
    .badge-tool { background: var(--accent-purple); }
    .badge-modified { background: var(--accent-yellow); color: #000; }
    .badge-blocked { background: var(--accent-red); }

    .event-time { color: var(--text-muted); font-size: 12px; }
    .event-expand { color: var(--text-muted); transition: transform 0.2s; }
    .event-card.expanded .event-expand { transform: rotate(180deg); }

    .event-details { display: none; padding: 0 16px 16px 16px; border-top: 1px solid var(--border-color); background: var(--bg-tertiary); }
    .event-card.expanded .event-details { display: block; }

    .detail-row { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border-color); }
    .detail-row:last-child { border-bottom: none; }
    .detail-label { font-weight: 600; color: var(--text-secondary); min-width: 120px; }
    .detail-value { flex: 1; word-break: break-all; }

    .code-block { background: var(--bg-primary); border-radius: 6px; padding: 12px; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }

    /* Conversation Trace */
    .trace-event { display: flex; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border-color); }
    .trace-event:last-child { border-bottom: none; }
    .trace-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 50%; flex-shrink: 0; }
    .trace-icon.user { background: var(--accent-blue); }
    .trace-icon.tool { background: var(--accent-purple); }
    .trace-icon svg { width: 16px; height: 16px; color: white; }
    .trace-content { flex: 1; }
    .trace-header { display: flex; justify-content: space-between; margin-bottom: 4px; }
    .trace-type { font-weight: 600; font-size: 13px; }
    .trace-time { color: var(--text-muted); font-size: 12px; }
    .trace-text { color: var(--text-secondary); font-size: 13px; }

    /* Empty State */
    .empty-state { text-align: center; padding: 48px 24px; color: var(--text-secondary); }
    .empty-state .emoji { font-size: 48px; margin-bottom: 12px; }

    /* Filter Controls */
    .filter-controls { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .filter-btn { padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border-color); background: var(--bg-tertiary); color: var(--text-secondary); cursor: pointer; font-size: 12px; transition: all 0.2s; }
    .filter-btn:hover { border-color: var(--accent-blue); color: var(--text-primary); }
    .filter-btn.active { background: var(--accent-blue); border-color: var(--accent-blue); color: white; }

    /* ATLAS Mapping */
    .atlas-header { margin-bottom: 24px; }
    .atlas-header h3 { font-size: 18px; font-weight: 600; }
    .atlas-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
    .atlas-card.status-active { border-left: 4px solid var(--accent-green); }
    .atlas-card.status-partial { border-left: 4px solid var(--accent-yellow); }
    .atlas-card.status-planned { border-left: 4px solid var(--text-muted); }
    .atlas-card.status-not_installed { border-left: 4px solid var(--text-muted); opacity: 0.7; }

    .atlas-layer-header { display: flex; align-items: center; justify-content: space-between; padding: 16px; background: var(--bg-tertiary); cursor: pointer; }
    .atlas-layer-header:hover { background: var(--bg-hover); }
    .atlas-layer-info { display: flex; align-items: center; gap: 12px; }
    .atlas-layer-number { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; background: var(--accent-purple); color: white; border-radius: 8px; font-weight: 700; font-size: 14px; }
    .atlas-layer-name { font-weight: 600; font-size: 15px; }
    .atlas-layer-desc { color: var(--text-secondary); font-size: 13px; margin-top: 2px; }

    .atlas-status { padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .atlas-status.active { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
    .atlas-status.partial { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
    .atlas-status.planned { background: rgba(110, 118, 129, 0.15); color: var(--text-muted); }
    .atlas-status.not_installed { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }

    .source-badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; margin-left: 8px; vertical-align: middle; }
    .source-badge.external { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }
    .source-badge.builtin { background: rgba(110, 118, 129, 0.1); color: var(--text-muted); }
    .source-badge.not-installed { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }

    .coverage-sublabel { font-size: 11px; color: var(--accent-yellow); margin-top: 2px; }

    .atlas-details { padding: 16px; display: none; }
    .atlas-card.expanded .atlas-details { display: block; }

    .atlas-section { margin-bottom: 16px; }
    .atlas-section:last-child { margin-bottom: 0; }
    .atlas-section-title { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px; }
    .atlas-tags { display: flex; flex-wrap: wrap; gap: 8px; }
    .atlas-tag { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; transition: transform 0.2s; }
    .atlas-tag:hover { transform: scale(1.05); }
    .atlas-tag.atlas { background: rgba(163, 113, 247, 0.15); color: var(--accent-purple); border: 1px solid rgba(163, 113, 247, 0.3); }
    .atlas-tag.owasp-critical { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); border: 1px solid rgba(248, 81, 73, 0.3); }
    .atlas-tag.owasp-high { background: rgba(240, 136, 62, 0.15); color: var(--accent-orange); border: 1px solid rgba(240, 136, 62, 0.3); }
    .atlas-tag.owasp-medium { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); border: 1px solid rgba(210, 153, 34, 0.3); }
    .atlas-tag.agentic { background: rgba(88, 166, 255, 0.12); color: var(--accent-blue); border: 1px solid rgba(88, 166, 255, 0.25); }
    .atlas-tag-id { font-family: 'SF Mono', Monaco, monospace; font-size: 11px; opacity: 0.8; }

    .coverage-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; padding: 16px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; }
    .coverage-item { text-align: center; }
    .coverage-value { font-size: 24px; font-weight: 700; color: var(--accent-green); }
    .coverage-label { font-size: 12px; color: var(--text-secondary); }

    /* Collapsible Framework Sections */
    .framework-section { margin-top: 24px; padding: 16px; background: rgba(136, 46, 224, 0.08); border-radius: 12px; border: 1px solid rgba(136, 46, 224, 0.2); }
    .framework-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
    .framework-title { flex: 1; }
    .framework-stats { display: flex; gap: 8px; align-items: center; }
    .stat-badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; }
    .stat-badge.covered { background: rgba(46, 160, 67, 0.2); color: #3fb950; }
    .stat-badge.partial { background: rgba(210, 153, 34, 0.2); color: #d29922; }
    .stat-badge.gap { background: rgba(248, 81, 73, 0.2); color: #f85149; }
    .stat-badge.na { background: rgba(110, 118, 129, 0.2); color: #8b949e; }
    .framework-expand { margin-left: 8px; color: var(--text-muted); transition: transform 0.3s ease; }
    .framework-section.expanded .framework-expand { transform: rotate(180deg); }
    .framework-content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease, margin-top 0.3s ease; }
    .framework-section.expanded .framework-content { max-height: 2000px; margin-top: 16px; }

    /* Footer */
    footer { text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 32px; padding: 16px; border-top: 1px solid var(--border-color); }

    /* Responsive */
    @media (max-width: 768px) {
      .header-top { flex-direction: column; align-items: flex-start; gap: 16px; }
      .header-meta { flex-direction: column; gap: 8px; }
      .metrics-grid { grid-template-columns: repeat(2, 1fr); }
      .tabs { flex-wrap: nowrap; overflow-x: auto; -webkit-overflow-scrolling: touch; }
      .event-badges { flex-wrap: wrap; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="header-top">
        <div class="header-title">
          <span class="logo">\ud83e\udd96\u26a1</span>
          <h1>Vex-Talon Security Report</h1>
        </div>
        <div class="status-badge status-${data.summary.overallStatus.toLowerCase()}">
          <span>${status.emoji}</span>
          <span>${status.label}</span>
        </div>
      </div>
      <div class="header-meta">
        <span><strong>Session:</strong> ${data.sessionId.substring(0, 12)}...</span>
        <span><strong>Generated:</strong> ${new Date(data.generatedAt).toLocaleString('en-US', { timeZone: 'America/Puerto_Rico' })} AST</span>
        <span><strong>Duration:</strong> ${formatDuration(data.summary.sessionDurationMs)}</span>
        ${data.leashActive ? '<span class="leash-badge">\ud83d\udd12 LEASH ACTIVE</span>' : ''}
      </div>
    </header>

    <!-- Activity Metrics -->
    <div class="metrics-grid">
      <div class="metric-card safe" data-navigate="governor" data-count="${data.summary.totalToolCalls}" title="View all tool calls in Governor tab">
        <div class="metric-value">${data.summary.totalToolCalls}</div>
        <div class="metric-label">Tool Calls Monitored</div>
      </div>
      <div class="metric-card ${data.summary.policyViolations > 0 ? 'high' : 'safe'}" data-navigate="governor" data-count="${data.summary.policyViolations}" title="View policy violations">
        <div class="metric-value">${data.summary.policyViolations}</div>
        <div class="metric-label">Policy Violations</div>
      </div>
      <div class="metric-card ${data.summary.injectionDetections > 0 ? 'critical' : 'safe'}" data-navigate="injection" data-count="${data.summary.injectionDetections}" title="View injection detections">
        <div class="metric-value">${data.summary.injectionDetections}</div>
        <div class="metric-label">Injection Detections</div>
      </div>
      <div class="metric-card ${data.summary.codeReverts > 0 ? 'critical' : 'safe'}" data-navigate="linter" data-filter-action="reverted" data-count="${data.summary.codeReverts}" title="View code reverts">
        <div class="metric-value">${data.summary.codeReverts}</div>
        <div class="metric-label">Code Reverts</div>
      </div>
      ${data.leashActive ? `
      <div class="metric-card ${data.summary.leashBlocks > 0 ? 'critical' : 'safe'}" data-navigate="leash" data-count="${data.summary.leashBlocks}" title="View kernel blocks">
        <div class="metric-value">${data.summary.leashBlocks}</div>
        <div class="metric-label">Kernel Blocks</div>
      </div>
      ` : ''}
      <div class="metric-card">
        <div class="metric-value">~${(data.summary.estimatedTokens / 1000).toFixed(1)}K</div>
        <div class="metric-label">Est. Tokens</div>
      </div>
    </div>

    <!-- Severity Summary -->
    <div class="metrics-grid">
      <div class="metric-card critical" data-navigate="governor" data-filter="critical" data-count="${data.summary.criticalCount}" data-breakdown='${JSON.stringify(data.summary.severityBreakdown.critical)}'>
        <div class="metric-value">${data.summary.criticalCount}</div>
        <div class="metric-label">CRITICAL</div>
        <div class="severity-tooltip"></div>
      </div>
      <div class="metric-card high" data-navigate="governor" data-filter="high" data-count="${data.summary.highCount}" data-breakdown='${JSON.stringify(data.summary.severityBreakdown.high)}'>
        <div class="metric-value">${data.summary.highCount}</div>
        <div class="metric-label">HIGH</div>
        <div class="severity-tooltip"></div>
      </div>
      <div class="metric-card medium" data-navigate="governor" data-filter="medium" data-count="${data.summary.mediumCount}" data-breakdown='${JSON.stringify(data.summary.severityBreakdown.medium)}'>
        <div class="metric-value">${data.summary.mediumCount}</div>
        <div class="metric-label">MEDIUM</div>
        <div class="severity-tooltip"></div>
      </div>
      <div class="metric-card low" data-navigate="governor" data-filter="low" data-count="${data.summary.lowCount}" data-breakdown='${JSON.stringify(data.summary.severityBreakdown.low)}'>
        <div class="metric-value">${data.summary.lowCount}</div>
        <div class="metric-label">LOW</div>
        <div class="severity-tooltip"></div>
      </div>
    </div>

    <!-- Vex-Talon Analysis (AI-Synthesized Executive Summary) -->
    ${data.vexAnalysis ? `
    <div class="vex-analysis-container" style="margin: 20px 0; background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(59, 130, 246, 0.05)); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 12px; overflow: hidden;">
      <div class="vex-analysis-header" style="display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; background: rgba(139, 92, 246, 0.15); cursor: pointer;" onclick="this.parentElement.classList.toggle('collapsed')">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="font-size: 20px;">\ud83d\udee1\ufe0f</span>
          <span style="font-weight: 600; color: var(--text-primary);">Vex-Talon Analysis</span>
          <span style="font-size: 11px; color: var(--text-muted); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 10px;">AI-Synthesized</span>
        </div>
        <span class="vex-analysis-toggle" style="color: var(--text-muted); transition: transform 0.2s;">\u25bc</span>
      </div>
      <div class="vex-analysis-content" style="padding: 16px; line-height: 1.6; color: var(--text-secondary);">
        ${escapeHtml(data.vexAnalysis).replace(/\n/g, '<br>')}
      </div>
    </div>
    <style>
      .vex-analysis-container.collapsed .vex-analysis-content { display: none; }
      .vex-analysis-container.collapsed .vex-analysis-toggle { transform: rotate(-90deg); }
      .vex-analysis-container:hover { border-color: rgba(139, 92, 246, 0.5); }
    </style>
    ` : ''}

    <!-- Timeline -->
    <div class="timeline-container">
      <div class="timeline-header">
        <h3>\ud83d\udccd Session Timeline</h3>
        <span style="color: var(--text-muted); font-size: 12px;">Click markers to jump to events</span>
      </div>
      <div class="timeline-track">
        ${timelineMarkers}
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <div class="tab active" data-tab="governor">
        \ud83d\udee1\ufe0f Governor
        <span class="count">${displayGovernorEvents.length}</span>
      </div>
      <div class="tab" data-tab="evaluator">
        \u2705 Evaluator
        <span class="count">${displayEvaluatorEvents.length}</span>
      </div>
      <div class="tab" data-tab="injection">
        \ud83d\udd0d Injection
        <span class="count">${displayInjectionScans.length + displayImageSafetyEvents.length}</span>
      </div>
      <div class="tab" data-tab="secure-code">
        \ud83d\udd10 Secure Code
        <span class="count">${displaySecureCodeEvents.length}</span>
      </div>
      <div class="tab" data-tab="linter">
        \ud83d\udd04 Auto-Revert
        <span class="count">${displayLinterEvents.length}</span>
      </div>
      ${data.leashActive ? `
      <div class="tab" data-tab="leash">
        \ud83d\udd12 Leash
        <span class="count">${displayLeashEvents.length}</span>
      </div>
      ` : ''}
      ${displayMemoryEvents.length > 0 ? `
      <div class="tab" data-tab="memory">
        \ud83e\udde0 Memory
        <span class="count">${displayMemoryEvents.length}</span>
      </div>
      ` : ''}
      <div class="tab" data-tab="trace">
        \ud83d\udcdc Trace
        <span class="count">${data.conversationTrace.length}</span>
      </div>
      <div class="tab" data-tab="errors">
        \u274c Errors
        <span class="count">${data.errors.length}</span>
      </div>
      <div class="tab" data-tab="atlas">
        \ud83c\udfaf ATLAS
        <span class="count">${ATLAS_MAPPINGS_LOADED.length}</span>
      </div>
    </div>

    <!-- Tab Contents -->
    <div id="content-governor" class="tab-content active">
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>
      <div class="events-container" id="governor-events">
        ${generateGovernorEventsHTML(data.governorEvents)}
      </div>
    </div>

    <div id="content-evaluator" class="tab-content">
      <div class="evaluator-header" style="margin-bottom: 16px;">
        <p style="color: var(--text-secondary); font-size: 13px;">
          Post-commit validation results. The Evaluator scans committed code for secrets, PII, and security issues.
        </p>
      </div>
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Failed</button>
        <button class="filter-btn" data-filter="medium">Warnings</button>
        <button class="filter-btn" data-filter="low">Passed</button>
      </div>
      <div class="events-container" id="evaluator-events">
        ${generateEvaluatorEventsHTML(data.evaluatorEvents)}
      </div>
    </div>

    <div id="content-injection" class="tab-content">
      <div class="injection-header" style="margin-bottom: 16px;">
        <p style="color: var(--text-secondary); font-size: 13px;">
          Prompt injection detection across text (L4) and images (L7).
        </p>
      </div>
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>

      <!-- Text Injection Subsection -->
      <div class="subsection" style="margin-top: 16px;">
        <h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
          \ud83d\udcdd Text Injection (Layer 4)
          <span class="badge" style="background: var(--bg-tertiary); font-size: 11px;">${displayInjectionScans.length} detected</span>
        </h4>
        <div class="events-container" id="injection-events">
          ${generateInjectionEventsHTML(data.injectionScans)}
        </div>
      </div>

      <!-- Image Safety Subsection -->
      <div class="subsection" style="margin-top: 24px;">
        <h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
          \ud83d\uddbc\ufe0f Image Safety (L7)
          <span class="badge" style="background: var(--bg-tertiary); font-size: 11px;">${displayImageSafetyEvents.length} suspicious</span>
        </h4>
        <div class="events-container" id="image-safety-events">
          ${generateImageSafetyEventsHTML(data.imageSafetyEvents)}
        </div>
      </div>
    </div>

    <div id="content-secure-code" class="tab-content">
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>
      <div class="events-container" id="secure-code-events">
        ${generateSecureCodeEventsHTML(data.secureCodeEvents)}
      </div>
    </div>

    <div id="content-linter" class="tab-content">
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>
      <div class="events-container" id="linter-events">
        ${generateLinterEventsHTML(data.secureCodeLinterEvents)}
      </div>
    </div>

    ${data.leashActive ? `
    <div id="content-leash" class="tab-content">
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>
      <div class="events-container" id="leash-events">
        ${generateLeashEventsHTML(data.leashEvents)}
      </div>
    </div>
    ` : ''}

    ${displayMemoryEvents.length > 0 ? `
    <div id="content-memory" class="tab-content">
      <div class="filter-controls">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>
      <div class="events-container" id="memory-events">
        ${generateMemorySecurityEventsHTML(data.memorySecurityEvents)}
      </div>
    </div>
    ` : ''}

    <div id="content-trace" class="tab-content">
      <div class="events-container" id="trace-events">
        ${generateTraceHTML(data.conversationTrace)}
      </div>
    </div>

    <div id="content-errors" class="tab-content">
      <div class="events-container" id="error-events">
        ${generateErrorsHTML(data.errors)}
      </div>
    </div>

    <div id="content-atlas" class="tab-content">
      <div class="atlas-header">
        <h3>\ud83c\udfaf Defense-in-Depth vs AI Threat Landscape</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          Vex-Talon security layers mapped to <a href="https://atlas.mitre.org" target="_blank" style="color: var(--accent-blue);">MITRE ATLAS</a>,
          <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank" style="color: var(--accent-blue);">OWASP LLM Top 10 2025</a>,
          and <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" style="color: var(--accent-blue);">OWASP Agentic 2026</a>
        </p>
      </div>
      <div class="events-container" id="atlas-events">
        ${generateATLASMappingHTML()}
      </div>
    </div>

    <footer>
      <p>Generated by <a href="https://github.com/0K-cool/vex-talon" style="color: var(--accent-blue); text-decoration: none;">Vex-Talon</a> Security Report v3 | MITRE ATLAS + OWASP LLM 2025 + OWASP Agentic 2026</p>
      <p>100% Local Processing | Zero External APIs | Defense-in-Depth Architecture</p>
      <p>Vex-Talon \ud83e\udd96\u26a1 - Defense-in-Depth Security for Claude Code | Inspired by NOVA Claude Code Protector</p>
    </footer>
  </div>

  <script>
    // Session data for JavaScript interactivity
    const SESSION_DATA = ${sessionDataJson};

    // Populate severity breakdown tooltips
    const tabNames = {
      governor: '\ud83d\udee1\ufe0f Governor',
      injection: '\ud83d\udd0d Injection',
      imageSafety: '\ud83d\uddbc\ufe0f Image Safety',
      secureCode: '\ud83d\udd10 Secure Code',
      linter: '\ud83d\udd04 Auto-Revert',
      leash: '\ud83d\udd12 Leash',
      memory: '\ud83e\udde0 Memory'
    };

    const tabIds = {
      governor: 'governor',
      injection: 'injection',
      imageSafety: 'injection',
      secureCode: 'secure-code',
      linter: 'linter',
      leash: 'leash',
      memory: 'memory'
    };

    document.querySelectorAll('.metric-card[data-breakdown]').forEach(card => {
      const breakdown = JSON.parse(card.dataset.breakdown);
      const tooltip = card.querySelector('.severity-tooltip');
      const severity = card.dataset.filter;

      let html = '<div class="tooltip-title">\ud83d\udcca ' + severity.toUpperCase() + ' by Tab</div>';
      let hasAny = false;
      let tabsWithEvents = 0;

      for (const [key, count] of Object.entries(breakdown)) {
        if (count > 0) {
          hasAny = true;
          tabsWithEvents++;
        }
        const rowClass = count > 0 ? 'tooltip-row has-events' : 'tooltip-row';
        html += '<div class="' + rowClass + '" data-tab="' + tabIds[key] + '" data-severity="' + severity + '" data-count="' + count + '">';
        html += '<span class="tab-name">' + tabNames[key] + '</span>';
        html += '<span class="count">' + count + '</span>';
        html += '</div>';
      }

      if (tabsWithEvents === 1) {
        card.classList.add('direct-navigate');
      }

      if (!hasAny) {
        card.classList.add('no-events');
        html += '<div style="color: var(--text-muted); font-style: italic; padding-top: 4px;">No events</div>';
      } else if (tabsWithEvents > 1) {
        html += '<div style="color: var(--text-muted); font-size: 10px; margin-top: 8px; padding-top: 6px; border-top: 1px solid var(--border-color);">Click a row to navigate, or click card for most events</div>';
      }

      // Security: Use DOM APIs instead of innerHTML to prevent stored XSS
      tooltip.textContent = '';
      const wrapper = document.createElement('div');
      wrapper.innerHTML = html;
      while (wrapper.firstChild) {
        tooltip.appendChild(wrapper.firstChild);
      }

      // Add click handlers to tooltip rows
      tooltip.querySelectorAll('.tooltip-row.has-events').forEach(row => {
        row.addEventListener('click', (e) => {
          e.stopPropagation();
          const tabId = row.dataset.tab;
          const sev = row.dataset.severity;

          const tabBtn = document.querySelector('.tab[data-tab="' + tabId + '"]');
          if (tabBtn) {
            tabBtn.click();
            setTimeout(() => {
              const tabContent = document.getElementById('content-' + tabId);
              if (tabContent) {
                const filterBtn = tabContent.querySelector('[data-filter="' + sev + '"]');
                if (filterBtn) filterBtn.click();
                setTimeout(() => {
                  const firstEvent = tabContent.querySelector('.event-card.severity-' + sev);
                  if (firstEvent) {
                    firstEvent.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    firstEvent.style.background = 'var(--bg-hover)';
                    setTimeout(() => firstEvent.style.background = '', 2000);
                  }
                }, 100);
              }
            }, 50);
          }
        });
      });
    });

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('content-' + tab.dataset.tab).classList.add('active');
      });
    });

    // Event card expansion
    document.querySelectorAll('.event-header').forEach(header => {
      header.addEventListener('click', () => {
        header.parentElement.classList.toggle('expanded');
      });
    });

    // Filter controls
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const container = btn.closest('.tab-content');
        container.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filter = btn.dataset.filter;
        container.querySelectorAll('.event-card').forEach(card => {
          if (filter === 'all') {
            card.style.display = 'block';
          } else {
            card.style.display = card.classList.contains('severity-' + filter) ? 'block' : 'none';
          }
        });

        // Update tab badge count to reflect filtered results
        const tabId = container.id.replace('content-', '');
        const tabEl = document.querySelector('.tab[data-tab="' + tabId + '"]');
        if (tabEl) {
          const countEl = tabEl.querySelector('.count');
          if (countEl) {
            const visibleCount = container.querySelectorAll('.event-card:not([style*="display: none"])').length;
            const totalCount = container.querySelectorAll('.event-card').length;
            countEl.textContent = filter === 'all' ? String(totalCount) : visibleCount + '/' + totalCount;
          }
        }

        // Update subsection badge counts within this tab
        container.querySelectorAll('.subsection').forEach(subsection => {
          const badge = subsection.querySelector('h4 .badge');
          if (badge) {
            const visibleInSection = subsection.querySelectorAll('.event-card:not([style*="display: none"])').length;
            const totalInSection = subsection.querySelectorAll('.event-card').length;
            const label = badge.textContent.replace(/^[\\d\\/]+\\s*/, '');
            badge.textContent = filter === 'all' ? totalInSection + ' ' + label : visibleInSection + '/' + totalInSection + ' ' + label;
          }
        });
      });
    });

    // Metric card click navigation
    document.querySelectorAll('.metric-card[data-navigate]').forEach(card => {
      card.addEventListener('click', () => {
        const targetTab = card.dataset.navigate;
        const filterSeverity = card.dataset.filter;
        const breakdown = card.dataset.breakdown ? JSON.parse(card.dataset.breakdown) : null;
        const cardCount = parseInt(card.dataset.count || '0', 10);

        if (cardCount === 0) {
          return;
        }

        if (filterSeverity && breakdown) {
          let maxCount = 0;
          let bestTab = null;
          const tabMapping = {
            governor: 'governor',
            injection: 'injection',
            imageSafety: 'injection',
            secureCode: 'secure-code',
            linter: 'linter',
            leash: 'leash',
            memory: 'memory'
          };

          for (const [key, count] of Object.entries(breakdown)) {
            if (count > maxCount) {
              maxCount = count;
              bestTab = tabMapping[key];
            }
          }

          if (bestTab && maxCount > 0) {
            const tabBtn = document.querySelector(\`.tab[data-tab="\${bestTab}"]\`);
            if (tabBtn) {
              tabBtn.click();
              setTimeout(() => {
                const tabContent = document.getElementById('content-' + bestTab);
                if (tabContent) {
                  const filterBtn = tabContent.querySelector(\`[data-filter="\${filterSeverity}"]\`);
                  if (filterBtn) filterBtn.click();
                  setTimeout(() => {
                    const firstEvent = tabContent.querySelector(\`.event-card.severity-\${filterSeverity}\`);
                    if (firstEvent) {
                      firstEvent.scrollIntoView({ behavior: 'smooth', block: 'center' });
                      firstEvent.style.background = 'var(--bg-hover)';
                      setTimeout(() => firstEvent.style.background = '', 2000);
                    }
                  }, 100);
                }
              }, 50);
            }
          }
        } else {
          const tabBtn = document.querySelector(\`.tab[data-tab="\${targetTab}"]\`);
          if (tabBtn) {
            tabBtn.click();

            const filterAction = card.dataset.filterAction;
            if (filterAction) {
              setTimeout(() => {
                const tabContent = document.getElementById('content-' + targetTab);
                if (tabContent) {
                  tabContent.querySelectorAll('.event-card').forEach(eventCard => {
                    if (eventCard.classList.contains('action-' + filterAction)) {
                      eventCard.style.display = 'block';
                    } else {
                      eventCard.style.display = 'none';
                    }
                  });
                  tabContent.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                  });
                  const allBtn = tabContent.querySelector('[data-filter="all"]');
                  if (allBtn) allBtn.classList.add('active');
                  setTimeout(() => {
                    const firstEvent = tabContent.querySelector(\`.event-card.action-\${filterAction}\`);
                    if (firstEvent) {
                      firstEvent.scrollIntoView({ behavior: 'smooth', block: 'center' });
                      firstEvent.style.background = 'var(--bg-hover)';
                      setTimeout(() => firstEvent.style.background = '', 2000);
                    }
                  }, 100);
                }
              }, 50);
            }
          }
        }
      });
    });

    // Timeline marker click
    document.querySelectorAll('.timeline-marker').forEach(marker => {
      marker.addEventListener('click', () => {
        const eventType = marker.dataset.eventType;
        const tabMap = {
          'tool': 'trace',
          'governor': 'governor',
          'memory': 'memory',
          'injection': 'injection',
          'error': 'errors',
          'evaluator': 'evaluator'
        };
        const tabName = tabMap[eventType] || 'governor';
        const tab = document.querySelector(\`.tab[data-tab="\${tabName}"]\`);
        if (tab) {
          tab.click();
          tab.style.boxShadow = '0 0 10px var(--accent-blue)';
          setTimeout(() => tab.style.boxShadow = '', 1000);
        }
      });
    });

    // Expand all / Collapse all keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'e' && e.ctrlKey) {
        e.preventDefault();
        const activeContent = document.querySelector('.tab-content.active');
        const cards = activeContent.querySelectorAll('.event-card');
        const allExpanded = Array.from(cards).every(c => c.classList.contains('expanded'));
        cards.forEach(c => allExpanded ? c.classList.remove('expanded') : c.classList.add('expanded'));
      }
    });
  </script>
</body>
</html>`;
}

// ============================================================================
// Event HTML Generators
// ============================================================================

function generateGovernorEventsHTML(events: GovernorAuditEntry[]): string {
  const filtered = events.filter((e) => e.policy_matched && e.policy_matched !== 'none').slice(0, 50);

  if (filtered.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No policy violations detected</p></div>';
  }

  return filtered.map((e) => `
    <div class="event-card severity-${(e.severity || 'medium').toLowerCase()}">
      <div class="event-header">
        <div class="event-icon">${getToolIcon(e.tool)}</div>
        <div class="event-title">${escapeHtml(e.policy_matched && e.policy_matched !== 'none' ? e.policy_matched : (e.message || e.tool || 'Unknown Policy'))}</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-${(e.severity || 'medium').toLowerCase()}">${escapeHtml(e.severity || 'MEDIUM')}</span>
          <span class="badge badge-tool">${escapeHtml(e.tool || 'unknown')}</span>
          ${e.input_modified ? '<span class="badge badge-modified">MODIFIED</span>' : ''}
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Message</span>
          <span class="detail-value">${escapeHtml(e.message)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Action</span>
          <span class="detail-value">${escapeHtml(e.action)}</span>
        </div>
        ${e.modification_type ? `
        <div class="detail-row">
          <span class="detail-label">Modification</span>
          <span class="detail-value">${escapeHtml(e.modification_type)}</span>
        </div>
        ` : ''}
        ${e.parameters ? `
        <div class="detail-row">
          <span class="detail-label">Parameters</span>
          <div class="code-block">${escapeHtml(JSON.stringify(e.parameters, null, 2))}</div>
        </div>
        ` : ''}
      </div>
    </div>
  `).join('');
}

function generateEvaluatorEventsHTML(events: EvaluatorAuditEntry[]): string {
  if (events.length === 0) {
    return '<div class="empty-state"><div class="emoji">\ud83d\udcdd</div><p>No commits validated this session</p></div>';
  }

  const passed = events.filter((e) => e.status === 'PASSED').length;
  const warnings = events.filter((e) => e.status === 'PASSED_WITH_WARNINGS').length;
  const failed = events.filter((e) => e.status === 'FAILED').length;
  const totalSecurityIssues = events.reduce((acc, e) => acc + e.security_issues, 0);
  const totalQualityWarnings = events.reduce((acc, e) => acc + e.quality_warnings, 0);

  const summaryHtml = `
    <div class="evaluator-summary" style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; padding: 16px; background: rgba(139, 148, 158, 0.05); border-radius: 8px;">
      <div style="text-align: center;">
        <div style="font-size: 24px; font-weight: bold; color: var(--accent-green);">${passed}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Passed</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 24px; font-weight: bold; color: var(--accent-yellow);">${warnings}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Warnings</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 24px; font-weight: bold; color: var(--accent-red);">${failed}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Failed</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 24px; font-weight: bold; color: var(--accent-red);">${totalSecurityIssues}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Security Issues</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 24px; font-weight: bold; color: var(--accent-yellow);">${totalQualityWarnings}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Quality Warns</div>
      </div>
    </div>
  `;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PASSED': return '<span class="badge" style="background: var(--accent-green); color: white;">\u2705 PASSED</span>';
      case 'PASSED_WITH_WARNINGS': return '<span class="badge" style="background: var(--accent-yellow); color: black;">\u26a0\ufe0f WARNINGS</span>';
      case 'FAILED': return '<span class="badge" style="background: var(--accent-red); color: white;">\u274c FAILED</span>';
      default: return `<span class="badge">${status}</span>`;
    }
  };

  const getSeverity = (e: EvaluatorAuditEntry) => {
    if (e.status === 'FAILED') return 'critical';
    if (e.status === 'PASSED_WITH_WARNINGS') return 'medium';
    return 'low';
  };

  const commitsHtml = events.map((e) => `
    <div class="event-card severity-${getSeverity(e)}">
      <div class="event-header">
        <div class="event-icon">\ud83d\udce6</div>
        <div class="event-title" style="font-family: monospace;">${escapeHtml(e.commit_short)}</div>
        <div class="event-badges">
          ${getStatusBadge(e.status)}
          <span class="badge badge-tool">${e.files_changed} file${e.files_changed !== 1 ? 's' : ''}</span>
          ${e.security_issues > 0 ? `<span class="badge badge-severity badge-critical">${e.security_issues} security</span>` : ''}
          ${e.quality_warnings > 0 ? `<span class="badge badge-severity badge-medium">${e.quality_warnings} quality</span>` : ''}
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Commit</span>
          <span class="detail-value" style="font-family: monospace;">${escapeHtml(e.commit)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Message</span>
          <span class="detail-value">${escapeHtml(e.message)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Author</span>
          <span class="detail-value">${escapeHtml(e.author)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Security Issues</span>
          <span class="detail-value">${e.security_issues}</span>
        </div>
        ${e.security_findings && e.security_findings.length > 0 ? `
        <div class="detail-row">
          <span class="detail-label">Security Findings</span>
          <div class="findings-list">
            ${e.security_findings.map((f) => `
              <div class="finding-item" style="margin: 8px 0; padding: 8px; background: rgba(248, 81, 73, 0.1); border-radius: 4px; border-left: 3px solid var(--accent-red);">
                <div style="font-weight: 500; color: var(--accent-red); margin-bottom: 4px;">\ud83d\udd12 ${escapeHtml(f.description)}</div>
                ${f.line ? `<div style="font-family: monospace; font-size: 11px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 4px 8px; border-radius: 3px; overflow-x: auto; white-space: pre;">${escapeHtml(f.line)}</div>` : ''}
                ${f.file ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">File: ${escapeHtml(f.file)}</div>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
        ` : ''}
        <div class="detail-row">
          <span class="detail-label">Quality Warnings</span>
          <span class="detail-value">${e.quality_warnings}</span>
        </div>
        ${e.quality_findings && e.quality_findings.length > 0 ? `
        <div class="detail-row">
          <span class="detail-label">Quality Findings</span>
          <div class="findings-list">
            ${e.quality_findings.map((f) => `
              <div class="finding-item" style="margin: 8px 0; padding: 8px; background: rgba(210, 153, 34, 0.1); border-radius: 4px; border-left: 3px solid var(--accent-yellow);">
                <div style="font-weight: 500; color: var(--accent-yellow); margin-bottom: 4px;">\ud83d\udcdd ${escapeHtml(f.description)}</div>
                ${f.line ? `<div style="font-family: monospace; font-size: 11px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 4px 8px; border-radius: 3px; overflow-x: auto; white-space: pre;">${escapeHtml(f.line)}</div>` : ''}
                ${f.file ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">File: ${escapeHtml(f.file)}</div>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
        ` : ''}
      </div>
    </div>
  `).join('');

  return summaryHtml + commitsHtml;
}

function generateInjectionEventsHTML(scans: InjectionScanEntry[]): string {
  const filtered = scans.filter((e) => e.injection_detected).slice(0, 30);

  if (filtered.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No injection patterns detected</p></div>';
  }

  return filtered.map((e) => `
    <div class="event-card severity-${(e.severity || 'medium').toLowerCase()}">
      <div class="event-header">
        <div class="event-icon">${getToolIcon(e.tool)}</div>
        <div class="event-title">Injection Detected: ${escapeHtml(e.categories.join(', '))}</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-${(e.severity || 'medium').toLowerCase()}">${escapeHtml(e.severity || 'MEDIUM')}</span>
          <span class="badge badge-tool">${escapeHtml(e.tool)}</span>
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Patterns</span>
          <span class="detail-value">${escapeHtml(e.patterns_matched.join(', '))}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Content Size</span>
          <span class="detail-value">${e.content_length} bytes</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Scan Time</span>
          <span class="detail-value">${e.scan_duration_ms}ms</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Snippet</span>
          <div class="code-block">${escapeHtml(e.content_snippet)}</div>
        </div>
      </div>
    </div>
  `).join('');
}

function generateImageSafetyEventsHTML(events: ImageSafetyEntry[]): string {
  if (events.length === 0) {
    return '<div class="empty-state"><div class="emoji">\ud83d\uddbc\ufe0f</div><p>No images scanned this session</p></div>';
  }

  const suspicious = events.filter((e) => e.result.suspicious);
  const clean = events.filter((e) => !e.result.suspicious);

  const summaryHtml = `
    <div class="image-safety-summary" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; padding: 12px; background: rgba(139, 148, 158, 0.05); border-radius: 8px;">
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--text-primary);">${events.length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Scanned</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-green);">${clean.length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Clean</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-red);">${suspicious.length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Suspicious</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-yellow);">${events.filter((e) => e.action_taken === 'quarantined').length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Quarantined</div>
      </div>
    </div>
  `;

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'low';
    }
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'blocked': return '<span class="badge" style="background: var(--accent-red); color: white;">\ud83d\udeab BLOCKED</span>';
      case 'quarantined': return '<span class="badge" style="background: var(--accent-orange); color: white;">\ud83d\udce6 QUARANTINED</span>';
      case 'warned': return '<span class="badge" style="background: var(--accent-yellow); color: black;">\u26a0\ufe0f WARNED</span>';
      case 'allowed': return '<span class="badge" style="background: var(--accent-green); color: white;">\u2705 ALLOWED</span>';
      default: return `<span class="badge">${action}</span>`;
    }
  };

  const eventsToShow = [...suspicious, ...clean.slice(0, 5)];

  const eventsHtml = eventsToShow.map((e) => {
    const fileName = e.file_path.split('/').pop() || e.file_path;
    const indicatorsHtml = e.result.indicators.length > 0
      ? e.result.indicators.map((ind) => `
          <div style="padding: 8px; background: rgba(139, 148, 158, 0.1); border-radius: 4px; margin-top: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 500; color: var(--text-primary);">${escapeHtml(ind.type)}</span>
              <span class="badge badge-severity badge-${getSeverityClass(ind.severity)}">${ind.severity}</span>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">${escapeHtml(ind.description)}</div>
            ${ind.evidence ? `<div class="code-block" style="margin-top: 4px; font-size: 11px;">${escapeHtml(ind.evidence)}</div>` : ''}
          </div>
        `).join('')
      : '<div style="color: var(--text-muted); font-style: italic;">No indicators</div>';

    return `
      <div class="event-card severity-${getSeverityClass(e.result.severity)}">
        <div class="event-header">
          <div class="event-icon">\ud83d\uddbc\ufe0f</div>
          <div class="event-title" style="font-family: monospace;">${escapeHtml(fileName)}</div>
          <div class="event-badges">
            ${e.result.suspicious
              ? `<span class="badge badge-severity badge-${getSeverityClass(e.result.severity)}">${escapeHtml(e.result.severity)}</span>`
              : '<span class="badge" style="background: var(--accent-green); color: white;">CLEAN</span>'
            }
            ${getActionBadge(e.action_taken)}
            <span class="badge badge-tool">${escapeHtml(String(e.result.confidence))} conf</span>
          </div>
          <span class="event-time">${formatTime(e.timestamp)}</span>
          <span class="event-expand">\u25bc</span>
        </div>
        <div class="event-details">
          <div class="detail-row">
            <span class="detail-label">File Path</span>
            <span class="detail-value" style="font-family: monospace; font-size: 11px;">${escapeHtml(e.file_path)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Scan Time</span>
            <span class="detail-value">${e.result.executionTime}ms</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Indicators (${e.result.indicators.length})</span>
            <div class="detail-value" style="max-height: 200px; overflow-y: auto;">${indicatorsHtml}</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  return summaryHtml + eventsHtml;
}

function generateSecureCodeEventsHTML(events: SecureCodeEntry[]): string {
  const filtered = events.filter((e) => e.classification === 'SECURITY_SENSITIVE').slice(0, 30);

  if (filtered.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No security-sensitive code writes detected</p></div>';
  }

  return filtered.map((e) => `
    <div class="event-card severity-${e.risk_level.toLowerCase()}">
      <div class="event-header">
        <div class="event-icon">${getToolIcon(e.tool)}</div>
        <div class="event-title">${escapeHtml(e.file_path ? (e.file_path.split('/').pop() || e.file_path) : 'unknown')}</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-${e.risk_level?.toLowerCase() || 'medium'}">${escapeHtml(e.risk_level || 'MEDIUM')}</span>
          <span class="badge badge-tool">${escapeHtml(e.language)}</span>
          ${e.suggested_review ? '<span class="badge badge-modified">REVIEW</span>' : ''}
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">File</span>
          <span class="detail-value">${escapeHtml(e.file_path || 'unknown')}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Triggers</span>
          <span class="detail-value">${escapeHtml(e.triggers ? e.triggers.join(', ') : 'unknown')}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Confidence</span>
          <span class="detail-value">${escapeHtml(String(e.confidence))}</span>
        </div>
      </div>
    </div>
  `).join('');
}

function generateLinterEventsHTML(events: SecureCodeLinterEntry[]): string {
  if (events.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No vulnerable code detected and reverted</p></div>';
  }

  const sorted = sortBySeverity(events);
  const truncated = events.length > 30;

  let html = sorted.slice(0, 30).map((e) => `
    <div class="event-card severity-${e.severity.toLowerCase()}${e.action === 'REVERT' || e.reverted ? ' action-reverted' : ''}">
      <div class="event-header">
        <div class="event-icon">${getToolIcon(e.tool)}</div>
        <div class="event-title">${escapeHtml(e.file_path ? (e.file_path.split('/').pop() || e.file_path) : 'unknown')}</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-${e.severity?.toLowerCase() || 'medium'}">${escapeHtml(e.severity || 'MEDIUM')}</span>
          ${e.action === 'REVERT' || e.reverted ? '<span class="badge badge-blocked">\ud83d\udd04 REVERTED</span>' :
            e.action === 'WARN' ? '<span class="badge" style="background: var(--warning-color)">\u26a0\ufe0f WARN</span>' :
            '<span class="badge" style="background: var(--accent-blue)">\ud83d\udcdd LOG</span>'}
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Action</span>
          <span class="detail-value">${escapeHtml(e.action)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Findings</span>
          <span class="detail-value">${e.error_count || 0} errors, ${e.warning_count || 0} warnings</span>
        </div>
        ${e.top_findings && e.top_findings.length > 0 ? `
        <div class="detail-row">
          <span class="detail-label">Top Issues</span>
          <span class="detail-value">${escapeHtml(e.top_findings.join('; '))}</span>
        </div>
        ` : ''}
        ${e.llm_verdict ? `
        <div class="detail-row">
          <span class="detail-label">LLM Review</span>
          <span class="detail-value" style="color: ${e.llm_verdict === 'UNSAFE' ? 'var(--accent-red)' : e.llm_verdict === 'NEEDS_REVIEW' ? 'var(--accent-yellow)' : 'var(--accent-green)'};">
            ${escapeHtml(e.llm_verdict)} (${escapeHtml(String(e.llm_confidence || 'N/A'))} confidence)
          </span>
        </div>
        ` : ''}
        ${e.escalation_reason ? `
        <div class="detail-row">
          <span class="detail-label">Escalation Reason</span>
          <span class="detail-value">${escapeHtml(e.escalation_reason)}</span>
        </div>
        ` : ''}
        ${e.llm_vulnerabilities && e.llm_vulnerabilities.length > 0 ? `
        <div class="detail-row">
          <span class="detail-label">LLM Findings</span>
          <span class="detail-value">${escapeHtml(e.llm_vulnerabilities.map(v => typeof v === 'string' ? v : v.vulnerability || JSON.stringify(v)).join('; '))}</span>
        </div>
        ` : ''}
        ${e.quarantine_path ? `
        <div class="detail-row">
          <span class="detail-label">Quarantine</span>
          <span class="detail-value">${escapeHtml(e.quarantine_path)}</span>
        </div>
        ` : ''}
      </div>
    </div>
  `).join('');

  if (truncated) {
    html += `<div class="truncation-notice" style="text-align: center; padding: 12px; color: var(--text-muted); font-size: 12px; border-top: 1px solid var(--border-color); margin-top: 8px;">
      Showing 30 of ${events.length} events (sorted by severity, CRITICAL first)
    </div>`;
  }

  return html;
}

function generateLeashEventsHTML(events: LeashEvent[]): string {
  const filtered = events.filter((e) => e.decision === 'DENY').slice(0, 50);

  if (filtered.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No syscalls blocked by Leash kernel sandbox</p></div>';
  }

  return filtered.map((e) => `
    <div class="event-card severity-${e.severity.toLowerCase()}">
      <div class="event-header">
        <div class="event-icon">${TOOL_ICONS.default}</div>
        <div class="event-title">${escapeHtml(e.action || 'action')}: ${escapeHtml(e.resource ? (e.resource.split('/').pop() || e.resource) : 'unknown')}</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-${e.severity.toLowerCase()}">${escapeHtml(e.severity)}</span>
          <span class="badge" style="background: var(--accent-blue)">${escapeHtml(e.category)}</span>
          <span class="badge badge-blocked">BLOCKED</span>
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Resource</span>
          <span class="detail-value">${escapeHtml(e.resource)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Policy</span>
          <span class="detail-value">${escapeHtml(e.policy_id)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Details</span>
          <div class="code-block">${escapeHtml(JSON.stringify(e.details, null, 2))}</div>
        </div>
      </div>
    </div>
  `).join('');
}

function generateMemorySecurityEventsHTML(events: MemorySecurityEntry[]): string {
  const withFindings = events.filter((e) => e.findings && e.findings.length > 0);

  if (withFindings.length === 0) {
    return '<div class="empty-state"><div class="emoji">\ud83e\udde0</div><p>No memory poisoning attempts detected</p></div>';
  }

  const preToolUse = withFindings.filter((e) => e.hookType === 'PreToolUse');
  const postToolUse = withFindings.filter((e) => e.hookType === 'PostToolUse');
  const criticalCount = withFindings.filter((e) => e.highestSeverity === 'CRITICAL').length;
  const blocked = withFindings.filter((e) => e.action === 'BLOCK').length;

  const summaryHtml = `
    <div class="memory-security-summary" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; padding: 12px; background: rgba(139, 148, 158, 0.05); border-radius: 8px;">
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-red);">${withFindings.length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Attempts</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-red);">${criticalCount}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Critical</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-orange);">${blocked}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Blocked</div>
      </div>
      <div style="text-align: center;">
        <div style="font-size: 20px; font-weight: bold; color: var(--accent-yellow);">${postToolUse.length}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Post-Exec Alerts</div>
      </div>
    </div>
    <div style="margin-bottom: 12px; padding: 8px; background: rgba(255, 82, 82, 0.1); border-radius: 6px; border-left: 3px solid var(--accent-red);">
      <div style="font-size: 12px; color: var(--accent-red); font-weight: 500;">\u26a0\ufe0f Memory Poisoning Detected</div>
      <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
        Malicious content was detected in MCP Memory Server operations. Maps to OWASP ASI06 (Memory &amp; Context Manipulation) and MITRE ATLAS AML.T0064 (Data Poisoning).
      </div>
    </div>
  `;

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'low';
    }
  };

  const getActionBadge = (entry: MemorySecurityEntry) => {
    if (entry.action === 'BLOCK') {
      return '<span class="badge badge-blocked">\ud83d\udeab BLOCKED</span>';
    } else if (entry.hookType === 'PostToolUse' && entry.alertLevel?.includes('CRITICAL')) {
      return '<span class="badge" style="background: var(--accent-orange); color: white;">\ud83d\udea8 ALERT</span>';
    } else if (entry.action === 'WARN') {
      return '<span class="badge" style="background: var(--accent-yellow); color: black;">\u26a0\ufe0f WARNED</span>';
    }
    return '<span class="badge">' + (entry.action || entry.alertLevel || 'DETECTED') + '</span>';
  };

  const eventsHtml = withFindings.slice(0, 50).map((e) => {
    const findingsHtml = e.findings.map((f) => `
      <div style="padding: 8px; background: rgba(139, 148, 158, 0.1); border-radius: 4px; margin-top: 4px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-weight: 500; color: var(--text-primary);">${escapeHtml(f.patternId)}</span>
          <span class="badge badge-severity badge-${getSeverityClass(f.severity)}">${f.severity}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">${escapeHtml(f.description)}</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Location: ${escapeHtml(f.location)}</div>
        <div class="code-block" style="margin-top: 4px; font-size: 11px;">${escapeHtml(f.matchedText)}</div>
      </div>
    `).join('');

    return `
      <div class="event-card severity-${getSeverityClass(e.highestSeverity)}">
        <div class="event-header">
          <div class="event-icon">\ud83e\udde0</div>
          <div class="event-title">${escapeHtml(e.operation)} (${escapeHtml(e.hookType)})</div>
          <div class="event-badges">
            <span class="badge badge-severity badge-${getSeverityClass(e.highestSeverity)}">${escapeHtml(e.highestSeverity)}</span>
            ${getActionBadge(e)}
            <span class="badge badge-tool">${escapeHtml(e.tool.replace('mcp__memory__', ''))}</span>
          </div>
          <span class="event-time">${formatTime(e.timestamp)}</span>
          <span class="event-expand">\u25bc</span>
        </div>
        <div class="event-details">
          <div class="detail-row">
            <span class="detail-label">Hook Type</span>
            <span class="detail-value">${escapeHtml(e.hookType)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Operation</span>
            <span class="detail-value">${escapeHtml(e.operation)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Evaluation Time</span>
            <span class="detail-value">${e.evaluationTimeMs}ms</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Findings (${e.findings.length})</span>
            <div class="detail-value" style="max-height: 200px; overflow-y: auto;">${findingsHtml}</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  return summaryHtml + eventsHtml;
}

function generateTraceHTML(events: ConversationEvent[]): string {
  if (events.length === 0) {
    return '<div class="empty-state"><div class="emoji">\ud83d\udced</div><p>No conversation trace available</p></div>';
  }

  return events.map((e) => `
    <div class="trace-event" data-trace-id="${e.id}">
      <div class="trace-icon ${e.type}">
        ${e.type === 'user'
          ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
          : getToolIcon(e.toolName || 'default')
        }
      </div>
      <div class="trace-content">
        <div class="trace-header">
          <span class="trace-type">${e.type === 'user' ? 'User' : escapeHtml(e.toolName || 'Tool')}</span>
          <span class="trace-time">${formatTime(e.timestamp)}</span>
        </div>
        <div class="trace-text">${escapeHtml(e.content.substring(0, 300))}${e.content.length > 300 ? '...' : ''}</div>
      </div>
    </div>
  `).join('');
}

function generateErrorsHTML(errors: ErrorEntry[]): string {
  if (errors.length === 0) {
    return '<div class="empty-state"><div class="emoji">\u2705</div><p>No errors during this session</p></div>';
  }

  return errors.slice(0, 20).map((e) => `
    <div class="event-card severity-medium">
      <div class="event-header">
        <div class="event-icon" style="background: var(--accent-red); color: white;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        </div>
        <div class="event-title">${escapeHtml((e.message || 'Unknown error').substring(0, 60))}...</div>
        <div class="event-badges">
          <span class="badge badge-severity badge-high">${escapeHtml(e.level?.toUpperCase() || 'ERROR')}</span>
        </div>
        <span class="event-time">${formatTime(e.timestamp)}</span>
        <span class="event-expand">\u25bc</span>
      </div>
      <div class="event-details">
        <div class="detail-row">
          <span class="detail-label">Message</span>
          <span class="detail-value">${escapeHtml(e.message)}</span>
        </div>
        ${e.source ? `
        <div class="detail-row">
          <span class="detail-label">Source</span>
          <span class="detail-value">${escapeHtml(e.source)}</span>
        </div>
        ` : ''}
      </div>
    </div>
  `).join('');
}

function generateATLASMappingHTML(): string {
  // Calculate coverage statistics — only count IDs from ACTIVE layers
  const activeMappings = ATLAS_MAPPINGS_LOADED.filter(m => m.status === 'active');
  const uniqueAtlasIds = new Set(activeMappings.flatMap(m => m.atlasIds));
  const uniqueOwaspIds = new Set(activeMappings.flatMap(m => m.owaspIds));
  const activeLayers = activeMappings.length;
  const notInstalledLayers = ATLAS_MAPPINGS_LOADED.filter(m => m.status === 'not_installed').length;

  const getOwaspSeverityClass = (id: string): string => {
    const info = OWASP_LLM_2025[id as keyof typeof OWASP_LLM_2025];
    if (!info) return 'owasp-medium';
    if (info.severity === 'CRITICAL') return 'owasp-critical';
    if (info.severity === 'HIGH') return 'owasp-high';
    return 'owasp-medium';
  };

  // Calculate architectural gaps
  const architecturalGaps = [
    { id: 'LLM07', name: 'System Prompt Leakage', reason: 'System prompts in CLAUDE.md are public (not sensitive)' },
  ];
  const totalOwaspItems = Object.keys(OWASP_LLM_2025).length || 10;
  const effectiveCoverage = totalOwaspItems - architecturalGaps.length;
  const naOwaspIdsForSummary = new Set(architecturalGaps.map(g => g.id));
  const applicableOwaspCovered = Array.from(uniqueOwaspIds).filter(id => !naOwaspIdsForSummary.has(id)).length;

  // Agentic stats for summary bar (dynamically calculated)
  const agenticDataForSummary = OWASP_AGENTIC_2026;
  const agenticItemsForSummary = Object.entries(agenticDataForSummary).filter(([k]) => k.startsWith('ASI'));
  const agenticCoveredForSummary = agenticItemsForSummary.filter(([, v]: [string, any]) => v.coverage === 'covered').length;
  const agenticPartialForSummary = agenticItemsForSummary.filter(([, v]: [string, any]) => v.coverage === 'partial' || v.coverage === 'detection').length;

  const setupNote = notInstalledLayers > 0
    ? `<div class="coverage-sublabel">${notInstalledLayers} require setup</div>`
    : '';

  const coverageSummary = `
    <div class="coverage-summary">
      <div class="coverage-item">
        <div class="coverage-value">${activeLayers}/${ATLAS_MAPPINGS_LOADED.length}</div>
        <div class="coverage-label">Active Security Layers</div>
        ${setupNote}
      </div>
      <div class="coverage-item">
        <div class="coverage-value">${uniqueAtlasIds.size}/${TOTAL_RELEVANT_ATLAS}</div>
        <div class="coverage-label">ATLAS Techniques Covered</div>
      </div>
      <div class="coverage-item">
        <div class="coverage-value">${applicableOwaspCovered}/${effectiveCoverage}</div>
        <div class="coverage-label">OWASP LLM Covered*</div>
      </div>
      <div class="coverage-item">
        <div class="coverage-value">${agenticCoveredForSummary}+${agenticPartialForSummary}/${agenticItemsForSummary.length}</div>
        <div class="coverage-label">OWASP Agentic (covered+partial)</div>
      </div>
      <div class="coverage-item">
        <div class="coverage-value">100%</div>
        <div class="coverage-label">Local Processing</div>
      </div>
    </div>
    <div class="coverage-note" style="margin-top: 16px; padding: 12px 16px; background: rgba(110, 118, 129, 0.1); border-radius: 8px; border-left: 3px solid var(--accent-blue);">
      <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">
        <strong>* Architectural Note:</strong> Vex-Talon uses Claude API (not self-hosted models), making ${architecturalGaps.length} OWASP items not applicable:
      </div>
      <div style="display: flex; gap: 16px; flex-wrap: wrap;">
        ${architecturalGaps.map(gap => `
          <div style="font-size: 11px; color: var(--text-muted);">
            <span style="color: var(--accent-yellow);">N/A</span> <strong>${gap.id}</strong>: ${gap.name} <span style="opacity: 0.7;">(${gap.reason})</span>
          </div>
        `).join('')}
      </div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
        Coverage is <strong>${applicableOwaspCovered}/${effectiveCoverage}</strong> of applicable items = <strong>${Math.round((applicableOwaspCovered / effectiveCoverage) * 100)}%</strong> effective coverage
      </div>
    </div>
  `;

  // OWASP Agentic 2026 Section
  const agenticData = OWASP_AGENTIC_2026;
  const agenticItems = Object.entries(agenticData).filter(([k]) => k.startsWith('ASI'));
  const agenticCovered = agenticItems.filter(([, v]: [string, any]) => v.coverage === 'covered').length;
  const agenticPartial = agenticItems.filter(([, v]: [string, any]) => v.coverage === 'partial' || v.coverage === 'detection').length;
  const agenticGaps = agenticItems.filter(([, v]: [string, any]) => v.coverage === 'gap').length;

  const agenticSection = `
    <div class="framework-section expanded" id="agentic-section" style="background: rgba(88, 166, 255, 0.08); border-color: rgba(88, 166, 255, 0.2);">
      <div class="framework-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="framework-title">
          <h3 style="margin: 0; font-size: 14px; color: #58a6ff;">\ud83e\udd16 OWASP Top 10 for Agentic Applications 2026</h3>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
            <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" style="color: var(--accent-blue);" onclick="event.stopPropagation();">Framework for autonomous AI systems</a>
            - Released Dec 2025
          </div>
        </div>
        <div class="framework-stats">
          <span class="stat-badge covered">${agenticCovered} covered</span>
          <span class="stat-badge partial">${agenticPartial} partial</span>
          <span class="stat-badge gap">${agenticGaps} gap</span>
          <span class="framework-expand">\u25bc</span>
        </div>
      </div>
      <div class="framework-content">
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 8px;">
          ${agenticItems.map(([id, item]: [string, any]) => {
            const isPartialOrDetection = item.coverage === 'partial' || item.coverage === 'detection';
            const statusColor = item.coverage === 'covered' ? '#3fb950' : isPartialOrDetection ? '#d29922' : '#f85149';
            const statusBg = item.coverage === 'covered' ? 'rgba(46, 160, 67, 0.15)' : isPartialOrDetection ? 'rgba(210, 153, 34, 0.15)' : 'rgba(248, 81, 73, 0.15)';
            const statusIcon = item.coverage === 'covered' ? '\u2705' : isPartialOrDetection ? '\u26a0\ufe0f' : '\ud83d\udea8';
            return `
              <div style="padding: 10px 12px; background: ${statusBg}; border-radius: 6px; border-left: 3px solid ${statusColor};">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                  <div>
                    <span style="font-weight: 600; color: ${statusColor};">${id}</span>
                    <span style="margin-left: 6px; font-size: 12px;">${item.name}</span>
                  </div>
                  <span style="font-size: 12px;">${statusIcon}</span>
                </div>
                ${item.notes ? `<div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">${item.notes}</div>` : ''}
              </div>
            `;
          }).join('')}
        </div>
        ${agenticGaps > 0 ? `
          <div style="margin-top: 12px; padding: 10px; background: rgba(248, 81, 73, 0.1); border-radius: 6px; font-size: 11px; color: #f85149;">
            <strong>\u26a0\ufe0f Action Required:</strong> ${agenticGaps} gap(s) identified in OWASP Agentic framework coverage
          </div>
        ` : ''}
      </div>
    </div>
  `;

  // MITRE ATLAS Section
  const atlasBreakdown: Record<string, { name: string; layers: string[] }> = {};
  ATLAS_MAPPINGS_LOADED.forEach(mapping => {
    mapping.atlasIds.forEach((id, i) => {
      if (!atlasBreakdown[id]) {
        atlasBreakdown[id] = { name: mapping.atlasNames[i] || 'Unknown', layers: [] };
      }
      atlasBreakdown[id].layers.push(`L${mapping.layer}`);
    });
  });
  const atlasCovered = Object.keys(atlasBreakdown).length;

  const atlasSection = `
    <div class="framework-section" id="atlas-section" style="background: rgba(163, 113, 247, 0.08); border-color: rgba(163, 113, 247, 0.2);">
      <div class="framework-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="framework-title">
          <h3 style="margin: 0; font-size: 14px; color: #a371f7;">\ud83c\udfaf MITRE ATLAS Techniques</h3>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
            <a href="https://atlas.mitre.org" target="_blank" style="color: var(--accent-blue);" onclick="event.stopPropagation();">Adversarial Threat Landscape for AI Systems</a>
            - v4.0
          </div>
        </div>
        <div class="framework-stats">
          <span class="stat-badge covered">${atlasCovered} covered</span>
          <span class="stat-badge gap">0 gap</span>
          <span class="framework-expand">\u25bc</span>
        </div>
      </div>
      <div class="framework-content">
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 8px;">
          ${Object.entries(atlasBreakdown).map(([id, data]) => `
            <div style="padding: 10px 12px; background: rgba(46, 160, 67, 0.1); border-radius: 6px; border-left: 3px solid #3fb950;">
              <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                  <a href="https://atlas.mitre.org/techniques/${id}" target="_blank" style="font-weight: 600; color: #3fb950; text-decoration: none;">${id}</a>
                  <span style="margin-left: 6px; font-size: 12px;">${data.name}</span>
                </div>
                <span style="font-size: 12px;">\u2705</span>
              </div>
              <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Layers: ${data.layers.join(', ')}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  // OWASP LLM Top 10 2025 Section
  const owaspBreakdown: Record<string, { name: string; layers: string[]; severity: string }> = {};
  ATLAS_MAPPINGS_LOADED.forEach(mapping => {
    mapping.owaspIds.forEach((id, i) => {
      if (!owaspBreakdown[id]) {
        const owaspData = OWASP_LLM_2025[id as keyof typeof OWASP_LLM_2025];
        owaspBreakdown[id] = {
          name: mapping.owaspNames[i] || 'Unknown',
          layers: [],
          severity: owaspData?.severity || 'MEDIUM'
        };
      }
      owaspBreakdown[id].layers.push(`L${mapping.layer}`);
    });
  });
  const naOwaspIds = new Set(architecturalGaps.map(g => g.id));
  const owaspCoveredApplicable = Object.keys(owaspBreakdown).filter(id => !naOwaspIds.has(id)).length;
  const owaspGapCount = Math.max(0, 10 - architecturalGaps.length - owaspCoveredApplicable);

  const owaspSection = `
    <div class="framework-section" id="owasp-section" style="background: rgba(248, 81, 73, 0.06); border-color: rgba(248, 81, 73, 0.2);">
      <div class="framework-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="framework-title">
          <h3 style="margin: 0; font-size: 14px; color: #f85149;">\ud83d\udd12 OWASP LLM Top 10 2025</h3>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
            <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank" style="color: var(--accent-blue);" onclick="event.stopPropagation();">Security risks for LLM applications</a>
            - 2025
          </div>
        </div>
        <div class="framework-stats">
          <span class="stat-badge covered">${owaspCoveredApplicable} covered</span>
          <span class="stat-badge gap">${owaspGapCount} gap</span>
          <span class="stat-badge na">${architecturalGaps.length} N/A</span>
          <span class="framework-expand">\u25bc</span>
        </div>
      </div>
      <div class="framework-content">
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 8px;">
          ${Object.entries(owaspBreakdown).map(([id, data]) => {
            const isNA = naOwaspIds.has(id);
            const bgColor = isNA ? 'rgba(110, 118, 129, 0.1)' : 'rgba(46, 160, 67, 0.1)';
            const borderColor = isNA ? '#8b949e' : '#3fb950';
            const textColor = isNA ? '#8b949e' : '#3fb950';
            const icon = isNA ? 'N/A' : '\u2705';
            return `
              <div style="padding: 10px 12px; background: ${bgColor}; border-radius: 6px; border-left: 3px solid ${borderColor};">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                  <div>
                    <a href="https://genai.owasp.org/llmrisk/${id.toLowerCase()}/" target="_blank" style="font-weight: 600; color: ${textColor}; text-decoration: none;">${id}</a>
                    <span style="margin-left: 6px; font-size: 12px;">${data.name}</span>
                  </div>
                  <span style="font-size: 12px; ${isNA ? 'color: #8b949e;' : ''}">${icon}</span>
                </div>
                <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Layers: ${data.layers.join(', ')}</div>
              </div>
            `;
          }).join('')}
        </div>
        ${architecturalGaps.length > 0 ? `
          <div style="margin-top: 12px; padding: 10px; background: rgba(110, 118, 129, 0.1); border-radius: 6px; font-size: 11px; color: var(--text-muted);">
            <strong>Not Applicable:</strong> ${architecturalGaps.map(g => `${g.id} (${g.reason})`).join(', ')}
          </div>
        ` : ''}
      </div>
    </div>
  `;

  const getSourceBadge = (mapping: ATLASMapping): string => {
    if (mapping.source === 'external' && mapping.status === 'active') {
      return '<span class="source-badge external">EXTERNAL</span>';
    }
    if (mapping.source === 'external' && mapping.status === 'not_installed') {
      return '<span class="source-badge not-installed">NOT INSTALLED</span>';
    }
    if (mapping.source === 'builtin') {
      return '<span class="source-badge builtin">BUILT-IN</span>';
    }
    return ''; // plugin layers get no badge (they're the default)
  };

  const getSetupHint = (mapping: ATLASMapping): string => {
    if (mapping.status === 'not_installed' && mapping.setupHint) {
      return `
        <div class="atlas-section" style="margin-top: 8px;">
          <div style="padding: 8px 12px; background: rgba(210, 153, 34, 0.1); border-radius: 6px; border-left: 3px solid var(--accent-yellow);">
            <div style="font-size: 11px; color: var(--accent-yellow); font-weight: 600;">Setup Required</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${mapping.setupHint}</div>
          </div>
        </div>`;
    }
    return '';
  };

  const getStatusLabel = (status: string): string => {
    if (status === 'not_installed') return 'not installed';
    return status;
  };

  const layerCards = ATLAS_MAPPINGS_LOADED.map((mapping) => `
    <div class="atlas-card status-${mapping.status}">
      <div class="atlas-layer-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="atlas-layer-info">
          <div class="atlas-layer-number">${mapping.layer}</div>
          <div>
            <div class="atlas-layer-name">${mapping.layerName} ${getSourceBadge(mapping)}</div>
            <div class="atlas-layer-desc">${mapping.description}</div>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span class="atlas-status ${mapping.status}">${getStatusLabel(mapping.status)}</span>
          <span class="event-expand">\u25bc</span>
        </div>
      </div>
      <div class="atlas-details">
        ${getSetupHint(mapping)}
        ${mapping.atlasIds && mapping.atlasIds.length > 0 ? `
        <div class="atlas-section">
          <div class="atlas-section-title">MITRE ATLAS Techniques Mitigated</div>
          <div class="atlas-tags">
            ${mapping.atlasIds.map((id, i) => `
              <a href="https://atlas.mitre.org/techniques/${id}" target="_blank" class="atlas-tag atlas" title="${mapping.atlasNames[i] || id}">
                <span class="atlas-tag-id">${id}</span>
                <span>${mapping.atlasNames[i] || 'Unknown'}</span>
              </a>
            `).join('')}
          </div>
        </div>
        ` : ''}
        ${mapping.owaspIds && mapping.owaspIds.length > 0 ? `
        <div class="atlas-section">
          <div class="atlas-section-title">OWASP LLM Top 10 2025 Mitigated</div>
          <div class="atlas-tags">
            ${mapping.owaspIds.map((id, i) => `
              <a href="https://genai.owasp.org/llmrisk/${id.toLowerCase()}/" target="_blank" class="atlas-tag ${getOwaspSeverityClass(id)}" title="${mapping.owaspNames[i] || id}">
                <span class="atlas-tag-id">${id}</span>
                <span>${mapping.owaspNames[i] || 'Unknown'}</span>
              </a>
            `).join('')}
          </div>
        </div>
        ` : ''}
        ${mapping.owaspAgenticIds && mapping.owaspAgenticIds.length > 0 ? `
        <div class="atlas-section">
          <div class="atlas-section-title">OWASP Agentic 2026 Mitigated</div>
          <div class="atlas-tags">
            ${mapping.owaspAgenticIds.map((id, i) => `
              <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" class="atlas-tag agentic" title="${mapping.owaspAgenticNames[i] || id}">
                <span class="atlas-tag-id">${id}</span>
                <span>${mapping.owaspAgenticNames[i] || 'Unknown'}</span>
              </a>
            `).join('')}
          </div>
        </div>
        ` : ''}
      </div>
    </div>
  `).join('');

  return coverageSummary + agenticSection + atlasSection + owaspSection + layerCards;
}

// ============================================================================
// Main (Stop Hook Entry Point)
// ============================================================================

async function main() {
  try {
    console.error('TALON: Security Report Generator triggered...');

    // Detect runtime status of external security layers
    detectLayerStatus();
    // Calculate OWASP Agentic coverage based on active layers
    calculateAgenticCoverage();

    // Read stop hook input (Vex-Talon Stop hook format)
    let rawInput = '';
    try {
      rawInput = await Promise.race([
        Bun.stdin.text(),
        new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 500)),
      ]);
    } catch {
      // No input or timeout - proceed anyway for stop hook
    }

    let input: { session_id?: string; transcript_path?: string } = {};
    if (rawInput?.trim()) {
      try {
        input = JSON.parse(rawInput);
      } catch {
        // Invalid JSON - proceed with defaults
      }
    }

    const sessionId = input.session_id || `unknown-${Date.now()}`;
    const transcriptPath = input.transcript_path || '';

    // Ensure directories exist
    ensureDirectories();
    if (!existsSync(REPORTS_DIR)) {
      mkdirSync(REPORTS_DIR, { recursive: true, mode: 0o700 });
    }

    // Collect report data
    const reportData = collectReportData(sessionId, transcriptPath);

    // Skip report generation if no events to report
    const hasEvents =
      reportData.governorEvents.filter((e) => e.policy_matched && e.policy_matched !== 'none').length > 0 ||
      reportData.injectionScans.filter((e) => e.injection_detected).length > 0 ||
      reportData.secureCodeEvents.filter((e) => e.classification === 'SECURITY_SENSITIVE').length > 0 ||
      reportData.secureCodeLinterEvents.length > 0 ||
      reportData.leashEvents.filter((e) => e.decision === 'DENY').length > 0 ||
      reportData.memorySecurityEvents.filter((e) => e.findings && e.findings.length > 0).length > 0;

    if (!hasEvents && reportData.errors.length === 0) {
      console.error('TALON: No security events to report - skipping report generation');
      process.exit(0);
    }

    // Generate Vex-Talon Analysis (AI-powered executive summary)
    console.error('TALON: Generating Vex-Talon Analysis (via claude CLI)...');
    try {
      reportData.vexAnalysis = await generateVexAnalysis(reportData);
      console.error('TALON: Vex-Talon Analysis generated');
    } catch (analysisError) {
      console.error(`TALON: Vex-Talon Analysis unavailable: ${analysisError}`);
      reportData.vexAnalysis = undefined;
    }

    // Generate HTML
    const html = generateHTML(reportData);

    // Generate filename with timestamp
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
    const filename = `security-report-${timestamp}.html`;
    const filepath = join(REPORTS_DIR, filename);

    // Write report
    writeFileSync(filepath, html, { mode: 0o600 });

    console.error(`\nTALON Security Report generated: ${filepath}`);
    console.error(`   Status: ${reportData.summary.overallStatus}`);
    console.error(`   Policy Violations: ${reportData.summary.policyViolations}`);
    console.error(`   Injection Detections: ${reportData.summary.injectionDetections}`);
    console.error(`   Memory Poisoning: ${reportData.summary.memoryPoisoningAttempts}`);

    // Auto-open report in browser
    openReportInBrowser(filepath);

    process.exit(0);
  } catch (error) {
    console.error(`[stop-security-report] Error: ${error}`);
    process.exit(0); // Don't fail the session
  }
}

main();
