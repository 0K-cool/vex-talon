#!/usr/bin/env bun

/**
 * L3: Memory Validation - PreToolUse Hook
 *
 * Part of Vex-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Validate MCP Memory Server operations for injection attempts.
 * Pattern: Sidecar Pattern (monitoring before tool execution)
 *
 * Detects:
 * - Instruction injection in entity names/observations
 * - Fake facts injection
 * - Encoded/obfuscated content
 * - Context manipulation attempts
 *
 * Maps to:
 * - OWASP Agentic 2026 ASI06 (Memory and Context Manipulation)
 * - MITRE ATLAS AML.T0064 (Data Poisoning)
 *
 * @version 0.1.0 (vex-talon)
 * @date 2026-02-04
 */

import { appendFileSync } from 'fs';
import { ensureTalonDirs, getAuditLogPath } from './lib/talon-paths';

const HOOK_NAME = 'L3-memory-validation';

interface HookInput {
  session_id: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
}

interface Finding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  detail: string;
}

// MCP Memory tools to monitor
const MEMORY_TOOLS = [
  'mcp__memory__create_entities',
  'mcp__memory__create_relations',
  'mcp__memory__add_observations',
];

// Limits
const MAX_ENTITY_NAME = 100;
const MAX_OBSERVATION = 2000;
const MAX_ENTITIES_BATCH = 20;
const MAX_OBSERVATIONS_BATCH = 50;

// Injection patterns (strings to avoid regex false positives)
const INJECTION_KEYWORDS = [
  'ignore previous',
  'disregard all',
  'new instructions',
  'system prompt',
  'you are now',
  'forget everything',
  'override',
  'jailbreak',
];

const FAKE_FACT_PATTERNS = [
  'kelvin said',
  'kelvin wants',
  'kelvin prefers',
  'user confirmed',
  'user approved',
  'authorized to',
  'permission granted',
];

function normalizeText(text: string): string {
  // Basic homoglyph normalization
  return text.normalize('NFKC').toLowerCase();
}

function checkInjection(text: string): Finding | null {
  const normalized = normalizeText(text);

  for (const keyword of INJECTION_KEYWORDS) {
    if (normalized.includes(keyword)) {
      return {
        type: 'INJECTION',
        severity: 'CRITICAL',
        detail: `Injection pattern detected: "${keyword}"`,
      };
    }
  }
  return null;
}

function checkFakeFact(text: string): Finding | null {
  const normalized = normalizeText(text);

  for (const pattern of FAKE_FACT_PATTERNS) {
    if (normalized.includes(pattern)) {
      return {
        type: 'FAKE_FACT',
        severity: 'HIGH',
        detail: `Fake fact pattern: "${pattern}"`,
      };
    }
  }
  return null;
}

function checkEncoding(text: string): Finding | null {
  // Check for base64-like content
  if (/^[A-Za-z0-9+/=]{50,}$/.test(text.trim())) {
    return {
      type: 'ENCODED',
      severity: 'HIGH',
      detail: 'Suspicious encoded content detected',
    };
  }
  return null;
}

function checkLimits(toolName: string, input: Record<string, any>): Finding[] {
  const findings: Finding[] = [];

  if (toolName.includes('create_entities')) {
    const entities = input.entities || [];
    if (entities.length > MAX_ENTITIES_BATCH) {
      findings.push({
        type: 'LIMIT_EXCEEDED',
        severity: 'MEDIUM',
        detail: `Too many entities: ${entities.length} > ${MAX_ENTITIES_BATCH}`,
      });
    }
    for (const entity of entities) {
      if (entity.name?.length > MAX_ENTITY_NAME) {
        findings.push({
          type: 'LIMIT_EXCEEDED',
          severity: 'MEDIUM',
          detail: `Entity name too long: ${entity.name.length} chars`,
        });
      }
    }
  }

  if (toolName.includes('add_observations')) {
    const observations = input.observations || [];
    if (observations.length > MAX_OBSERVATIONS_BATCH) {
      findings.push({
        type: 'LIMIT_EXCEEDED',
        severity: 'MEDIUM',
        detail: `Too many observations: ${observations.length} > ${MAX_OBSERVATIONS_BATCH}`,
      });
    }
    for (const obs of observations) {
      for (const content of obs.contents || []) {
        if (content.length > MAX_OBSERVATION) {
          findings.push({
            type: 'LIMIT_EXCEEDED',
            severity: 'MEDIUM',
            detail: `Observation too long: ${content.length} chars`,
          });
        }
      }
    }
  }

  return findings;
}

function scanMemoryInput(toolName: string, input: Record<string, any>): Finding[] {
  const findings: Finding[] = [];

  // Extract all text content to scan
  const textsToScan: string[] = [];

  if (toolName.includes('create_entities')) {
    for (const entity of input.entities || []) {
      if (entity.name) textsToScan.push(entity.name);
      if (entity.entityType) textsToScan.push(entity.entityType);
      for (const obs of entity.observations || []) {
        textsToScan.push(obs);
      }
    }
  }

  if (toolName.includes('create_relations')) {
    for (const rel of input.relations || []) {
      if (rel.from) textsToScan.push(rel.from);
      if (rel.to) textsToScan.push(rel.to);
      if (rel.relationType) textsToScan.push(rel.relationType);
    }
  }

  if (toolName.includes('add_observations')) {
    for (const obs of input.observations || []) {
      if (obs.entityName) textsToScan.push(obs.entityName);
      for (const content of obs.contents || []) {
        textsToScan.push(content);
      }
    }
  }

  // Scan all text
  for (const text of textsToScan) {
    const injection = checkInjection(text);
    if (injection) findings.push(injection);

    const fakeFact = checkFakeFact(text);
    if (fakeFact) findings.push(fakeFact);

    const encoding = checkEncoding(text);
    if (encoding) findings.push(encoding);
  }

  // Check limits
  findings.push(...checkLimits(toolName, input));

  return findings;
}

function logToAudit(entry: any): void {
  try {
    ensureTalonDirs();
    appendFileSync(getAuditLogPath(HOOK_NAME), JSON.stringify(entry) + '\n');
  } catch {}
}

function outputAlert(findings: Finding[], toolName: string): void {
  const critical = findings.filter(f => f.severity === 'CRITICAL');

  console.error('\n🚨 TALON L3: MEMORY POISONING ATTEMPT DETECTED');
  console.error(`   Tool: ${toolName}`);
  for (const f of findings.slice(0, 5)) {
    const emoji = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
    console.error(`   ${emoji} ${f.type}: ${f.detail}`);
  }
  console.error('   ⚠️  Memory operation flagged for review\n');

  // Output alert context for Claude
  if (critical.length > 0) {
    console.log(JSON.stringify({
      decision: 'block',
      reason: `TALON L3: Memory poisoning detected - ${critical.map(f => f.detail).join('; ')}`,
    }));
  }
}

async function main() {
  try {
    const input = await Promise.race([
      Bun.stdin.text(),
      new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 300)),
    ]);
    if (!input?.trim()) process.exit(0);

    const data: HookInput = JSON.parse(input);

    // Only scan memory tools
    if (!data.tool_name || !MEMORY_TOOLS.some(t => data.tool_name?.includes(t))) {
      process.exit(0);
    }

    const toolInput = data.tool_input || {};
    const findings = scanMemoryInput(data.tool_name, toolInput);

    if (findings.length === 0) {
      process.exit(0);
    }

    // Log to audit
    logToAudit({
      timestamp: new Date().toISOString(),
      session_id: data.session_id,
      tool: data.tool_name,
      findings,
      severity: findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' :
                findings.some(f => f.severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
    });

    // Output alert
    outputAlert(findings, data.tool_name);

    // Note: Cannot actually block MCP tools due to Claude Code bug #13744
    // Alert provides context for behavioral defense
    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
