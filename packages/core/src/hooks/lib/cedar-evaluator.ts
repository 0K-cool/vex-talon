/**
 * Cedar Policy Evaluator for Vex-Talon Governor (L1)
 *
 * Evaluates tool calls against Cedar policies using @cedar-policy/cedar-wasm.
 * Hybrid model: Cedar evaluates alongside YAML — Cedar forbid overrides YAML allow.
 *
 * Phase 1: Foundation (5 pilot policies)
 * Phase 2: IFC taint-aware policies
 * Phase 3: Trajectory-aware policies
 *
 * Maps to:
 * - OWASP LLM01 (Prompt Injection)
 * - OWASP LLM02 (Sensitive Information Disclosure)
 * - MITRE ATLAS AML.T0054 (LLM Jailbreak)
 *
 * @version 0.1.0 (vex-talon)
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join } from 'path';
import { TALON_DIR } from './talon-paths';

// Cedar WASM — lazy loaded via require (ESM path has WASM compatibility issues with Bun)
let cedarWasm: any = null;

// Cedar security config lives alongside the plugin source
const CEDAR_DIR = join(TALON_DIR, 'security', 'cedar');
const SCHEMA_FILE = join(CEDAR_DIR, 'talon.cedarschema');
const POLICIES_DIR = join(CEDAR_DIR, 'policies');

// Fallback to bundled source-tree cedar dir when TALON_DIR has no cedar config
const BUNDLED_CEDAR_DIR = join(import.meta.dir, '..', '..', '..', 'security', 'cedar');
const BUNDLED_SCHEMA_FILE = join(BUNDLED_CEDAR_DIR, 'talon.cedarschema');
const BUNDLED_POLICIES_DIR = join(BUNDLED_CEDAR_DIR, 'policies');

// Cache for loaded policies and schema (60s TTL)
let policyCache: { policies: string; loadedAt: number } | null = null;
let schemaCache: { schema: string; loadedAt: number } | null = null;
const CACHE_TTL_MS = 60_000;

export interface CedarEvaluationResult {
  decision: 'ALLOW' | 'DENY';
  matchedPolicies: string[];
  errors: string[];
  evaluationTimeMs: number;
}

export interface TrajectoryContext {
  toolCallCount: number;
  webFetchCount: number;
  shellCommandCount: number;
  consecutiveSameTool: number;
}

/**
 * Lazily load cedar-wasm module via Node.js CJS path.
 * Bun's require resolution finds the package in packages/core/node_modules.
 * import.meta.dir resolves to the hooks/lib directory at runtime.
 */
function loadCedar() {
  if (!cedarWasm) {
    try {
      // Absolute path from hooks/lib up to packages/core/node_modules
      const cedarPath = join(
        import.meta.dir,
        '..', '..', '..', // hooks/lib -> hooks -> src -> packages/core
        'node_modules',
        '@cedar-policy', 'cedar-wasm', 'nodejs', 'cedar_wasm.js'
      );
      cedarWasm = require(cedarPath);
    } catch (e) {
      throw new Error(`Failed to load cedar-wasm: ${e}`);
    }
  }
  return cedarWasm;
}

/**
 * Load all Cedar policy files from the policies directory.
 * Falls back to bundled source-tree policies if TALON_DIR has none.
 */
function loadCedarPolicies(): string {
  const now = Date.now();
  if (policyCache && (now - policyCache.loadedAt) < CACHE_TTL_MS) {
    return policyCache.policies;
  }

  // Prefer user-configured policies; fall back to bundled
  const dir = existsSync(POLICIES_DIR) ? POLICIES_DIR
             : existsSync(BUNDLED_POLICIES_DIR) ? BUNDLED_POLICIES_DIR
             : null;

  if (!dir) return '';

  const policyFiles = readdirSync(dir).filter(f => f.endsWith('.cedar')).sort();
  const allPolicies = policyFiles
    .map(f => readFileSync(join(dir, f), 'utf-8'))
    .join('\n\n');

  policyCache = { policies: allPolicies, loadedAt: now };
  return allPolicies;
}

/**
 * Load the Talon Cedar schema.
 * Falls back to bundled schema if TALON_DIR has none.
 */
function loadCedarSchema(): string {
  const now = Date.now();
  if (schemaCache && (now - schemaCache.loadedAt) < CACHE_TTL_MS) {
    return schemaCache.schema;
  }

  const schemaFile = existsSync(SCHEMA_FILE) ? SCHEMA_FILE
                   : existsSync(BUNDLED_SCHEMA_FILE) ? BUNDLED_SCHEMA_FILE
                   : null;

  if (!schemaFile) return '';

  const schema = readFileSync(schemaFile, 'utf-8');
  schemaCache = { schema, loadedAt: now };
  return schema;
}

/**
 * Map a tool call to Cedar action and build the authorization request.
 * Returns null for tools that have no Cedar policy coverage (passthrough).
 */
function mapToolCallToCedarAction(
  toolName: string,
  params: Record<string, any>,
  sessionProfile: string = 'dev',
  sessionTaintLevel: number = 0,
  trajectory?: TrajectoryContext
): { action: string; resourceType: string; context: Record<string, any> } | null {

  const filePath = params.file_path || params.filePath || '';
  const command = params.command || '';
  const traj = trajectory || {
    toolCallCount: 0,
    webFetchCount: 0,
    shellCommandCount: 0,
    consecutiveSameTool: 0,
  };

  const baseContext = {
    sessionProfile,
    sessionTaintLevel,
    toolCallCount: traj.toolCallCount,
    webFetchCount: traj.webFetchCount,
    shellCommandCount: traj.shellCommandCount,
    consecutiveSameTool: traj.consecutiveSameTool,
  };

  switch (toolName) {
    case 'Read':
      return {
        action: 'Talon::Action::"read_file"',
        resourceType: 'Talon::File',
        context: { toolName, filePath, ...baseContext },
      };

    case 'Write':
    case 'Edit':
      return {
        action: 'Talon::Action::"write_file"',
        resourceType: 'Talon::File',
        context: { toolName, filePath, ...baseContext },
      };

    case 'Bash': {
      const isGit = command.startsWith('git ') || command.includes(' git ');
      if (isGit) {
        const branch = extractBranch(command);
        return {
          action: 'Talon::Action::"git_operation"',
          resourceType: 'Talon::Tool',
          context: { toolName, command, branch, ...baseContext },
        };
      }
      return {
        action: 'Talon::Action::"execute_command"',
        resourceType: 'Talon::Tool',
        context: { toolName, command, ...baseContext },
      };
    }

    case 'WebFetch':
    case 'WebSearch':
      return {
        action: 'Talon::Action::"network_request"',
        resourceType: 'Talon::Tool',
        context: { toolName, url: params.url || '', ...baseContext },
      };

    default:
      return null;
  }
}

/**
 * Extract branch name from a git command string.
 */
function extractBranch(command: string): string {
  const match = command.match(/(?:push|pull|checkout|merge|rebase)\s+(?:origin\s+)?(\S+)/);
  return match?.[1] || 'unknown';
}

/**
 * Determine file sensitivity from path.
 * Only includes generic universal patterns — no installation-specific paths.
 */
function getFileSensitivity(filePath: string): number {
  if (filePath.includes('.env') || filePath.includes('.ssh') || filePath.includes('credentials')) return 3; // SECRET
  if (filePath.includes('security') || filePath.includes('policies')) return 2; // CONFIDENTIAL
  if (filePath.includes('.vex-talon') || filePath.includes('hooks')) return 1; // INTERNAL
  return 0; // PUBLIC
}

/**
 * Evaluate a tool call against Cedar policies.
 *
 * Returns ALLOW if:
 * - Cedar WASM not available (graceful degradation)
 * - No Cedar policies or schema loaded
 * - Tool not mapped to a Cedar action
 * - Cedar permits the action
 *
 * Returns DENY if:
 * - Any Cedar forbid policy matches
 */
export function evaluateCedarPolicies(
  toolName: string,
  params: Record<string, any>,
  sessionProfile: string = 'dev',
  sessionTaintLevel: number = 0,
  trajectory?: TrajectoryContext
): CedarEvaluationResult {
  const startTime = Date.now();

  // Map tool call to Cedar action
  const mapping = mapToolCallToCedarAction(toolName, params, sessionProfile, sessionTaintLevel, trajectory);
  if (!mapping) {
    return {
      decision: 'ALLOW',
      matchedPolicies: [],
      errors: [],
      evaluationTimeMs: Date.now() - startTime,
    };
  }

  // Load policies and schema
  const policiesText = loadCedarPolicies();
  const schemaText = loadCedarSchema();
  if (!policiesText || !schemaText) {
    return {
      decision: 'ALLOW',
      matchedPolicies: [],
      errors: ['No Cedar policies or schema found — Cedar disabled'],
      evaluationTimeMs: Date.now() - startTime,
    };
  }

  try {
    const cedar = loadCedar();

    const filePath = params.file_path || params.filePath || '';
    const sensitivity = getFileSensitivity(filePath);
    const actionId = mapping.action.replace('Talon::Action::', '').replace(/"/g, '');
    const resourceId = filePath || toolName;

    // Cedar is deny-by-default. Add a default permit so forbid policies can override.
    const policiesWithDefault = `
@id("default-allow")
permit (
    principal is Talon::Agent,
    action,
    resource
);

${policiesText}`;

    const authCall = {
      principal: { type: 'Talon::Agent', id: 'agent' },
      action: { type: 'Talon::Action', id: actionId },
      resource: { type: mapping.resourceType, id: resourceId },
      context: mapping.context,
      schema: schemaText,
      validateRequest: false, // Skip validation for performance (policies are pre-validated)
      policies: { staticPolicies: policiesWithDefault },
      entities: [
        {
          uid: { type: 'Talon::Agent', id: 'agent' },
          attrs: { profile: sessionProfile, sessionId: 'current' },
          parents: [],
        },
        {
          uid: { type: mapping.resourceType, id: resourceId },
          attrs: mapping.resourceType === 'Talon::File'
            ? { path: filePath, sensitivity }
            : { name: toolName },
          parents: [],
        },
      ],
    };

    const response = cedar.isAuthorized(authCall);

    const matchedPolicies = (response.response?.diagnostics?.reason || [])
      .filter((p: string) => p !== 'policy0'); // Filter out default-allow from reporting
    const errors = (response.response?.diagnostics?.errors || []).map(
      (e: any) => e.error?.message || String(e)
    );

    const decision = response.response?.decision;
    return {
      decision: decision === 'deny' ? 'DENY' : 'ALLOW',
      matchedPolicies: matchedPolicies.map(String),
      errors,
      evaluationTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    // Graceful degradation — if Cedar fails, fall back to YAML-only governor
    return {
      decision: 'ALLOW',
      matchedPolicies: [],
      errors: [`Cedar evaluation error: ${error}`],
      evaluationTimeMs: Date.now() - startTime,
    };
  }
}
