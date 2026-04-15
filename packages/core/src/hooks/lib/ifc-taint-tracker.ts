/**
 * IFC Taint Tracker for 0K-Talon Governor (L1)
 *
 * Bell-LaPadula model: "No write-down"
 * When agent reads sensitive data, session becomes tainted.
 * Taint level only escalates (never decreases) within a session.
 * Tainted sessions face stricter egress and trajectory restrictions via Cedar.
 *
 * Phase 2 of Cedar Security Evolution (IFC taint-aware policies)
 * Phase 3: Trajectory counters per tool category for step-count limits
 *
 * Maps to:
 * - OWASP LLM02 (Sensitive Information Disclosure)
 * - MITRE ATLAS AML.T0024 (Exfiltration via Cyber Means)
 *
 * @version 0.1.0 (0k-talon)
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { TALON_DIR, STATE_DIR } from './talon-paths';

const STATE_FILE = join(STATE_DIR, 'session-taint.json');

// Labels config: user-configured path first, bundled fallback second
const USER_LABELS_FILE = join(TALON_DIR, 'security', 'cedar', 'sensitivity-labels.json');
const BUNDLED_LABELS_FILE = join(import.meta.dir, '..', '..', '..', 'security', 'cedar', 'sensitivity-labels.json');

// Cache for labels (loaded once per session)
let labelsCache: SensitivityLabel[] | null = null;

// ============================================================================
// Types
// ============================================================================

export interface TaintState {
  session_id: string;
  tainted: boolean;
  taint_level: number;         // 0-3, highest sensitivity touched
  taint_source: string | null; // Path that caused initial taint
  taint_timestamp: string | null;
  sensitive_reads: SensitiveRead[];
  tool_call_count: number;
  // Phase 3: Trajectory counters by category
  trajectory: {
    file_reads: number;
    file_writes: number;
    shell_commands: number;
    web_fetches: number;
    web_searches: number;
    mcp_calls: number;
    skill_invokes: number;
    consecutive_same_tool: number;
    last_tool: string;
  };
}

interface SensitiveRead {
  path: string;
  level: number;
  label: string;
  timestamp: string;
}

interface SensitivityLabel {
  pattern: string;
  level: number;
  label: string;
  note?: string;
}

// ============================================================================
// Label Loading
// ============================================================================

/**
 * Load sensitivity labels from config.
 * Prefers user-configured labels in TALON_DIR; falls back to bundled defaults.
 */
function loadLabels(): SensitivityLabel[] {
  if (labelsCache) return labelsCache;
  try {
    const labelsFile = existsSync(USER_LABELS_FILE) ? USER_LABELS_FILE
                     : existsSync(BUNDLED_LABELS_FILE) ? BUNDLED_LABELS_FILE
                     : null;
    if (!labelsFile) return [];
    const config = JSON.parse(readFileSync(labelsFile, 'utf-8'));
    labelsCache = config.path_rules || [];
    return labelsCache!;
  } catch {
    return [];
  }
}

// ============================================================================
// Path Sensitivity
// ============================================================================

/**
 * Get the sensitivity level for a file path.
 * Scans all loaded path_rules and returns the highest matching level.
 */
export function getPathSensitivity(filePath: string): { level: number; label: string } {
  const labels = loadLabels();
  let maxLevel = 0;
  let maxLabel = 'PUBLIC';

  for (const rule of labels) {
    if (filePath.includes(rule.pattern)) {
      if (rule.level > maxLevel) {
        maxLevel = rule.level;
        maxLabel = rule.label;
      }
    }
  }

  return { level: maxLevel, label: maxLabel };
}

// ============================================================================
// Taint State Management
// ============================================================================

/**
 * Load current taint state from disk, or create a fresh state.
 * State is only reused if the session_id matches (new session = fresh state).
 */
export function loadTaintState(sessionId: string): TaintState {
  try {
    if (existsSync(STATE_FILE)) {
      const state = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as TaintState;
      // Only reuse state for same session
      if (state.session_id === sessionId) {
        return state;
      }
    }
  } catch { /* fresh state on parse error */ }

  return {
    session_id: sessionId,
    tainted: false,
    taint_level: 0,
    taint_source: null,
    taint_timestamp: null,
    sensitive_reads: [],
    tool_call_count: 0,
    trajectory: freshTrajectory(),
  };
}

/**
 * Save taint state to disk. Best-effort — does not throw on failure.
 */
function saveTaintState(state: TaintState): void {
  try {
    if (!existsSync(STATE_DIR)) mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error(`[IFC] Failed to save taint state: ${e}`);
  }
}

// ============================================================================
// Taint Operations
// ============================================================================

/**
 * Record a file read and escalate taint if the path matches a sensitivity label.
 * Bell-LaPadula: taint level only increases, never decreases.
 * Returns the updated taint state.
 */
export function recordFileRead(sessionId: string, filePath: string): TaintState {
  const state = loadTaintState(sessionId);
  state.tool_call_count++;

  if (!state.trajectory) state.trajectory = freshTrajectory();
  state.trajectory.file_reads++;
  updateConsecutive(state, 'Read');

  const { level, label } = getPathSensitivity(filePath);

  // Only taint and record if sensitivity > PUBLIC
  if (level > 0) {
    // Taint only escalates — Bell-LaPadula "No write-down"
    if (level > state.taint_level) {
      state.tainted = true;
      state.taint_level = level;
      state.taint_source = filePath;
      state.taint_timestamp = new Date().toISOString();
    }

    // Keep history of sensitive reads (cap at 100 to prevent bloat)
    if (state.sensitive_reads.length < 100) {
      state.sensitive_reads.push({
        path: filePath,
        level,
        label,
        timestamp: new Date().toISOString(),
      });
    }
  }

  saveTaintState(state);
  return state;
}

/**
 * Record a generic tool call with trajectory tracking.
 * Call this for all non-Read tool invocations to maintain accurate counters.
 */
export function recordToolCall(sessionId: string, toolName?: string, params?: Record<string, any>): TaintState {
  const state = loadTaintState(sessionId);
  state.tool_call_count++;

  if (!state.trajectory) state.trajectory = freshTrajectory();

  if (toolName) {
    updateConsecutive(state, toolName);
    switch (toolName) {
      case 'Write':
      case 'Edit':
        state.trajectory.file_writes++;
        break;
      case 'Bash': {
        state.trajectory.shell_commands++;
        // Command-based taint escalation (AML.T0091 Lateral Movement prevention)
        // Accessing credential managers escalates taint to SECRET
        if (params?.command) {
          const cmd = params.command;
          if (isCredentialCommand(cmd)) {
            escalateTaint(state, 3, `command:${cmd.substring(0, 60)}`);
          }
        }
        break;
      }
      case 'WebFetch':
        state.trajectory.web_fetches++;
        break;
      case 'WebSearch':
        state.trajectory.web_searches++;
        break;
      case 'Skill':
        state.trajectory.skill_invokes++;
        break;
      default:
        if (toolName.startsWith('mcp__')) state.trajectory.mcp_calls++;
    }
  }

  saveTaintState(state);
  return state;
}

/**
 * Detect commands that access credential stores or secret managers.
 * These escalate session taint to SECRET (level 3).
 */
function isCredentialCommand(command: string): boolean {
  const patterns = [
    /\bop\s+(read|run|get|item\s+get)\b/,       // 1Password CLI
    /\bsecretless-ai\s+env\b/,                   // Secretless AI
    /\baws\s+secretsmanager\b/,                   // AWS Secrets Manager
    /\bvault\s+(read|kv\s+get)\b/,               // HashiCorp Vault
    /\bgcloud\s+secrets\s+versions\s+access\b/,  // GCP Secret Manager
    /\baz\s+keyvault\s+secret\s+show\b/,         // Azure Key Vault
    /\bkubectl\s+get\s+secret\b/,                // K8s secrets
  ];
  return patterns.some(p => p.test(command));
}

/**
 * Escalate taint level (Bell-LaPadula: only goes up, never down).
 */
function escalateTaint(state: TaintState, level: number, source: string): void {
  if (level > state.taint_level) {
    state.tainted = true;
    state.taint_level = level;
    state.taint_source = source;
    state.taint_timestamp = new Date().toISOString();
  }
}

// ============================================================================
// Helpers
// ============================================================================

function freshTrajectory(): TaintState['trajectory'] {
  return {
    file_reads: 0,
    file_writes: 0,
    shell_commands: 0,
    web_fetches: 0,
    web_searches: 0,
    mcp_calls: 0,
    skill_invokes: 0,
    consecutive_same_tool: 0,
    last_tool: '',
  };
}

function updateConsecutive(state: TaintState, toolName: string): void {
  if (state.trajectory.last_tool === toolName) {
    state.trajectory.consecutive_same_tool++;
  } else {
    state.trajectory.consecutive_same_tool = 1;
    state.trajectory.last_tool = toolName;
  }
}

/**
 * Get the human-readable label for a taint level.
 */
export function getTaintLabel(level: number): string {
  switch (level) {
    case 0: return 'PUBLIC';
    case 1: return 'INTERNAL';
    case 2: return 'CONFIDENTIAL';
    case 3: return 'SECRET';
    default: return 'UNKNOWN';
  }
}
