/**
 * @vex-talon/db - Log Ingestion
 *
 * Ingest security events from JSONL audit logs into the database.
 */

import { existsSync, readFileSync, statSync, watchFile, unwatchFile } from 'fs';
import { join } from 'path';
import { insertEvent, updateLayerStats, upsertSession, type SecurityEvent } from './queries';

// ============================================================================
// Types
// ============================================================================

interface AuditLogEntry {
  timestamp: string;
  session_id?: string;
  tool?: string;
  tool_name?: string;
  file_path?: string;
  classification?: string;
  risk_level?: string;
  severity?: string;
  action?: string;
  blocked?: boolean;
  block_reason?: string;
  triggers?: string[];
  patterns_matched?: string[];
  pattern_id?: string;
  description?: string;
  matched_text?: string;
  [key: string]: unknown;
}

interface IngestResult {
  processed: number;
  inserted: number;
  errors: number;
}

// ============================================================================
// Log File Mapping
// ============================================================================

/**
 * Map log file names to security layers
 */
const LOG_TO_LAYER: Record<string, string> = {
  'secure-code-enforcer': 'L0',
  'secure-code-enforcer-audit.jsonl': 'L0',
  'governor-audit.jsonl': 'L1',
  'secure-code-linter-audit.jsonl': 'L2',
  'memory-validation-audit.jsonl': 'L3',
  'injection-scanner': 'L4',
  'injection-scanner-audit.jsonl': 'L4',
  'output-sanitizer-audit.jsonl': 'L5',
  'image-safety-audit.jsonl': 'L7',
  'egress-scanner-audit.jsonl': 'L9',
  'supply-chain-audit.jsonl': 'L14',
  'skill-scanner-audit.jsonl': 'L19',
};

/**
 * Map log file to hook type
 */
const LOG_TO_HOOK_TYPE: Record<string, string> = {
  'secure-code-enforcer': 'PreToolUse',
  'governor-audit.jsonl': 'PreToolUse',
  'injection-scanner': 'PostToolUse',
  'secure-code-linter-audit.jsonl': 'PostToolUse',
  'output-sanitizer-audit.jsonl': 'PostToolUse',
  'image-safety-audit.jsonl': 'PostToolUse',
  'egress-scanner-audit.jsonl': 'PreToolUse',
  'supply-chain-audit.jsonl': 'PostToolUse',
  'memory-validation-audit.jsonl': 'Pre+PostToolUse',
  'skill-scanner-audit.jsonl': 'PreToolUse',
};

// ============================================================================
// Ingestion Functions
// ============================================================================

/**
 * Parse a single audit log entry into a SecurityEvent
 */
function parseLogEntry(entry: AuditLogEntry, logName: string): SecurityEvent | null {
  try {
    const layer = LOG_TO_LAYER[logName] || 'Unknown';
    const hookType = LOG_TO_HOOK_TYPE[logName] || 'Unknown';

    // Determine severity
    let severity: SecurityEvent['severity'] = 'LOW';
    if (entry.risk_level) {
      severity = entry.risk_level.toUpperCase() as SecurityEvent['severity'];
    } else if (entry.severity) {
      severity = entry.severity.toUpperCase() as SecurityEvent['severity'];
    }

    // Determine action
    let action: SecurityEvent['action'] = 'log';
    if (entry.blocked === true || entry.action === 'block') {
      action = 'block';
    } else if (severity === 'CRITICAL') {
      action = 'alert';
    } else if (severity === 'HIGH' || entry.action === 'warn') {
      action = 'warn';
    }

    // Extract pattern info
    const patternId = entry.pattern_id ||
      (entry.patterns_matched && entry.patterns_matched[0]) ||
      (entry.triggers && entry.triggers[0]) ||
      null;

    return {
      timestamp: entry.timestamp || new Date().toISOString(),
      session_id: entry.session_id || 'unknown',
      layer,
      hook_type: hookType,
      tool_name: entry.tool || entry.tool_name || undefined,
      severity,
      action,
      pattern_id: patternId || undefined,
      description: entry.description || entry.block_reason || undefined,
      file_path: entry.file_path || undefined,
      matched_text: entry.matched_text || undefined,
      metadata: JSON.stringify(entry),
    };
  } catch {
    return null;
  }
}

/**
 * Ingest a JSONL log file
 */
export function ingestLogFile(filePath: string): IngestResult {
  const result: IngestResult = { processed: 0, inserted: 0, errors: 0 };

  if (!existsSync(filePath)) {
    console.error(`[Ingest] File not found: ${filePath}`);
    return result;
  }

  const logName = filePath.split('/').pop() || '';
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.trim().split('\n').filter(line => line.trim());

  for (const line of lines) {
    result.processed++;
    try {
      const entry = JSON.parse(line) as AuditLogEntry;
      const event = parseLogEntry(entry, logName);

      if (event) {
        insertEvent(event);
        result.inserted++;

        // Update layer stats
        const layer = LOG_TO_LAYER[logName];
        if (layer) {
          updateLayerStats(
            layer,
            1, // invocation
            event.action === 'block' ? 1 : 0,
            event.action === 'warn' || event.action === 'alert' ? 1 : 0
          );
        }
      }
    } catch {
      result.errors++;
    }
  }

  return result;
}

/**
 * Ingest all log files from a directory
 */
export function ingestLogsDirectory(logsDir: string): IngestResult {
  const totalResult: IngestResult = { processed: 0, inserted: 0, errors: 0 };

  if (!existsSync(logsDir)) {
    console.error(`[Ingest] Directory not found: ${logsDir}`);
    return totalResult;
  }

  const { readdirSync } = require('fs');
  const files = readdirSync(logsDir) as string[];

  for (const file of files) {
    if (file.endsWith('.jsonl')) {
      const result = ingestLogFile(join(logsDir, file));
      totalResult.processed += result.processed;
      totalResult.inserted += result.inserted;
      totalResult.errors += result.errors;
    }
  }

  return totalResult;
}

// ============================================================================
// File Watching
// ============================================================================

const watchedFiles = new Set<string>();

/**
 * Watch a log file for changes and ingest new entries
 */
export function watchLogFile(filePath: string, onIngest?: (result: IngestResult) => void): void {
  if (watchedFiles.has(filePath)) return;

  let lastSize = 0;
  if (existsSync(filePath)) {
    lastSize = statSync(filePath).size;
  }

  watchFile(filePath, { interval: 1000 }, (curr, prev) => {
    if (curr.size > lastSize) {
      const result = ingestLogFile(filePath);
      lastSize = curr.size;
      if (onIngest) onIngest(result);
    }
  });

  watchedFiles.add(filePath);
}

/**
 * Stop watching a log file
 */
export function unwatchLogFile(filePath: string): void {
  if (watchedFiles.has(filePath)) {
    unwatchFile(filePath);
    watchedFiles.delete(filePath);
  }
}

/**
 * Stop watching all log files
 */
export function unwatchAllLogFiles(): void {
  for (const filePath of watchedFiles) {
    unwatchFile(filePath);
  }
  watchedFiles.clear();
}

// ============================================================================
// Session Management
// ============================================================================

/**
 * Start tracking a new session
 */
export function startSession(sessionId: string): void {
  upsertSession({
    id: sessionId,
    started_at: new Date().toISOString(),
    total_events: 0,
    total_blocks: 0,
    total_warnings: 0,
  });
}

/**
 * End a session and calculate final stats
 */
export function endSession(sessionId: string): void {
  const { getEventsBySession } = require('./queries');
  const events = getEventsBySession(sessionId) as SecurityEvent[];

  const stats = events.reduce(
    (acc, e) => {
      acc.total++;
      if (e.action === 'block') acc.blocks++;
      if (e.action === 'warn' || e.action === 'alert') acc.warnings++;
      return acc;
    },
    { total: 0, blocks: 0, warnings: 0 }
  );

  upsertSession({
    id: sessionId,
    started_at: events[events.length - 1]?.timestamp || new Date().toISOString(),
    ended_at: new Date().toISOString(),
    total_events: stats.total,
    total_blocks: stats.blocks,
    total_warnings: stats.warnings,
  });
}
