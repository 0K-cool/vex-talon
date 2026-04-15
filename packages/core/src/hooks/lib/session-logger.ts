/**
 * Session Logger - Shared logging for SessionStart hooks
 *
 * Redirects informational messages from stderr to a log file so that
 * Claude Code doesn't show "hook error" for normal status output.
 *
 * Usage in hooks:
 *   import { logInfo, logWarn } from './lib/session-logger';
 *   logInfo('SkillScanner', 'All 41 skills cached');
 *
 * @version 1.0.0 (0k-talon)
 * @date 2026-02-27
 */

import { appendFileSync, existsSync, statSync, writeFileSync } from 'fs';
import { join } from 'path';
import { LOGS_DIR, ensureDirectories } from './talon-paths';

const LOG_FILE = join(LOGS_DIR, 'session-init.log');
const MAX_LOG_SIZE = 512 * 1024; // 512KB max before truncation

function getTimestamp(): string {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

/**
 * Rotate the session-init.log if it exceeds MAX_LOG_SIZE.
 * Keeps the last ~256KB of the file.
 */
function rotateIfNeeded(): void {
  try {
    if (!existsSync(LOG_FILE)) return;
    const stats = statSync(LOG_FILE);
    if (stats.size > MAX_LOG_SIZE) {
      const { readFileSync } = require('fs');
      const content = readFileSync(LOG_FILE, 'utf-8');
      // Keep last ~256KB
      const keepBytes = 256 * 1024;
      const truncated = content.slice(-keepBytes);
      // Find first newline to avoid partial lines
      const firstNewline = truncated.indexOf('\n');
      const clean = firstNewline > 0 ? truncated.slice(firstNewline + 1) : truncated;
      writeFileSync(LOG_FILE, `[${getTimestamp()}] --- Log rotated (was ${stats.size} bytes) ---\n${clean}`);
    }
  } catch {
    // Don't fail on rotation errors
  }
}

let initialized = false;

function init(): void {
  if (initialized) return;
  initialized = true;
  ensureDirectories();
  rotateIfNeeded();
}

/**
 * Log informational message to session-init.log (not stderr)
 */
export function logInfo(source: string, message: string): void {
  init();
  try {
    appendFileSync(LOG_FILE, `[${getTimestamp()}] [${source}] ${message}\n`);
  } catch {
    // Silently fail - don't crash hooks over logging
  }
}

/**
 * Log warning to session-init.log (not stderr)
 */
export function logWarn(source: string, message: string): void {
  init();
  try {
    appendFileSync(LOG_FILE, `[${getTimestamp()}] [${source}] WARN: ${message}\n`);
  } catch {
    // Silently fail
  }
}
