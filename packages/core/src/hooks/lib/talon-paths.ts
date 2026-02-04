/**
 * Portable Path Resolution for Vex-Talon Hooks
 *
 * Purpose: Provide consistent paths regardless of installation location.
 * Vex-Talon can be installed:
 * - Globally: ~/.vex-talon/
 * - Per-project: ./vex-talon/ or ./.claude-plugin/vex-talon/
 * - Via environment: TALON_DIR=/custom/path
 *
 * @version 0.1.0
 */

import { existsSync, mkdirSync, statSync } from 'fs';
import { join, resolve } from 'path';
import { homedir } from 'os';

// ============================================================================
// Path Validation
// ============================================================================

/**
 * Validate that a TALON_DIR path is safe to use.
 * Prevents path traversal attacks via environment variable manipulation.
 */
function isValidTalonDir(dir: string): boolean {
  const resolved = resolve(dir);
  const home = homedir();
  const cwd = process.cwd();

  // Must be under home directory or current working directory
  if (!resolved.startsWith(home) && !resolved.startsWith(cwd)) {
    return false;
  }

  // Must not contain path traversal sequences after resolution
  if (resolved.includes('..')) {
    return false;
  }

  // If directory exists, verify it's owned by current user (not a symlink attack)
  if (existsSync(resolved)) {
    try {
      const stat = statSync(resolved);
      if (stat.uid !== process.getuid?.()) {
        return false;
      }
    } catch {
      // If we can't stat, reject
      return false;
    }
  }

  return true;
}

// ============================================================================
// Path Detection
// ============================================================================

/**
 * Detect the Vex-Talon installation directory.
 * Priority:
 * 1. TALON_DIR environment variable (validated)
 * 2. ~/.vex-talon (global installation)
 * 3. ./vex-talon (project-local)
 * 4. Fallback to ~/.vex-talon (create if needed)
 */
function detectTalonDir(): string {
  // 1. Check environment variable (with validation)
  if (process.env.TALON_DIR) {
    const envDir = resolve(process.env.TALON_DIR);
    if (isValidTalonDir(envDir)) {
      return envDir;
    }
    // Invalid TALON_DIR - log warning and fall through to defaults
    console.error(`[talon-paths] WARNING: TALON_DIR="${process.env.TALON_DIR}" rejected (path validation failed). Using default.`);
  }

  // 2. Check global installation
  const globalDir = join(homedir(), '.vex-talon');
  if (existsSync(globalDir)) {
    return globalDir;
  }

  // 3. Check project-local installation
  const cwd = process.cwd();
  const projectDirs = [
    join(cwd, '.vex-talon'),
    join(cwd, 'vex-talon'),
    join(cwd, '.claude-plugin', 'vex-talon'),
  ];
  for (const dir of projectDirs) {
    if (existsSync(dir)) {
      return dir;
    }
  }

  // 4. Fallback to global (will be created)
  return globalDir;
}

// ============================================================================
// Directory Structure
// ============================================================================

export const TALON_DIR = detectTalonDir();
export const LOGS_DIR = join(TALON_DIR, 'logs');
export const STATE_DIR = join(TALON_DIR, 'state');
export const CONFIG_DIR = join(TALON_DIR, 'config');
export const QUARANTINE_DIR = join(TALON_DIR, 'quarantine');

// ============================================================================
// Directory Management
// ============================================================================

/**
 * Ensure all required directories exist.
 * Safe to call multiple times.
 */
export function ensureDirectories(): void {
  const dirs = [TALON_DIR, LOGS_DIR, STATE_DIR, CONFIG_DIR, QUARANTINE_DIR];
  for (const dir of dirs) {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }
}

// Alias for backward compatibility
export const ensureTalonDirs = ensureDirectories;

// ============================================================================
// Path Helpers
// ============================================================================

/**
 * Sanitize a name to prevent path traversal in filenames.
 */
function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Rotate a log file if it exceeds the size threshold.
 * Renames current to .1, .1 to .2, etc. Keeps up to 3 rotations.
 */
function rotateIfNeeded(logPath: string, maxBytes: number = 5 * 1024 * 1024): void {
  try {
    if (!existsSync(logPath)) return;
    const stat = statSync(logPath);
    if (stat.size < maxBytes) return;

    // Rotate: .3 → delete, .2 → .3, .1 → .2, current → .1
    for (let i = 2; i >= 1; i--) {
      const from = `${logPath}.${i}`;
      const to = `${logPath}.${i + 1}`;
      if (existsSync(from)) {
        const { renameSync } = require('fs');
        renameSync(from, to);
      }
    }
    const { renameSync } = require('fs');
    renameSync(logPath, `${logPath}.1`);
  } catch {
    // Best-effort rotation - don't block hook execution
  }
}

/**
 * Get the audit log path for a specific hook.
 * Rotates log files that exceed 5MB.
 */
export function getAuditLogPath(hookName: string): string {
  const logPath = join(LOGS_DIR, `${sanitizeName(hookName)}-audit.jsonl`);
  rotateIfNeeded(logPath);
  return logPath;
}

/**
 * Get a state file path for a specific hook.
 */
export function getStateFilePath(hookName: string, filename: string): string {
  return join(STATE_DIR, `${sanitizeName(hookName)}-${sanitizeName(filename)}`);
}

/**
 * Get the config file path.
 */
export function getConfigFilePath(filename: string): string {
  return join(CONFIG_DIR, sanitizeName(filename));
}

/**
 * Get quarantine directory for a specific hook.
 */
export function getQuarantinePath(hookName: string): string {
  const path = join(QUARANTINE_DIR, sanitizeName(hookName));
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return path;
}
