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

import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

// ============================================================================
// Path Detection
// ============================================================================

/**
 * Detect the Vex-Talon installation directory.
 * Priority:
 * 1. TALON_DIR environment variable
 * 2. ~/.vex-talon (global installation)
 * 3. ./vex-talon (project-local)
 * 4. Fallback to ~/.vex-talon (create if needed)
 */
function detectTalonDir(): string {
  // 1. Check environment variable
  if (process.env.TALON_DIR) {
    return process.env.TALON_DIR;
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
 * Get the audit log path for a specific hook.
 */
export function getAuditLogPath(hookName: string): string {
  return join(LOGS_DIR, `${hookName}-audit.jsonl`);
}

/**
 * Get a state file path for a specific hook.
 */
export function getStateFilePath(hookName: string, filename: string): string {
  return join(STATE_DIR, `${hookName}-${filename}`);
}

/**
 * Get the config file path.
 */
export function getConfigFilePath(filename: string): string {
  return join(CONFIG_DIR, filename);
}

/**
 * Get quarantine directory for a specific hook.
 */
export function getQuarantinePath(hookName: string): string {
  const path = join(QUARANTINE_DIR, hookName);
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  return path;
}
