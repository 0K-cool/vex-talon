/**
 * Atomic File Operations for Vex-Talon Security Hooks
 *
 * Purpose: Prevent race conditions when multiple processes access state files.
 * Pattern: Write to temp file, then atomic rename.
 *
 * Ported from PAI security architecture.
 *
 * @version 1.0.0
 * @date 2026-02-04
 */

import { writeFileSync, renameSync, unlinkSync, existsSync, readFileSync } from 'fs';
import { dirname, basename, join } from 'path';

/**
 * Write content to a file atomically.
 */
export function atomicWriteFileSync(
  filePath: string,
  content: string,
  mode: number = 0o600
): void {
  const dir = dirname(filePath);
  const base = basename(filePath);
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  const tempPath = join(dir, `.${base}.${timestamp}.${random}.tmp`);

  try {
    writeFileSync(tempPath, content, { mode });
    renameSync(tempPath, filePath);
  } catch (error) {
    try {
      if (existsSync(tempPath)) {
        unlinkSync(tempPath);
      }
    } catch {}
    throw error;
  }
}

/**
 * Read and update a JSON state file atomically.
 */
export function atomicUpdateJsonFile<T>(
  filePath: string,
  updateFn: (current: T) => T,
  defaultState: T,
  mode: number = 0o600
): T {
  let currentState: T = defaultState;
  try {
    if (existsSync(filePath)) {
      const content = readFileSync(filePath, 'utf-8');
      currentState = JSON.parse(content);
    }
  } catch {
    currentState = defaultState;
  }

  const updatedState = updateFn(currentState);
  atomicWriteFileSync(filePath, JSON.stringify(updatedState, null, 2), mode);
  return updatedState;
}

/**
 * Read a JSON file with graceful fallback.
 */
export function readJsonFileSync<T>(filePath: string, defaultValue: T): T {
  try {
    if (existsSync(filePath)) {
      const content = readFileSync(filePath, 'utf-8');
      return JSON.parse(content);
    }
  } catch {}
  return defaultValue;
}
