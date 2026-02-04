/**
 * Circuit Breaker for Vex-Talon Security Hooks
 *
 * Purpose: Prevent cascading failures when hooks fail repeatedly.
 * Pattern: Circuit Breaker (from resilience engineering)
 *
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Too many failures, requests bypass hook (with warning)
 * - HALF_OPEN: Testing if hook has recovered
 *
 * @version 0.1.0
 * @date 2026-02-04
 */

import { existsSync, readFileSync, mkdirSync, writeFileSync, unlinkSync, statSync } from 'fs';
import { join } from 'path';
import { STATE_DIR, ensureTalonDirs } from './talon-paths';
import { atomicWriteFileSync, readJsonFileSync } from './atomic-file';

// ============================================================================
// File Locking
// ============================================================================

const LOCK_FILE = join(STATE_DIR, 'circuit-breaker.lock');
const LOCK_TIMEOUT_MS = 5000;
const LOCK_STALE_MS = 10000;

function acquireLock(): () => void {
  ensureTalonDirs();
  const startTime = Date.now();

  while (Date.now() - startTime < LOCK_TIMEOUT_MS) {
    try {
      if (existsSync(LOCK_FILE)) {
        const lockStat = statSync(LOCK_FILE);
        const lockAge = Date.now() - lockStat.mtimeMs;
        if (lockAge > LOCK_STALE_MS) {
          try { unlinkSync(LOCK_FILE); } catch {}
        } else {
          const waitMs = Math.min(50, LOCK_TIMEOUT_MS - (Date.now() - startTime));
          if (waitMs > 0) {
            Bun.sleepSync(waitMs);
          }
          continue;
        }
      }

      writeFileSync(LOCK_FILE, process.pid.toString(), { flag: 'wx', mode: 0o600 });

      return () => {
        try { unlinkSync(LOCK_FILE); } catch {}
      };
    } catch (e: any) {
      if (e.code === 'EEXIST') {
        const waitMs = Math.min(50, LOCK_TIMEOUT_MS - (Date.now() - startTime));
        if (waitMs > 0) {
          Bun.sleepSync(waitMs);
        }
        continue;
      }
      break;
    }
  }

  console.error('[CircuitBreaker] Warning: Could not acquire lock, proceeding without');
  return () => {};
}

// ============================================================================
// Types
// ============================================================================

type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

interface CircuitBreakerState {
  hookName: string;
  state: CircuitState;
  failureCount: number;
  lastFailureTime: number;
  lastSuccessTime: number;
  openedAt: number | null;
  totalFailures: number;
  totalSuccesses: number;
}

interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeoutMs: number;
  successThreshold: number;
}

// ============================================================================
// Configuration
// ============================================================================

const STATE_FILE = join(STATE_DIR, 'circuit-breaker.json');

const DEFAULT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  resetTimeoutMs: 60000,
  successThreshold: 2,
};

// ============================================================================
// State Management
// ============================================================================

function loadState(): Record<string, CircuitBreakerState> {
  ensureTalonDirs();
  return readJsonFileSync<Record<string, CircuitBreakerState>>(STATE_FILE, {});
}

function saveState(state: Record<string, CircuitBreakerState>): void {
  ensureTalonDirs();
  atomicWriteFileSync(STATE_FILE, JSON.stringify(state, null, 2), 0o600);
}

function getHookState(hookName: string): CircuitBreakerState {
  const allState = loadState();
  return allState[hookName] || {
    hookName,
    state: 'CLOSED',
    failureCount: 0,
    lastFailureTime: 0,
    lastSuccessTime: 0,
    openedAt: null,
    totalFailures: 0,
    totalSuccesses: 0,
  };
}

function updateHookState(state: CircuitBreakerState): void {
  const releaseLock = acquireLock();
  try {
    const allState = loadState();
    allState[state.hookName] = state;
    saveState(allState);
  } finally {
    releaseLock();
  }
}

// ============================================================================
// Circuit Breaker Logic
// ============================================================================

export function checkCircuit(
  hookName: string,
  config: Partial<CircuitBreakerConfig> = {}
): { shouldExecute: boolean; state: CircuitState; reason?: string } {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const hookState = getHookState(hookName);
  const now = Date.now();

  switch (hookState.state) {
    case 'CLOSED':
      return { shouldExecute: true, state: 'CLOSED' };

    case 'OPEN':
      if (hookState.openedAt && now - hookState.openedAt >= cfg.resetTimeoutMs) {
        hookState.state = 'HALF_OPEN';
        hookState.failureCount = 0;
        updateHookState(hookState);
        return {
          shouldExecute: true,
          state: 'HALF_OPEN',
          reason: 'Testing recovery after timeout',
        };
      }
      return {
        shouldExecute: false,
        state: 'OPEN',
        reason: `Circuit OPEN - ${Math.round((cfg.resetTimeoutMs - (now - (hookState.openedAt || 0))) / 1000)}s until retry`,
      };

    case 'HALF_OPEN':
      return {
        shouldExecute: true,
        state: 'HALF_OPEN',
        reason: 'Testing recovery',
      };

    default:
      return { shouldExecute: true, state: 'CLOSED' };
  }
}

export function recordSuccess(
  hookName: string,
  config: Partial<CircuitBreakerConfig> = {}
): void {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const hookState = getHookState(hookName);
  const now = Date.now();

  hookState.lastSuccessTime = now;
  hookState.totalSuccesses++;

  if (hookState.state === 'HALF_OPEN') {
    hookState.failureCount = 0;
    if (hookState.totalSuccesses >= cfg.successThreshold) {
      hookState.state = 'CLOSED';
      hookState.openedAt = null;
    }
  } else if (hookState.state === 'CLOSED') {
    hookState.failureCount = 0;
  }

  updateHookState(hookState);
}

export function recordFailure(
  hookName: string,
  error?: string,
  config: Partial<CircuitBreakerConfig> = {}
): void {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const hookState = getHookState(hookName);
  const now = Date.now();

  hookState.lastFailureTime = now;
  hookState.failureCount++;
  hookState.totalFailures++;

  if (hookState.state === 'HALF_OPEN') {
    hookState.state = 'OPEN';
    hookState.openedAt = now;
  } else if (hookState.state === 'CLOSED' && hookState.failureCount >= cfg.failureThreshold) {
    hookState.state = 'OPEN';
    hookState.openedAt = now;
    console.error(`\n⚡ [Circuit Breaker] Hook "${hookName}" circuit OPENED after ${hookState.failureCount} failures`);
    if (error) {
      console.error(`   Last error: ${error}`);
    }
    console.error(`   Will retry in ${cfg.resetTimeoutMs / 1000}s\n`);
  }

  updateHookState(hookState);
}

export function getAllCircuitStatus(): Record<string, CircuitBreakerState> {
  return loadState();
}

export function resetCircuit(hookName: string): void {
  const releaseLock = acquireLock();
  try {
    const allState = loadState();
    delete allState[hookName];
    saveState(allState);
  } finally {
    releaseLock();
  }
}

export function resetAllCircuits(): void {
  const releaseLock = acquireLock();
  try {
    saveState({});
  } finally {
    releaseLock();
  }
}
