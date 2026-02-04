/**
 * Vex-Talon Circuit Breaker
 *
 * Provides resilience for hooks by tracking failures and preventing
 * cascading failures during outages or performance issues.
 *
 * @version 0.1.0
 * @date 2026-02-04
 */

import { existsSync, readFileSync, writeFileSync } from 'fs';
import { getStateFilePath, ensureDirectories } from './talon-paths';

// ============================================================================
// Types
// ============================================================================

interface CircuitState {
  failures: number;
  lastFailure: number;
  open: boolean;
  openedAt: number;
}

interface CircuitResult {
  shouldExecute: boolean;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
}

// ============================================================================
// Configuration
// ============================================================================

// Threshold raised from 3→5 to prevent deliberate circuit tripping (weaponization).
// Reset lowered from 30s→15s to recover faster when circuit does open.
const FAILURE_THRESHOLD = 5;
const RESET_TIMEOUT_MS = 15000; // 15 seconds

// ============================================================================
// State Management
// ============================================================================

const circuitStates = new Map<string, CircuitState>();

function getState(hookName: string): CircuitState {
  if (circuitStates.has(hookName)) {
    return circuitStates.get(hookName)!;
  }

  // Try to load from disk
  try {
    ensureDirectories();
    const statePath = getStateFilePath(hookName, 'circuit.json');
    if (existsSync(statePath)) {
      const data = JSON.parse(readFileSync(statePath, 'utf-8'));
      circuitStates.set(hookName, data);
      return data;
    }
  } catch {
    // Use default
  }

  const defaultState: CircuitState = {
    failures: 0,
    lastFailure: 0,
    open: false,
    openedAt: 0,
  };
  circuitStates.set(hookName, defaultState);
  return defaultState;
}

function saveState(hookName: string, state: CircuitState): void {
  circuitStates.set(hookName, state);
  try {
    ensureDirectories();
    const statePath = getStateFilePath(hookName, 'circuit.json');
    writeFileSync(statePath, JSON.stringify(state, null, 2));
  } catch {
    // Silent fail
  }
}

// ============================================================================
// Circuit Breaker Logic
// ============================================================================

/**
 * Check if the circuit allows execution
 */
export function checkCircuit(hookName: string): CircuitResult {
  const state = getState(hookName);
  const now = Date.now();

  // Circuit is closed - allow execution
  if (!state.open) {
    return { shouldExecute: true, state: 'CLOSED' };
  }

  // Circuit is open - check if we should try half-open
  const timeSinceOpen = now - state.openedAt;
  if (timeSinceOpen >= RESET_TIMEOUT_MS) {
    return { shouldExecute: true, state: 'HALF_OPEN' };
  }

  // Circuit is still open
  return { shouldExecute: false, state: 'OPEN' };
}

/**
 * Record a successful execution
 */
export function recordSuccess(hookName: string): void {
  const state = getState(hookName);

  if (state.open) {
    // Was in half-open state, close circuit
    state.open = false;
    state.failures = 0;
    state.openedAt = 0;
  } else {
    // Normal success, reset failure count
    state.failures = Math.max(0, state.failures - 1);
  }

  saveState(hookName, state);
}

/**
 * Record a failed execution
 */
export function recordFailure(hookName: string, _error?: string): void {
  const state = getState(hookName);
  const now = Date.now();

  state.failures++;
  state.lastFailure = now;

  if (state.failures >= FAILURE_THRESHOLD) {
    state.open = true;
    state.openedAt = now;
  }

  saveState(hookName, state);
}

/**
 * Reset the circuit for a hook
 */
export function resetCircuit(hookName: string): void {
  const state: CircuitState = {
    failures: 0,
    lastFailure: 0,
    open: false,
    openedAt: 0,
  };
  saveState(hookName, state);
}

/**
 * Get circuit status for monitoring
 */
export function getCircuitStatus(hookName: string): {
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failures: number;
  lastFailure: Date | null;
} {
  const status = getState(hookName);
  const result = checkCircuit(hookName);

  return {
    state: result.state,
    failures: status.failures,
    lastFailure: status.lastFailure ? new Date(status.lastFailure) : null,
  };
}
