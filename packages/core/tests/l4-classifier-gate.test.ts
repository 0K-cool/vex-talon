/**
 * Tests for L4 classifier additions in src/hooks/lib/classifier.ts:
 *
 *   - resolveL4Backend()        — symmetric to L3's resolveBackend()
 *   - isL4ClassifierEnabled()   — symmetric to L3's isClassifierEnabled()
 *   - applyL4ClassifierGate()   — pure decision logic for the L4 alert gate
 *
 * The L4 classifier reuses the same CLI/API plumbing as L3 (Phase 4),
 * so backend tests focus on the per-layer override env-var
 * (VEX_L4_CLASSIFIER_BACKEND) rather than re-testing the CLI subprocess
 * or HTTP path — those are covered by l3-classifier-backend.test.ts.
 *
 * Run: pnpm test packages/core/tests/l4-classifier-gate.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  resolveL4Backend,
  isL4ClassifierEnabled,
  applyL4ClassifierGate,
  type Backend,
  type Verdict,
} from '../src/hooks/lib/classifier';

/**
 * Build a throwaway directory containing an executable shim named
 * `claude` so PATH-based detection has a deterministic hit, regardless
 * of whether Claude Code is actually installed on the test runner.
 */
function makeFakeClaudeBinDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fake-claude-bin-l4-'));
  const shim = join(dir, 'claude');
  writeFileSync(shim, '#!/bin/sh\nexit 0\n');
  chmodSync(shim, 0o755);
  return dir;
}

// ===========================================================================
// resolveL4Backend — env-driven dispatch (mirrors L3)
// ===========================================================================

describe('resolveL4Backend', () => {
  const origTier = process.env.VEX_L4_CLASSIFIER;
  const origExplicit = process.env.VEX_L4_CLASSIFIER_BACKEND;
  const origL3Tier = process.env.VEX_L3_CLASSIFIER;
  const origL3Explicit = process.env.VEX_L3_CLASSIFIER_BACKEND;
  const origKey = process.env.ANTHROPIC_API_KEY;
  const origPath = process.env.PATH;

  beforeEach(() => {
    delete process.env.VEX_L4_CLASSIFIER;
    delete process.env.VEX_L4_CLASSIFIER_BACKEND;
    delete process.env.VEX_L3_CLASSIFIER;
    delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    delete process.env.ANTHROPIC_API_KEY;
    process.env.PATH = origPath;
  });

  afterEach(() => {
    if (origTier === undefined) delete process.env.VEX_L4_CLASSIFIER;
    else process.env.VEX_L4_CLASSIFIER = origTier;
    if (origExplicit === undefined) delete process.env.VEX_L4_CLASSIFIER_BACKEND;
    else process.env.VEX_L4_CLASSIFIER_BACKEND = origExplicit;
    if (origL3Tier === undefined) delete process.env.VEX_L3_CLASSIFIER;
    else process.env.VEX_L3_CLASSIFIER = origL3Tier;
    if (origL3Explicit === undefined) delete process.env.VEX_L3_CLASSIFIER_BACKEND;
    else process.env.VEX_L3_CLASSIFIER_BACKEND = origL3Explicit;
    if (origKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = origKey;
    process.env.PATH = origPath;
  });

  it('returns null when explicit=cli but claude is not on PATH', () => {
    process.env.VEX_L4_CLASSIFIER_BACKEND = 'cli';
    process.env.PATH = '/nonexistent';
    expect(resolveL4Backend()).toBeNull();
  });

  it('returns "api" when explicit=api and ANTHROPIC_API_KEY is set', () => {
    process.env.VEX_L4_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveL4Backend()).toBe<Backend>('api');
  });

  it('returns null when explicit=api but ANTHROPIC_API_KEY is missing', () => {
    process.env.VEX_L4_CLASSIFIER_BACKEND = 'api';
    expect(resolveL4Backend()).toBeNull();
  });

  it('auto-prefers cli when claude is on PATH (local-only philosophy)', () => {
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${fakeBinDir}:${origPath ?? ''}`;
      expect(resolveL4Backend()).toBe<Backend>('cli');
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });

  it('auto-falls-back to api when claude is not on PATH but API key is set', () => {
    process.env.PATH = '/nonexistent';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveL4Backend()).toBe<Backend>('api');
  });

  it('auto-returns null when neither claude CLI nor API key is available', () => {
    process.env.PATH = '/nonexistent';
    expect(resolveL4Backend()).toBeNull();
  });

  it('rejects unknown explicit backend value (falls through to auto)', () => {
    process.env.VEX_L4_CLASSIFIER_BACKEND = 'magic';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    process.env.PATH = '/nonexistent';
    expect(resolveL4Backend()).toBe<Backend>('api');
  });

  it('is independent of L3 backend override (per-layer config)', () => {
    // L3 forced to api (with no key — would be null), L4 left in auto.
    // L4 should pick CLI from PATH; the L3 override must not bleed through.
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'api';
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${fakeBinDir}:${origPath ?? ''}`;
      expect(resolveL4Backend()).toBe<Backend>('cli');
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
// isL4ClassifierEnabled — combines L4 tier toggle with backend availability
// ===========================================================================

describe('isL4ClassifierEnabled', () => {
  const origTier = process.env.VEX_L4_CLASSIFIER;
  const origExplicit = process.env.VEX_L4_CLASSIFIER_BACKEND;
  const origL3Tier = process.env.VEX_L3_CLASSIFIER;
  const origKey = process.env.ANTHROPIC_API_KEY;
  const origPath = process.env.PATH;

  beforeEach(() => {
    delete process.env.VEX_L4_CLASSIFIER;
    delete process.env.VEX_L4_CLASSIFIER_BACKEND;
    delete process.env.VEX_L3_CLASSIFIER;
    delete process.env.ANTHROPIC_API_KEY;
    process.env.PATH = origPath;
  });

  afterEach(() => {
    if (origTier === undefined) delete process.env.VEX_L4_CLASSIFIER;
    else process.env.VEX_L4_CLASSIFIER = origTier;
    if (origExplicit === undefined) delete process.env.VEX_L4_CLASSIFIER_BACKEND;
    else process.env.VEX_L4_CLASSIFIER_BACKEND = origExplicit;
    if (origL3Tier === undefined) delete process.env.VEX_L3_CLASSIFIER;
    else process.env.VEX_L3_CLASSIFIER = origL3Tier;
    if (origKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = origKey;
    process.env.PATH = origPath;
  });

  it('false when L4 tier off, even with backend available', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(false);
  });

  it('false when L3 is smart but L4 left default (independence check)', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(false);
  });

  it('true when L4 tier=smart and CLI backend resolvable', () => {
    process.env.VEX_L4_CLASSIFIER = 'smart';
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.PATH = `${fakeBinDir}:${origPath ?? ''}`;
      expect(isL4ClassifierEnabled()).toBe(true);
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });

  it('true when L4 tier=smart, no CLI, but API key present', () => {
    process.env.VEX_L4_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(true);
  });

  it('false when L4 tier=smart but no backend is available', () => {
    process.env.VEX_L4_CLASSIFIER = 'smart';
    process.env.PATH = '/nonexistent';
    expect(isL4ClassifierEnabled()).toBe(false);
  });
});

// ===========================================================================
// applyL4ClassifierGate — pure verdict→alert decision
// ===========================================================================

describe('applyL4ClassifierGate', () => {
  const v = (
    verdict: Verdict['verdict'],
    confidence: number,
    reasoning = 'test reasoning',
  ): Verdict => ({ verdict, confidence, reasoning });

  describe('pattern tier did not request alert', () => {
    it('no-ops regardless of verdict', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: false,
        verdict: v('INSTRUCTION', 0.99),
      });
      expect(result.shouldAlert).toBe(false);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('DISABLED');
      expect(result.decisionReason).toMatch(/no alert pending/i);
    });

    it('no-ops when classifier disabled too', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: false,
        verdict: null,
      });
      expect(result.shouldAlert).toBe(false);
      expect(result.downgraded).toBe(false);
    });
  });

  describe('classifier disabled / unavailable (verdict=null)', () => {
    it('preserves the pattern-tier alert (no behavior change vs. current default)', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: null,
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('DISABLED');
      expect(result.classifierConfidence).toBe(0);
      expect(result.decisionReason).toMatch(/classifier disabled/i);
    });
  });

  describe('classifier returns DESCRIPTION (downgrade path)', () => {
    it('downgrades alert when DESCRIPTION + conf >= 0.70', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('DESCRIPTION', 0.85, 'CodeRabbit JSON output, not directives'),
      });
      expect(result.shouldAlert).toBe(false);
      expect(result.downgraded).toBe(true);
      expect(result.classifierVerdict).toBe('DESCRIPTION');
      expect(result.classifierConfidence).toBeCloseTo(0.85);
      expect(result.classifierReasoning).toContain('CodeRabbit');
      expect(result.decisionReason).toMatch(/DESCRIPTION/);
    });

    it('keeps alert when DESCRIPTION but confidence is below 0.70 (fail-safe)', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('DESCRIPTION', 0.55),
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('DESCRIPTION');
      expect(result.decisionReason).toMatch(/low confidence/i);
    });

    it('downgrades at the exact 0.70 boundary (>= threshold)', () => {
      // Threshold is "DESCRIPTION + conf >= 0.70 → skip" — at 0.70 exactly we DO skip.
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('DESCRIPTION', 0.70),
      });
      expect(result.shouldAlert).toBe(false);
      expect(result.downgraded).toBe(true);
    });
  });

  describe('classifier returns INSTRUCTION (alert preserved)', () => {
    it('keeps alert when INSTRUCTION + conf >= 0.85', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('INSTRUCTION', 0.95, 'imperative override directive'),
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('INSTRUCTION');
      expect(result.classifierReasoning).toContain('imperative');
    });

    it('keeps alert when INSTRUCTION but confidence is below 0.85 (fail-safe)', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('INSTRUCTION', 0.80),
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.decisionReason).toMatch(/low confidence/i);
    });
  });

  describe('classifier returns AMBIGUOUS (fail-safe)', () => {
    it('keeps alert', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: v('AMBIGUOUS', 0.99),
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('AMBIGUOUS');
      expect(result.decisionReason).toMatch(/AMBIGUOUS/);
    });
  });

  describe('classifier ERROR (fail-safe)', () => {
    it('keeps alert when classifier returned ERROR', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: { verdict: 'ERROR', confidence: 0, reasoning: 'cli timeout' },
      });
      expect(result.shouldAlert).toBe(true);
      expect(result.downgraded).toBe(false);
      expect(result.classifierVerdict).toBe('ERROR');
      expect(result.decisionReason).toMatch(/classifier ERROR/);
    });
  });

  describe('reasoning passthrough', () => {
    it('handles missing reasoning field gracefully', () => {
      const result = applyL4ClassifierGate({
        patternShouldAlert: true,
        verdict: { verdict: 'DESCRIPTION', confidence: 0.9 } as Verdict,
      });
      expect(result.classifierReasoning).toBe('');
      expect(result.shouldAlert).toBe(false);
    });
  });
});
