/**
 * Tests for graceful env-var migration: VEX_L*_* → OK_TALON_L*_*
 *
 * The plugin originally shipped with `VEX_L3_CLASSIFIER` /
 * `VEX_L3_CLASSIFIER_BACKEND` (port from PAI) and `VEX_L4_CLASSIFIER` /
 * `VEX_L4_CLASSIFIER_BACKEND`. The plugin-facing convention (matching
 * `OK_TALON_PATTERN_TIER`) is `OK_TALON_*` — this PR adds the new names
 * as the canonical primary while keeping `VEX_*` working as a
 * deprecated fallback with a one-time stderr warning.
 *
 * Drop the `VEX_*` fallback in 0K-Talon v2.
 *
 * Test scope:
 *   - Primary `OK_TALON_*` works for L3/L4 tier + backend
 *   - Legacy `VEX_*` still works (backward compat)
 *   - Legacy emits a one-time stderr deprecation warning
 *   - Primary wins on conflict (silently — user is mid-migration)
 *   - Warning emitted at most once per legacy var name
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  resolveBackend,
  resolveL4Backend,
  isClassifierEnabled,
  isL4ClassifierEnabled,
  _resetLegacyWarningsForTesting,
  type Backend,
} from '../src/hooks/lib/classifier';

function makeFakeClaudeBinDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fake-claude-bin-rename-'));
  const shim = join(dir, 'claude');
  writeFileSync(shim, '#!/bin/sh\nexit 0\n');
  chmodSync(shim, 0o755);
  return dir;
}

const ALL_VARS = [
  'OK_TALON_L3_CLASSIFIER',
  'OK_TALON_L3_CLASSIFIER_BACKEND',
  'OK_TALON_L4_CLASSIFIER',
  'OK_TALON_L4_CLASSIFIER_BACKEND',
  'VEX_L3_CLASSIFIER',
  'VEX_L3_CLASSIFIER_BACKEND',
  'VEX_L4_CLASSIFIER',
  'VEX_L4_CLASSIFIER_BACKEND',
];

function snapshotEnv() {
  const snap: Record<string, string | undefined> = {};
  for (const v of ALL_VARS) snap[v] = process.env[v];
  snap.PATH = process.env.PATH;
  snap.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  return snap;
}

function restoreEnv(snap: Record<string, string | undefined>) {
  for (const v of ALL_VARS) {
    if (snap[v] === undefined) delete process.env[v];
    else process.env[v] = snap[v];
  }
  if (snap.PATH === undefined) delete process.env.PATH;
  else process.env.PATH = snap.PATH;
  if (snap.ANTHROPIC_API_KEY === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = snap.ANTHROPIC_API_KEY;
}

// ===========================================================================
// Setup helpers shared across all describe blocks
// ===========================================================================

let envSnap: Record<string, string | undefined>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

function commonBeforeEach() {
  envSnap = snapshotEnv();
  for (const v of ALL_VARS) delete process.env[v];
  delete process.env.ANTHROPIC_API_KEY;
  _resetLegacyWarningsForTesting();
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
}

function commonAfterEach() {
  restoreEnv(envSnap);
  stderrSpy.mockRestore();
}

function deprecationMessages(): string[] {
  return stderrSpy.mock.calls
    .map((c) => String(c[0]))
    .filter((s) => s.includes('DEPRECATED'));
}

// ===========================================================================
// L3 — OK_TALON_* as primary
// ===========================================================================

describe('L3: OK_TALON_* primary takes effect', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('OK_TALON_L3_CLASSIFIER_BACKEND=api → resolveBackend returns "api"', () => {
    process.env.OK_TALON_L3_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveBackend()).toBe<Backend>('api');
  });

  it('OK_TALON_L3_CLASSIFIER=smart + backend present → isClassifierEnabled true', () => {
    process.env.OK_TALON_L3_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(true);
  });

  it('uses OK_TALON_* without emitting any deprecation warning', () => {
    process.env.OK_TALON_L3_CLASSIFIER = 'smart';
    process.env.OK_TALON_L3_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isClassifierEnabled(); // exercises both tier + backend resolution
    expect(deprecationMessages()).toEqual([]);
  });
});

// ===========================================================================
// L3 — VEX_* legacy still works + emits warning
// ===========================================================================

describe('L3: VEX_* legacy fallback', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('VEX_L3_CLASSIFIER_BACKEND=api still resolves to "api"', () => {
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveBackend()).toBe<Backend>('api');
  });

  it('VEX_L3_CLASSIFIER=smart still enables the classifier', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(true);
  });

  it('using VEX_L3_CLASSIFIER emits a one-time stderr deprecation warning', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isClassifierEnabled();
    const warnings = deprecationMessages();
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.join('\n')).toContain('VEX_L3_CLASSIFIER');
    expect(warnings.join('\n')).toContain('OK_TALON_L3_CLASSIFIER');
  });

  it('warning fires at most once per legacy var even across many calls', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    for (let i = 0; i < 5; i++) isClassifierEnabled();
    const tierWarnings = deprecationMessages().filter((m) =>
      m.includes('VEX_L3_CLASSIFIER ') ||
      m.match(/VEX_L3_CLASSIFIER\b/),
    );
    expect(tierWarnings.length).toBe(1);
  });
});

// ===========================================================================
// L3 — Primary wins on conflict (no warning emitted)
// ===========================================================================

describe('L3: primary wins on conflict', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('OK_TALON beats VEX when both set, primary value used', () => {
    process.env.OK_TALON_L3_CLASSIFIER = 'smart';
    process.env.VEX_L3_CLASSIFIER = 'off';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(true); // smart wins, not off
  });

  it('no deprecation warning when both names are set (operator mid-migration)', () => {
    process.env.OK_TALON_L3_CLASSIFIER = 'smart';
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.OK_TALON_L3_CLASSIFIER_BACKEND = 'api';
    process.env.VEX_L3_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isClassifierEnabled();
    expect(deprecationMessages()).toEqual([]);
  });
});

// ===========================================================================
// L4 — OK_TALON_* parity with L3
// ===========================================================================

describe('L4: OK_TALON_* primary takes effect', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('OK_TALON_L4_CLASSIFIER_BACKEND=api → resolveL4Backend returns "api"', () => {
    process.env.OK_TALON_L4_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveL4Backend()).toBe<Backend>('api');
  });

  it('OK_TALON_L4_CLASSIFIER=smart + backend present → isL4ClassifierEnabled true', () => {
    process.env.OK_TALON_L4_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(true);
  });

  it('uses OK_TALON_* without emitting any deprecation warning', () => {
    process.env.OK_TALON_L4_CLASSIFIER = 'smart';
    process.env.OK_TALON_L4_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isL4ClassifierEnabled();
    expect(deprecationMessages()).toEqual([]);
  });
});

describe('L4: VEX_* legacy fallback', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('VEX_L4_CLASSIFIER=smart still enables the L4 classifier', () => {
    process.env.VEX_L4_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(true);
  });

  it('VEX_L4_CLASSIFIER_BACKEND=api still resolves to "api"', () => {
    process.env.VEX_L4_CLASSIFIER_BACKEND = 'api';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(resolveL4Backend()).toBe<Backend>('api');
  });

  it('using VEX_L4_CLASSIFIER emits a one-time stderr deprecation warning', () => {
    process.env.VEX_L4_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isL4ClassifierEnabled();
    const warnings = deprecationMessages();
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.join('\n')).toContain('VEX_L4_CLASSIFIER');
    expect(warnings.join('\n')).toContain('OK_TALON_L4_CLASSIFIER');
  });
});

describe('L4: primary wins on conflict', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('OK_TALON_L4_CLASSIFIER=smart beats VEX_L4_CLASSIFIER=off', () => {
    process.env.OK_TALON_L4_CLASSIFIER = 'smart';
    process.env.VEX_L4_CLASSIFIER = 'off';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(true);
  });
});

// ===========================================================================
// Cross-layer independence — L3 and L4 deprecation warnings are independent
// ===========================================================================

describe('L3 and L4 deprecation warnings are independent', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('warning for VEX_L3_CLASSIFIER does not suppress the VEX_L4_CLASSIFIER warning', () => {
    process.env.VEX_L3_CLASSIFIER = 'smart';
    process.env.VEX_L4_CLASSIFIER = 'smart';
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isClassifierEnabled();
    isL4ClassifierEnabled();
    const warnings = deprecationMessages().join('\n');
    expect(warnings).toContain('VEX_L3_CLASSIFIER');
    expect(warnings).toContain('VEX_L4_CLASSIFIER');
  });
});

// ===========================================================================
// Negative cases — neither name set
// ===========================================================================

describe('neither name set', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('isClassifierEnabled false when no tier env is set', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isClassifierEnabled()).toBe(false);
  });

  it('isL4ClassifierEnabled false when no L4 tier env is set', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    expect(isL4ClassifierEnabled()).toBe(false);
  });

  it('no deprecation warning when no env is set', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    isClassifierEnabled();
    isL4ClassifierEnabled();
    expect(deprecationMessages()).toEqual([]);
  });
});

// ===========================================================================
// CLI-backend resolution honors OK_TALON_* override too
// ===========================================================================

describe('CLI backend resolution under OK_TALON_*', () => {
  beforeEach(commonBeforeEach);
  afterEach(commonAfterEach);

  it('OK_TALON_L3_CLASSIFIER_BACKEND=cli + claude on PATH → "cli"', () => {
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.OK_TALON_L3_CLASSIFIER_BACKEND = 'cli';
      process.env.PATH = `${fakeBinDir}:${envSnap.PATH ?? ''}`;
      expect(resolveBackend()).toBe<Backend>('cli');
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });

  it('OK_TALON_L4_CLASSIFIER_BACKEND=cli + claude on PATH → "cli"', () => {
    const fakeBinDir = makeFakeClaudeBinDir();
    try {
      process.env.OK_TALON_L4_CLASSIFIER_BACKEND = 'cli';
      process.env.PATH = `${fakeBinDir}:${envSnap.PATH ?? ''}`;
      expect(resolveL4Backend()).toBe<Backend>('cli');
    } finally {
      rmSync(fakeBinDir, { recursive: true, force: true });
    }
  });
});
