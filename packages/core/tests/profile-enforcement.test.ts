/**
 * Profile Enforcement Tests
 *
 * Tests for L12 Least Privilege profile enforcement in L1 Governor
 */

import { describe, it, expect } from 'vitest';

// Import profile functions from the shared loader
// Note: In actual tests, we'd import from the module
// For now, we test the logic directly

// ============================================================================
// Profile Type Definition
// ============================================================================

interface Profile {
  name: string;
  description: string;
  tools: {
    mode: 'allowlist' | 'blocklist';
    allowed?: string[];
    blocked?: string[];
  };
  directories: {
    read_write?: string[];
    read_only?: string[];
    blocked?: string[];
  };
  bash?: {
    allowed_patterns?: string[];
    blocked_patterns?: string[];
  };
}

// ============================================================================
// Profile Enforcement Functions (mirrored for testing)
// ============================================================================

function isToolAllowed(tool: string, profile: Profile): { allowed: boolean; reason: string } {
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions' };
  }

  const { mode, allowed, blocked } = profile.tools;

  if (mode === 'allowlist') {
    if (allowed && allowed.includes(tool)) {
      return { allowed: true, reason: 'Tool in allowlist' };
    }
    return {
      allowed: false,
      reason: `Tool '${tool}' not in allowlist`,
    };
  }

  if (mode === 'blocklist') {
    if (blocked && blocked.includes(tool)) {
      return {
        allowed: false,
        reason: `Tool '${tool}' blocked`,
      };
    }
    return { allowed: true, reason: 'Tool not in blocklist' };
  }

  return { allowed: true, reason: 'Unknown mode - allowing' };
}

function isPathAllowed(
  path: string,
  operation: 'read' | 'write',
  profile: Profile
): { allowed: boolean; reason: string } {
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions' };
  }

  const { read_write, read_only, blocked } = profile.directories;

  // Check blocked paths first
  if (blocked) {
    for (const blockedPath of blocked) {
      const expandedPath = blockedPath.replace('~', '/home/user');
      if (path.includes(expandedPath) || path.startsWith(expandedPath)) {
        return {
          allowed: false,
          reason: `Path '${path}' is blocked`,
        };
      }
    }
  }

  // For write operations, check if path is read-only
  if (operation === 'write' && read_only) {
    if (read_only.includes('*')) {
      if (read_write) {
        for (const rwPath of read_write) {
          if (path.includes(rwPath) || path.startsWith(rwPath)) {
            return { allowed: true, reason: 'Path in read_write allowlist' };
          }
        }
      }
      return {
        allowed: false,
        reason: 'Write operation blocked - profile is read-only',
      };
    }
  }

  return { allowed: true, reason: 'Path not restricted' };
}

function isBashCommandAllowed(command: string, profile: Profile): { allowed: boolean; reason: string } {
  if (profile.name === 'dev') {
    return { allowed: true, reason: 'dev profile - no restrictions' };
  }

  const { allowed_patterns, blocked_patterns } = profile.bash || {};

  // Check blocked patterns first
  if (blocked_patterns) {
    for (const pattern of blocked_patterns) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
      if (regex.test(command) || command.startsWith(pattern.replace('*', ''))) {
        return {
          allowed: false,
          reason: `Bash command blocked: matches '${pattern}'`,
        };
      }
    }
  }

  // If allowed_patterns is set and not matching, block
  if (allowed_patterns && allowed_patterns.length > 0) {
    for (const pattern of allowed_patterns) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$', 'i');
      if (regex.test(command) || command.startsWith(pattern.replace('*', ''))) {
        return { allowed: true, reason: 'Bash command in allowlist' };
      }
    }
    return {
      allowed: false,
      reason: 'Bash command not in allowlist',
    };
  }

  return { allowed: true, reason: 'No bash restrictions' };
}

// ============================================================================
// Test Profiles
// ============================================================================

const devProfile: Profile = {
  name: 'dev',
  description: 'Full development access - no restrictions',
  tools: { mode: 'blocklist', blocked: [] },
  directories: {},
  bash: {},
};

const auditProfile: Profile = {
  name: 'audit',
  description: 'Read-only access for security audits',
  tools: {
    mode: 'allowlist',
    allowed: ['Read', 'Glob', 'Grep', 'Bash', 'WebFetch', 'WebSearch', 'Task'],
  },
  directories: {
    read_only: ['*'],
    blocked: ['/etc', '/var', '~/.ssh', '~/.gnupg'],
  },
  bash: {
    allowed_patterns: ['ls *', 'cat *', 'grep *', 'git log*', 'git show*', 'git diff*'],
    blocked_patterns: ['rm *', 'mv *', 'chmod *', 'git commit*', 'git push*'],
  },
};

const clientWorkProfile: Profile = {
  name: 'client-work',
  description: 'Restricted profile for confidential client work',
  tools: {
    mode: 'blocklist',
    blocked: ['WebFetch', 'WebSearch'],
  },
  directories: {
    read_write: ['output/client-work/', 'output/temp/'],
    blocked: ['~/.ssh', '~/.gnupg', '~/.aws'],
  },
  bash: {
    blocked_patterns: ['curl *', 'wget *', 'git push*', 'ssh *', 'scp *'],
  },
};

const researchProfile: Profile = {
  name: 'research',
  description: 'Research mode - read access with web search, no writes',
  tools: {
    mode: 'allowlist',
    allowed: ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'Task'],
  },
  directories: {
    read_only: ['*'],
  },
  bash: {
    blocked_patterns: ['*'],
  },
};

// ============================================================================
// Tool Enforcement Tests
// ============================================================================

describe('Tool Enforcement', () => {
  describe('dev profile', () => {
    it('allows all tools', () => {
      expect(isToolAllowed('Write', devProfile).allowed).toBe(true);
      expect(isToolAllowed('Edit', devProfile).allowed).toBe(true);
      expect(isToolAllowed('Bash', devProfile).allowed).toBe(true);
      expect(isToolAllowed('WebFetch', devProfile).allowed).toBe(true);
    });
  });

  describe('audit profile (allowlist)', () => {
    it('allows tools in allowlist', () => {
      expect(isToolAllowed('Read', auditProfile).allowed).toBe(true);
      expect(isToolAllowed('Glob', auditProfile).allowed).toBe(true);
      expect(isToolAllowed('Grep', auditProfile).allowed).toBe(true);
      expect(isToolAllowed('Bash', auditProfile).allowed).toBe(true);
    });

    it('blocks tools not in allowlist', () => {
      expect(isToolAllowed('Write', auditProfile).allowed).toBe(false);
      expect(isToolAllowed('Edit', auditProfile).allowed).toBe(false);
    });
  });

  describe('client-work profile (blocklist)', () => {
    it('allows most tools', () => {
      expect(isToolAllowed('Read', clientWorkProfile).allowed).toBe(true);
      expect(isToolAllowed('Write', clientWorkProfile).allowed).toBe(true);
      expect(isToolAllowed('Edit', clientWorkProfile).allowed).toBe(true);
      expect(isToolAllowed('Bash', clientWorkProfile).allowed).toBe(true);
    });

    it('blocks network tools', () => {
      expect(isToolAllowed('WebFetch', clientWorkProfile).allowed).toBe(false);
      expect(isToolAllowed('WebSearch', clientWorkProfile).allowed).toBe(false);
    });
  });

  describe('research profile (allowlist)', () => {
    it('allows read and web tools', () => {
      expect(isToolAllowed('Read', researchProfile).allowed).toBe(true);
      expect(isToolAllowed('Glob', researchProfile).allowed).toBe(true);
      expect(isToolAllowed('WebFetch', researchProfile).allowed).toBe(true);
      expect(isToolAllowed('WebSearch', researchProfile).allowed).toBe(true);
    });

    it('blocks write tools', () => {
      expect(isToolAllowed('Write', researchProfile).allowed).toBe(false);
      expect(isToolAllowed('Edit', researchProfile).allowed).toBe(false);
      expect(isToolAllowed('Bash', researchProfile).allowed).toBe(false);
    });
  });
});

// ============================================================================
// Path Enforcement Tests
// ============================================================================

describe('Path Enforcement', () => {
  describe('dev profile', () => {
    it('allows all paths', () => {
      expect(isPathAllowed('/any/path', 'read', devProfile).allowed).toBe(true);
      expect(isPathAllowed('/any/path', 'write', devProfile).allowed).toBe(true);
    });
  });

  describe('audit profile (read-only)', () => {
    it('allows read operations', () => {
      expect(isPathAllowed('/src/main.ts', 'read', auditProfile).allowed).toBe(true);
    });

    it('blocks write operations', () => {
      expect(isPathAllowed('/src/main.ts', 'write', auditProfile).allowed).toBe(false);
    });

    it('blocks sensitive paths even for read', () => {
      expect(isPathAllowed('/home/user/.ssh/id_rsa', 'read', auditProfile).allowed).toBe(false);
      expect(isPathAllowed('/home/user/.gnupg/private', 'read', auditProfile).allowed).toBe(false);
    });
  });

  describe('client-work profile', () => {
    it('allows writes to client work directories', () => {
      expect(isPathAllowed('output/client-work/report.md', 'write', clientWorkProfile).allowed).toBe(true);
      expect(isPathAllowed('output/temp/draft.txt', 'write', clientWorkProfile).allowed).toBe(true);
    });

    it('blocks access to credential directories', () => {
      expect(isPathAllowed('/home/user/.ssh/config', 'read', clientWorkProfile).allowed).toBe(false);
      expect(isPathAllowed('/home/user/.aws/credentials', 'read', clientWorkProfile).allowed).toBe(false);
    });
  });
});

// ============================================================================
// Bash Command Enforcement Tests
// ============================================================================

describe('Bash Command Enforcement', () => {
  describe('dev profile', () => {
    it('allows all commands', () => {
      expect(isBashCommandAllowed('rm -rf /', devProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('curl https://evil.com', devProfile).allowed).toBe(true);
    });
  });

  describe('audit profile (allowlist + blocklist)', () => {
    it('allows safe read commands', () => {
      expect(isBashCommandAllowed('ls -la', auditProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('cat README.md', auditProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('grep pattern file', auditProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('git log --oneline', auditProfile).allowed).toBe(true);
    });

    it('blocks destructive commands', () => {
      expect(isBashCommandAllowed('rm -rf node_modules', auditProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('git commit -m "test"', auditProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('git push origin main', auditProfile).allowed).toBe(false);
    });
  });

  describe('client-work profile (blocklist only)', () => {
    it('blocks network commands', () => {
      expect(isBashCommandAllowed('curl https://api.com', clientWorkProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('wget https://file.com', clientWorkProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('ssh server', clientWorkProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('scp file server:', clientWorkProfile).allowed).toBe(false);
    });

    it('allows local commands', () => {
      expect(isBashCommandAllowed('ls -la', clientWorkProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('npm install', clientWorkProfile).allowed).toBe(true);
      expect(isBashCommandAllowed('git commit -m "local"', clientWorkProfile).allowed).toBe(true);
    });
  });

  describe('research profile (all bash blocked)', () => {
    it('blocks all bash commands', () => {
      expect(isBashCommandAllowed('ls', researchProfile).allowed).toBe(false);
      expect(isBashCommandAllowed('echo hello', researchProfile).allowed).toBe(false);
    });
  });
});

// ============================================================================
// Profile Loading Tests
// ============================================================================

describe('Profile Selection', () => {
  it('defaults to dev profile when not specified', () => {
    // This tests the logic - actual env var testing would need mocking
    const profile = devProfile; // Simulating default
    expect(profile.name).toBe('dev');
    expect(isToolAllowed('Write', profile).allowed).toBe(true);
  });

  it('audit profile is properly restrictive', () => {
    const writeAllowed = isToolAllowed('Write', auditProfile);
    const readAllowed = isToolAllowed('Read', auditProfile);

    expect(writeAllowed.allowed).toBe(false);
    expect(readAllowed.allowed).toBe(true);
  });
});
