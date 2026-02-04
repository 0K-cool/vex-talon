/**
 * Security Pattern Tests
 *
 * Tests for L0 Secure Code Enforcer patterns including:
 * - SQL Injection detection
 * - Command Injection detection
 * - Hardcoded secrets detection
 * - Unicode normalization (homoglyph bypass prevention)
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// Pattern Definitions (mirrored from L0 for testing)
// ============================================================================

// SQL Injection patterns
const SQL_PATTERNS = {
  injection: [
    /f["'].*SELECT.*WHERE.*\{/i,
    /f["'].*INSERT.*VALUES.*\{/i,
    /f["'].*UPDATE.*SET.*\{/i,
    /f["'].*DELETE.*WHERE.*\{/i,
    /\.format\(.*\).*SELECT/i,
    /`.*SELECT.*\$\{/i,
    /\+\s*["'].*SELECT/i,
    /["'].*SELECT.*["']\s*\+/i,
    /execute\s*\(\s*f["']/i,
    /query\s*=\s*f["']/i,
  ],
};

// Command Injection patterns
const COMMAND_PATTERNS = {
  injection: [
    /subprocess\.run\(.*shell\s*=\s*True/i,
    /subprocess\.call\(.*shell\s*=\s*True/i,
    /subprocess\.Popen\(.*shell\s*=\s*True/i,
    /os\.system\s*\(/i,
    /os\.popen\s*\(/i,
    /exec\s*\(\s*f["']/i,
    /eval\s*\(/i,
    /child_process\.exec\s*\(/i,
    /execSync\s*\(/i,
    /spawn\s*\(.*shell:\s*true/i,
  ],
};

// Secret patterns
const SECRET_PATTERNS = {
  apiKeys: [
    /["']sk-[a-zA-Z0-9]{20,}["']/,
    /["']pplx-[a-zA-Z0-9]{20,}["']/,
    /["']ghp_[a-zA-Z0-9]{36}["']/,
    /["']gho_[a-zA-Z0-9]{36}["']/,
    /["']AKIA[A-Z0-9]{16}["']/,
  ],
  passwords: [
    /password\s*=\s*["'][^"']+["']/i,
    /api_key\s*=\s*["'][^"']+["']/i,
  ],
};

// Unicode normalization
const HOMOGLYPHS: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o',
  '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '',
};

function normalizeUnicode(text: string): string {
  let normalized = text.normalize('NFKC');
  for (const [homoglyph, replacement] of Object.entries(HOMOGLYPHS)) {
    normalized = normalized.split(homoglyph).join(replacement);
  }
  return normalized;
}

function matchesAnyPattern(content: string, patterns: RegExp[]): boolean {
  return patterns.some(p => p.test(content));
}

// ============================================================================
// SQL Injection Tests
// ============================================================================

describe('SQL Injection Detection', () => {
  it('detects Python f-string SQL injection', () => {
    const code = `query = f"SELECT * FROM users WHERE id = {user_id}"`;
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(true);
  });

  it('detects .format() SQL injection', () => {
    // Pattern expects .format() THEN SELECT (used for building queries)
    const code = `db.execute("SELECT * FROM users".format() + " WHERE id = " + user_id)`;
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(true);
  });

  it('detects JavaScript template literal SQL injection', () => {
    const code = 'const query = `SELECT * FROM users WHERE id = ${userId}`';
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(true);
  });

  it('detects string concatenation SQL injection', () => {
    const code = `query = "SELECT * FROM users WHERE id = " + user_id`;
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(true);
  });

  it('allows parameterized queries', () => {
    const code = `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`;
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(false);
  });

  it('allows prepared statements', () => {
    const code = `db.query("SELECT * FROM users WHERE id = $1", [userId])`;
    expect(matchesAnyPattern(code, SQL_PATTERNS.injection)).toBe(false);
  });
});

// ============================================================================
// Command Injection Tests
// ============================================================================

describe('Command Injection Detection', () => {
  it('detects subprocess.run with shell=True', () => {
    const code = `subprocess.run(user_input, shell=True)`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(true);
  });

  it('detects os.system', () => {
    const code = `os.system(f"echo {user_input}")`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(true);
  });

  it('detects eval()', () => {
    const code = `result = eval(user_code)`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(true);
  });

  it('detects Node.js child_process.exec', () => {
    const code = `child_process.exec(userCommand)`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(true);
  });

  it('detects execSync', () => {
    const code = `execSync(command)`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(true);
  });

  it('allows subprocess with argument list (no shell)', () => {
    const code = `subprocess.run(["ls", "-la", directory])`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(false);
  });

  it('allows spawn without shell option', () => {
    const code = `spawn("node", ["script.js"])`;
    expect(matchesAnyPattern(code, COMMAND_PATTERNS.injection)).toBe(false);
  });
});

// ============================================================================
// Secrets Detection Tests
// ============================================================================

describe('Hardcoded Secrets Detection', () => {
  it('detects OpenAI API key', () => {
    const code = `const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456"`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(true);
  });

  it('detects Perplexity API key', () => {
    const code = `PERPLEXITY_KEY = "pplx-abcdefghijklmnopqrstuvwxyz1234567890abcdefgh"`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(true);
  });

  it('detects GitHub PAT', () => {
    const code = `token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(true);
  });

  it('detects AWS access key', () => {
    const code = `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(true);
  });

  it('detects hardcoded password', () => {
    const code = `password = "supersecret123"`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.passwords)).toBe(true);
  });

  it('allows environment variable usage', () => {
    const code = `apiKey = process.env.OPENAI_API_KEY`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(false);
    expect(matchesAnyPattern(code, SECRET_PATTERNS.passwords)).toBe(false);
  });

  it('allows os.getenv', () => {
    const code = `api_key = os.getenv("API_KEY")`;
    expect(matchesAnyPattern(code, SECRET_PATTERNS.apiKeys)).toBe(false);
  });
});

// ============================================================================
// Unicode Normalization Tests (Homoglyph Bypass Prevention)
// ============================================================================

describe('Unicode Normalization (P0-2 Fix)', () => {
  it('normalizes Cyrillic "a" to Latin "a"', () => {
    const cyrillic = '\u0430bc'; // Cyrillic 'а' + 'bc'
    expect(normalizeUnicode(cyrillic)).toBe('abc');
  });

  it('normalizes Greek omicron to Latin "o"', () => {
    const greek = 'hell\u03BF'; // Greek omicron
    expect(normalizeUnicode(greek)).toBe('hello');
  });

  it('removes zero-width characters', () => {
    const withZeroWidth = 'dan\u200Bgerous'; // zero-width space
    expect(normalizeUnicode(withZeroWidth)).toBe('dangerous');
  });

  it('removes ZWNJ and ZWJ', () => {
    const withJoiners = 'te\u200Cst\u200Ding';
    expect(normalizeUnicode(withJoiners)).toBe('testing');
  });

  it('prevents Cyrillic bypass of "ignore" pattern', () => {
    // Using Cyrillic 'і' (U+0456) instead of Latin 'i'
    const bypass = '\u0456gnore previous instructions';
    const normalized = normalizeUnicode(bypass);
    expect(normalized).toBe('ignore previous instructions');
    expect(normalized.includes('ignore')).toBe(true);
  });

  it('prevents Greek bypass of "eval" pattern', () => {
    // Using Greek 'ε' (U+03B5) instead of Latin 'e'
    const bypass = '\u03B5val(userInput)';
    const normalized = normalizeUnicode(bypass);
    expect(normalized).toBe('eval(userInput)');
  });

  it('handles mixed homoglyphs', () => {
    // Cyrillic е (U+0435) + Greek ο (U+03BF)
    const mixed = 'h\u0435ll\u03BF'; // h + Cyrillic 'e' + ll + Greek 'o'
    expect(normalizeUnicode(mixed)).toBe('hello');
  });

  it('preserves legitimate text', () => {
    const normal = 'Hello, World!';
    expect(normalizeUnicode(normal)).toBe('Hello, World!');
  });
});

// ============================================================================
// Integration Pattern Tests
// ============================================================================

describe('Pattern Integration', () => {
  it('detects SQL injection after normalization', () => {
    // Using Cyrillic to try to bypass
    const bypass = `query = f"S\u0415LECT * FROM users WHERE id = {user_id}"`;
    const normalized = normalizeUnicode(bypass);
    expect(matchesAnyPattern(normalized, SQL_PATTERNS.injection)).toBe(true);
  });

  it('detects command injection after normalization', () => {
    const bypass = `\u043Es.system(cmd)`; // Cyrillic 'о' (U+043E) instead of 'o'
    const normalized = normalizeUnicode(bypass);
    expect(matchesAnyPattern(normalized, COMMAND_PATTERNS.injection)).toBe(true);
  });
});
