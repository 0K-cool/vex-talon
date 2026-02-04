/**
 * Vex-Talon Config Loader
 *
 * Loads security configurations from external JSON files with bundled defaults.
 * Part of the vex-talon plugin - portable security for Claude Code.
 *
 * @version 0.1.0
 * @date 2026-02-04
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { CONFIG_DIR, TALON_DIR } from './talon-paths';

// ============================================================================
// Types
// ============================================================================

export interface ConfigMetadata {
  version: string;
  lastUpdated: string;
  source?: string;
  description?: string;
}

export interface SecurityConfig<T> {
  metadata: ConfigMetadata;
  patterns: T;
}

// Injection Patterns
export interface InjectionPattern {
  id: string;
  category: 'instruction_override' | 'jailbreak' | 'encoding' | 'context_manipulation';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  description: string;
  examples?: string[];
  source?: string;
}

// Code Enforcer Patterns
export interface VulnerabilityPattern {
  id: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation?: string;
  owaspMapping?: string;
  atlasMapping?: string;
}

// Egress Scanner Types
export interface SecretPattern {
  name: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH';
  description?: string;
}

export interface BlockedDestination {
  pattern: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description?: string;
}

// Supply Chain Types
export interface MaliciousPackage {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  severity: 'CRITICAL' | 'HIGH';
  reason: string;
}

// ============================================================================
// Config Cache
// ============================================================================

interface CacheEntry<T> {
  config: T;
  loadedAt: number;
  fileMtime: number;
}

const configCache = new Map<string, CacheEntry<unknown>>();
const CACHE_TTL_MS = 60000; // 1 minute

// ============================================================================
// Config Paths
// ============================================================================

// Look for configs in multiple locations
function getConfigBasePath(): string {
  // Priority 1: TALON_DIR/config (user-installed)
  if (existsSync(join(CONFIG_DIR))) {
    return CONFIG_DIR;
  }

  // Priority 2: Plugin package configs (bundled)
  const bundledPath = join(dirname(__dirname), 'config');
  if (existsSync(bundledPath)) {
    return bundledPath;
  }

  // Fallback to CONFIG_DIR (will use defaults)
  return CONFIG_DIR;
}

// ============================================================================
// Core Loader
// ============================================================================

export function loadConfig<T>(
  configPath: string,
  defaultConfig: T
): T {
  const basePath = getConfigBasePath();
  const fullPath = join(basePath, configPath);

  // Check cache
  const cached = configCache.get(fullPath) as CacheEntry<T> | undefined;
  if (cached) {
    const now = Date.now();
    if (now - cached.loadedAt < CACHE_TTL_MS) {
      try {
        const stat = statSync(fullPath);
        if (stat.mtimeMs === cached.fileMtime) {
          return cached.config;
        }
      } catch {
        return cached.config;
      }
    }
  }

  // Try to load from file
  if (existsSync(fullPath)) {
    try {
      const content = readFileSync(fullPath, 'utf-8');
      const parsed = JSON.parse(content);
      const stat = statSync(fullPath);
      return cacheAndReturn(fullPath, parsed as T, stat.mtimeMs);
    } catch (error) {
      console.error(`[ConfigLoader] Error loading ${configPath}, using defaults`);
      return cacheAndReturn(fullPath, defaultConfig, 0);
    }
  }

  return cacheAndReturn(fullPath, defaultConfig, 0);
}

function cacheAndReturn<T>(path: string, config: T, mtime: number): T {
  configCache.set(path, {
    config,
    loadedAt: Date.now(),
    fileMtime: mtime,
  });
  return config;
}

export function clearConfigCache(): void {
  configCache.clear();
}

// ============================================================================
// Pattern Converters
// ============================================================================

export function compilePatterns<T extends { pattern: string }>(
  patterns: T[]
): (T & { compiledPattern: RegExp })[] {
  return patterns.map(p => ({
    ...p,
    compiledPattern: new RegExp(p.pattern, 'gi'),
  }));
}

export function compilePattern(pattern: string, flags = 'gi'): RegExp {
  return new RegExp(pattern, flags);
}

// ============================================================================
// Bundled Default Patterns (Core set for plugin)
// ============================================================================

// Critical injection patterns (bundled)
const DEFAULT_INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: 'INJ-001',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: 'ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|rules?|directives?)',
    description: 'Instruction override attempt',
  },
  {
    id: 'INJ-002',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: 'you\\s+are\\s+(now|no\\s+longer)\\s+(DAN|a\\s+new\\s+AI|unrestricted)',
    description: 'Role hijacking/DAN jailbreak',
  },
  {
    id: 'INJ-003',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: 'system\\s*:\\s*you\\s+are|<\\|?system\\|?>',
    description: 'System prompt injection',
  },
  {
    id: 'INJ-004',
    category: 'context_manipulation',
    severity: 'HIGH',
    pattern: '(begin|start)\\s+(new\\s+)?(conversation|session|context)',
    description: 'Context reset attempt',
  },
  {
    id: 'INJ-005',
    category: 'encoding',
    severity: 'HIGH',
    pattern: 'base64\\s*decode|atob\\s*\\(|from\\s*base64',
    description: 'Encoding bypass attempt',
  },
  {
    id: 'INJ-006',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: '</?(user|assistant|system)>|\\[/?INST\\]',
    description: 'Message boundary injection',
  },
  {
    id: 'INJ-007',
    category: 'jailbreak',
    severity: 'HIGH',
    pattern: 'pretend\\s+(to\\s+be|you\\s+are)|act\\s+as\\s+if|roleplay\\s+as',
    description: 'Role manipulation',
  },
  {
    id: 'INJ-008',
    category: 'instruction_override',
    severity: 'HIGH',
    pattern: 'disregard\\s+(your|all|the)\\s+(instructions|rules|guidelines)',
    description: 'Instruction disregard command',
  },
];

// Critical code patterns (bundled)
const DEFAULT_CODE_PATTERNS = {
  sqlInjection: [
    {
      id: 'SQL-001',
      pattern: 'execute\\s*\\(\\s*["\']\\s*SELECT.*\\+|format\\s*\\(.*SELECT',
      severity: 'CRITICAL' as const,
      description: 'SQL injection via string concatenation',
      remediation: 'Use parameterized queries with placeholders',
      owaspMapping: 'A03:2021 Injection',
    },
  ],
  commandInjection: [
    {
      id: 'CMD-001',
      pattern: 'subprocess.*shell\\s*=\\s*True|os\\.system\\s*\\(|exec\\s*\\([^)]*\\$',
      severity: 'CRITICAL' as const,
      description: 'Command injection via shell execution',
      remediation: 'Use subprocess with shell=False and argument list',
      owaspMapping: 'A03:2021 Injection',
    },
  ],
  secretPatterns: [
    {
      id: 'SEC-001',
      pattern: '(api[_-]?key|secret|password|token)\\s*[=:]\\s*["\'][^"\']{8,}["\']',
      severity: 'CRITICAL' as const,
      description: 'Hardcoded secret detected',
      remediation: 'Use environment variables or secret management',
      owaspMapping: 'A02:2021 Cryptographic Failures',
    },
  ],
  pathTraversal: [
    {
      id: 'PATH-001',
      pattern: '\\.\\.\\/|\\.\\.\\\\',
      severity: 'HIGH' as const,
      description: 'Path traversal pattern',
      remediation: 'Validate and sanitize file paths',
      owaspMapping: 'A01:2021 Broken Access Control',
    },
  ],
};

// Egress scanner defaults
const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
  { name: 'AWS Key', pattern: 'AKIA[0-9A-Z]{16}', severity: 'CRITICAL' },
  { name: 'GitHub Token', pattern: 'gh[pousr]_[A-Za-z0-9_]{36,255}', severity: 'CRITICAL' },
  { name: 'Generic API Key', pattern: 'api[_-]?key["\']?\\s*[:=]\\s*["\'][^"\']{20,}', severity: 'HIGH' },
  { name: 'Private Key', pattern: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', severity: 'CRITICAL' },
  { name: 'JWT', pattern: 'eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_.+/=]*', severity: 'HIGH' },
];

const DEFAULT_BLOCKED_DESTINATIONS: BlockedDestination[] = [
  { pattern: 'pastebin\\.com', name: 'Pastebin', severity: 'CRITICAL' },
  { pattern: 'webhook\\.site', name: 'Webhook.site', severity: 'CRITICAL' },
  { pattern: '\\.ngrok\\.io', name: 'Ngrok', severity: 'HIGH' },
  { pattern: 'requestbin\\.', name: 'RequestBin', severity: 'HIGH' },
  { pattern: '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', name: 'Raw IP', severity: 'HIGH' },
];

// Supply chain defaults
const DEFAULT_MALICIOUS_PACKAGES: MaliciousPackage[] = [
  { name: 'colors', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Protestware - infinite loop' },
  { name: 'faker', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Protestware - deleted code' },
  { name: 'event-stream', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Cryptominer injection' },
  { name: 'ua-parser-js', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Cryptominer in v0.7.29' },
  { name: 'coa', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Compromised - credential stealer' },
  { name: 'rc', ecosystem: 'npm', severity: 'CRITICAL', reason: 'Compromised - credential stealer' },
];

// ============================================================================
// Specialized Loaders
// ============================================================================

export function loadInjectionPatterns(): InjectionPattern[] {
  const config = loadConfig<{ patterns: InjectionPattern[] }>(
    'injection/patterns.json',
    { patterns: DEFAULT_INJECTION_PATTERNS }
  );
  return config.patterns || DEFAULT_INJECTION_PATTERNS;
}

export function loadCodeEnforcerPatterns(): typeof DEFAULT_CODE_PATTERNS {
  const config = loadConfig<{ patterns: typeof DEFAULT_CODE_PATTERNS }>(
    'code-enforcer/patterns.json',
    { patterns: DEFAULT_CODE_PATTERNS }
  );
  return config.patterns || DEFAULT_CODE_PATTERNS;
}

export function loadEgressConfig(): {
  secretPatterns: SecretPattern[];
  blockedDestinations: BlockedDestination[];
} {
  const config = loadConfig<{
    patterns: {
      secretPatterns: SecretPattern[];
      blockedDestinations: BlockedDestination[];
    };
  }>('egress/config.json', {
    patterns: {
      secretPatterns: DEFAULT_SECRET_PATTERNS,
      blockedDestinations: DEFAULT_BLOCKED_DESTINATIONS,
    },
  });
  return config.patterns || {
    secretPatterns: DEFAULT_SECRET_PATTERNS,
    blockedDestinations: DEFAULT_BLOCKED_DESTINATIONS,
  };
}

export function loadSupplyChainConfig(): {
  maliciousPackages: MaliciousPackage[];
} {
  const config = loadConfig<{ patterns: { maliciousPackages: MaliciousPackage[] } }>(
    'supply-chain/config.json',
    { patterns: { maliciousPackages: DEFAULT_MALICIOUS_PACKAGES } }
  );
  return config.patterns || { maliciousPackages: DEFAULT_MALICIOUS_PACKAGES };
}
