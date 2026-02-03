#!/usr/bin/env node
/**
 * Vex-Talon Unified Security Config Loader
 * @version 0.1.0
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, dirname } from 'path';

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

export interface InjectionPattern {
  id: string;
  category: 'instruction_override' | 'jailbreak' | 'encoding' | 'context_manipulation';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  description: string;
  examples?: string[];
}

export interface InjectionConfig extends SecurityConfig<InjectionPattern[]> {}

export interface VulnerabilityPattern {
  id: string;
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation?: string;
  owaspMapping?: string;
}

export interface CodeEnforcerConfig extends SecurityConfig<{
  sqlInjection: VulnerabilityPattern[];
  commandInjection: VulnerabilityPattern[];
  secretPatterns: VulnerabilityPattern[];
  pathTraversal: VulnerabilityPattern[];
  unsafeDeserialization: VulnerabilityPattern[];
  promptInjection: VulnerabilityPattern[];
  xssVectors: VulnerabilityPattern[];
  weakCrypto: VulnerabilityPattern[];
  authPatterns: VulnerabilityPattern[];
  codeExtensions?: Record<string, string>;
}> {
  skipPaths?: string[];
}

export interface MaliciousPackage {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  severity: 'CRITICAL' | 'HIGH';
  reason: string;
  dateAdded: string;
}

export interface SupplyChainConfig extends SecurityConfig<{
  maliciousPackages: MaliciousPackage[];
  trustedRegistries: string[];
  auditThresholds: { critical: number; high: number; moderate: number };
}> {}

const configCache = new Map<string, { config: unknown; loadedAt: number; fileMtime: number }>();
const CACHE_TTL_MS = 60000;

function getConfigBasePath(): string {
  if (process.env.VEX_TALON_CONFIG_PATH) return process.env.VEX_TALON_CONFIG_PATH;
  const projectPath = join(process.cwd(), '.vex-talon', 'configs');
  if (existsSync(projectPath)) return projectPath;
  return join(dirname(__dirname), 'configs');
}

const CONFIG_BASE_PATH = getConfigBasePath();

export function loadConfig<T>(configPath: string, defaultConfig: T): T {
  const fullPath = join(CONFIG_BASE_PATH, configPath);
  const cached = configCache.get(fullPath);
  if (cached && Date.now() - cached.loadedAt < CACHE_TTL_MS) {
    try {
      if (statSync(fullPath).mtimeMs === cached.fileMtime) return cached.config as T;
    } catch { return cached.config as T; }
  }
  if (existsSync(fullPath)) {
    try {
      const parsed = JSON.parse(readFileSync(fullPath, 'utf-8'));
      const stat = statSync(fullPath);
      configCache.set(fullPath, { config: parsed, loadedAt: Date.now(), fileMtime: stat.mtimeMs });
      return parsed as T;
    } catch { /* fall through */ }
  }
  configCache.set(fullPath, { config: defaultConfig, loadedAt: Date.now(), fileMtime: 0 });
  return defaultConfig;
}

export function clearConfigCache(): void { configCache.clear(); }

export function compilePattern(pattern: string, flags = 'gi'): RegExp {
  return new RegExp(pattern, flags);
}

export function loadInjectionConfig(): InjectionConfig {
  return loadConfig('injection/patterns.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: 'Vex-Talon defaults' },
    patterns: [],
  });
}

export function loadCodeEnforcerConfig(): CodeEnforcerConfig {
  return loadConfig('code-enforcer/patterns.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: 'Vex-Talon defaults' },
    patterns: {
      sqlInjection: [], commandInjection: [], secretPatterns: [], pathTraversal: [],
      unsafeDeserialization: [], promptInjection: [], xssVectors: [], weakCrypto: [], authPatterns: [],
    },
  });
}

export function loadSupplyChainConfig(): SupplyChainConfig {
  return loadConfig('supply-chain/config.json', {
    metadata: { version: '0.1.0', lastUpdated: '2026-02-03', description: 'Vex-Talon defaults' },
    patterns: {
      maliciousPackages: [],
      trustedRegistries: ['registry.npmjs.org', 'pypi.org', 'crates.io'],
      auditThresholds: { critical: 0, high: 0, moderate: 5 },
    },
  });
}

export { CONFIG_BASE_PATH };
