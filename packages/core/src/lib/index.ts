/**
 * Vex-Talon Shared Libraries
 */

// Config loader exports
export {
  type ConfigMetadata,
  type InjectionPattern,
  type InjectionConfig,
  type VulnerabilityPattern,
  type CodeEnforcerConfig,
  loadConfig,
  loadInjectionConfig,
  loadCodeEnforcerConfig,
  loadSupplyChainConfig,
  compilePattern,
  clearConfigCache,
  CONFIG_BASE_PATH,
} from './config-loader';

// Injection patterns exports
export {
  type InjectionCategory,
  type InjectionSeverity,
  type ScanResult,
  type InjectionMatch,
  type ExtendedScanResult,
  INJECTION_PATTERNS,
  getActivePatterns,
  reloadPatterns,
  scanForInjections,
  hasInjectionPatterns,
  normalizeForScanning,
  hasUnicodeObfuscation,
  getScanSummary,
} from './injection-patterns';
