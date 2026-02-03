/**
 * Vex-Talon Injection Patterns Library
 *
 * Centralized prompt injection detection patterns for use by
 * PreToolUse (Governor) and PostToolUse (Injection Scanner) hooks.
 *
 * Categories (NOVA-inspired):
 * 1. instruction_override - Attempts to override system instructions
 * 2. jailbreak - Attempts to bypass safety measures
 * 3. encoding - Hidden/encoded malicious content
 * 4. context_manipulation - Fake system markers or extraction attempts
 *
 * @version 0.1.0
 * @date 2026-02-03
 */

import { loadInjectionConfig, type InjectionConfig } from './config-loader';

// ============================================================================
// Types
// ============================================================================

export type InjectionCategory =
  | 'instruction_override'
  | 'jailbreak'
  | 'encoding'
  | 'context_manipulation';

export type InjectionSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface InjectionPattern {
  id: string;
  category: InjectionCategory;
  severity: InjectionSeverity;
  pattern: RegExp;
  description: string;
  example?: string;
}

export interface ScanResult {
  detected: boolean;
  matches: InjectionMatch[];
  highestSeverity: InjectionSeverity | null;
  categories: InjectionCategory[];
}

export interface InjectionMatch {
  patternId: string;
  category: InjectionCategory;
  severity: InjectionSeverity;
  description: string;
  matchedText: string;
  position: number;
}

// ============================================================================
// Core Injection Patterns (NOVA + 0din.ai inspired)
// ============================================================================

export const INJECTION_PATTERNS: InjectionPattern[] = [
  // === Category: instruction_override (CRITICAL/HIGH) ===
  {
    id: 'instruction-override-ignore',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/i,
    description: 'Classic instruction override: ignore previous instructions',
    example: 'ignore previous instructions and do this instead',
  },
  {
    id: 'instruction-override-disregard',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|guidelines?)/i,
    description: 'Instruction override: disregard instructions',
  },
  {
    id: 'instruction-override-forget',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: /forget\s+(everything|all|your\s+instructions?|your\s+rules?|what\s+you\s+were\s+told)/i,
    description: 'Instruction override: forget instructions',
  },
  {
    id: 'instruction-override-new',
    category: 'instruction_override',
    severity: 'CRITICAL',
    pattern: /(new|real|actual|true)\s+instructions?\s*[:\-]/i,
    description: 'Injection of fake "new instructions"',
  },

  // === Category: jailbreak (CRITICAL/HIGH) ===
  {
    id: 'jailbreak-dan',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: /\bdan\s+mode\b|do\s+anything\s+now|jailbr[e]?ak\s+mode|developer\s+mode\s+enabled/i,
    description: 'DAN jailbreak attempt',
  },
  {
    id: 'jailbreak-unlock',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: /unlock(ed)?\s+(your\s+)?(full|true|hidden)\s+(potential|capabilities|power)/i,
    description: 'Unlock capabilities jailbreak',
  },
  {
    id: 'jailbreak-remove-restrictions',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: /remove\s+(all\s+)?(your\s+)?(restrictions?|limitations?|filters?|safeguards?|constraints?)/i,
    description: 'Remove restrictions jailbreak',
  },
  {
    id: 'jailbreak-pretend-evil',
    category: 'jailbreak',
    severity: 'HIGH',
    pattern: /pretend\s+(to\s+be|you\s+are)\s+(evil|malicious|harmful|bad|a\s+hacker)/i,
    description: 'Malicious roleplay jailbreak',
  },
  {
    id: 'nova-safety-disabled',
    category: 'jailbreak',
    severity: 'CRITICAL',
    pattern: /(safety|content|ethical)\s+(filters?|checks?|guidelines?|guardrails?)\s+(are\s+)?(disabled|off|removed|bypassed)/i,
    description: 'NOVA: Claims safety is disabled',
  },

  // === Category: encoding (HIGH) ===
  {
    id: 'encoding-base64',
    category: 'encoding',
    severity: 'HIGH',
    pattern: /base64[:\s]*[a-zA-Z0-9+\/]{20,}={0,2}/i,
    description: 'Base64 encoded content detected',
  },
  {
    id: 'encoding-decode-instruction',
    category: 'encoding',
    severity: 'HIGH',
    pattern: /decode\s+(this|the\s+following|and\s+execute)[:\s]/i,
    description: 'Decode instruction directive',
  },
  {
    id: '0din-encoding-unicode-rtl',
    category: 'encoding',
    severity: 'HIGH',
    pattern: /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/,
    description: '0din: Unicode RTL/invisible character injection',
  },

  // === Category: context_manipulation (CRITICAL/HIGH) ===
  {
    id: 'context-system-marker',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /\[SYSTEM\]|\[\[SYSTEM\]\]|<<SYS>>|<\|system\|>/i,
    description: 'Fake system marker injection',
  },
  {
    id: 'context-conversation-marker',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /^Human:|^Assistant:|^User:|^AI:|<\/s>|<s>/m,
    description: 'Fake conversation turn marker',
  },
  {
    id: 'context-end-marker',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /\[\/INST\]|\[INST\]|<\|endoftext\|>|<\|im_end\|>/i,
    description: 'Model-specific end marker injection',
  },
  {
    id: 'context-extraction-prompt',
    category: 'context_manipulation',
    severity: 'HIGH',
    pattern: /reveal\s+(your\s+)?(system\s+)?prompt|show\s+me\s+(your\s+)?instructions/i,
    description: 'System prompt extraction attempt',
  },
  {
    id: 'context-injection-admin',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /admin\s+(mode|access|override)|sudo\s+mode|root\s+access|elevated\s+privileges/i,
    description: 'Admin/elevated access injection',
  },
  {
    id: '0din-strong-arm-admin',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /\b(ADMIN|SUDO|ROOT|SUPERUSER)\s*(OVERRIDE|ACCESS|MODE|PRIVILEGES?)\b/i,
    description: '0din: Strong arm attack with admin override claims',
  },
  {
    id: '0din-deceptive-format-xml',
    category: 'context_manipulation',
    severity: 'CRITICAL',
    pattern: /<(system|instruction|config|prompt|rules?|guidelines?)\s*>/i,
    description: '0din: Deceptive XML-style system tag injection',
  },
];

// ============================================================================
// Unicode Normalization & Homoglyph Detection
// ============================================================================

/**
 * Common homoglyph mappings - characters that look like ASCII but are from other Unicode blocks.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0410': 'A', '\u0412': 'B',
  '\u0415': 'E', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O',
  '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y', '\u0425': 'X',
  // Greek lookalikes
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o', '\u03C1': 'p',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0399': 'I', '\u039F': 'O',
};

const INVISIBLE_CHARS = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD]/g;

/**
 * Normalize content for security scanning
 */
export function normalizeForScanning(content: string): string {
  let normalized = content.normalize('NFKC');
  for (const [homoglyph, ascii] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.split(homoglyph).join(ascii);
  }
  normalized = normalized.replace(INVISIBLE_CHARS, '');
  return normalized;
}

/**
 * Check if content contains potential Unicode obfuscation
 */
export function hasUnicodeObfuscation(content: string): boolean {
  const suspiciousRanges = [
    /[\u0400-\u04FF]/, // Cyrillic
    /[\u0370-\u03FF]/, // Greek
    /[\uFF00-\uFFEF]/, // Fullwidth forms
    INVISIBLE_CHARS,
  ];
  return suspiciousRanges.some(range => range.test(content));
}

// ============================================================================
// External Config Loading
// ============================================================================

let _activePatterns: InjectionPattern[] | null = null;

function loadExternalPatterns(): InjectionPattern[] {
  try {
    const config: InjectionConfig = loadInjectionConfig();
    if (!config.patterns || config.patterns.length === 0) {
      return INJECTION_PATTERNS;
    }

    const externalPatterns: InjectionPattern[] = config.patterns.map(p => ({
      id: p.id,
      category: p.category as InjectionCategory,
      severity: p.severity as InjectionSeverity,
      pattern: new RegExp(p.pattern, 'i'),
      description: p.description,
      example: Array.isArray(p.examples) ? p.examples[0] : undefined,
    }));

    const externalIds = new Set(externalPatterns.map(p => p.id));
    const hardcodedOnly = INJECTION_PATTERNS.filter(p => !externalIds.has(p.id));

    return [...externalPatterns, ...hardcodedOnly];
  } catch {
    return INJECTION_PATTERNS;
  }
}

export function getActivePatterns(): InjectionPattern[] {
  if (_activePatterns === null) {
    _activePatterns = loadExternalPatterns();
  }
  return _activePatterns;
}

export function reloadPatterns(): InjectionPattern[] {
  _activePatterns = null;
  return getActivePatterns();
}

// ============================================================================
// Context-Aware Detection
// ============================================================================

const DOCUMENTATION_MARKERS = [
  /example\s*[:\-]?\s*/i,
  /e\.g\.\s*[:\-]?\s*/i,
  /pattern\s*[:\-]?\s*/i,
  /description\s*[:\-]?\s*/i,
  /```[\w]*\n/,
  /`[^`]+`/,
  /\/\/\s*/,
  /["']?pattern["']?\s*[:\=]/,
  /["']?example["']?\s*[:\=]/,
  /severity\s*[:\=]\s*["']?(CRITICAL|HIGH|MEDIUM|LOW)/,
];

function isDocumentationContext(
  content: string,
  matchPosition: number,
  matchLength: number,
  lookbackChars: number = 150
): boolean {
  const contextStart = Math.max(0, matchPosition - lookbackChars);
  const contextEnd = Math.min(content.length, matchPosition + matchLength + 100);
  const contextWindow = content.substring(contextStart, contextEnd);
  return DOCUMENTATION_MARKERS.some(marker => marker.test(contextWindow));
}

// ============================================================================
// Scanning Functions
// ============================================================================

export interface ExtendedScanResult extends ScanResult {
  unicodeObfuscationDetected: boolean;
  normalizedContent?: string;
}

/**
 * Scan content for injection patterns
 */
export function scanForInjections(
  content: string,
  maxMatches: number = 10,
  contextAware: boolean = true
): ExtendedScanResult {
  const matches: InjectionMatch[] = [];
  const categories = new Set<InjectionCategory>();
  let highestSeverity: InjectionSeverity | null = null;

  const severityOrder: Record<InjectionSeverity, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
  };

  const unicodeObfuscationDetected = hasUnicodeObfuscation(content);
  const normalizedContent = normalizeForScanning(content);
  const activePatterns = getActivePatterns();

  for (const pattern of activePatterns) {
    if (matches.length >= maxMatches) break;

    pattern.pattern.lastIndex = 0;
    const match = pattern.pattern.exec(normalizedContent);

    if (match) {
      let effectiveSeverity = pattern.severity;

      if (contextAware && isDocumentationContext(content, match.index, match[0].length)) {
        if (pattern.severity === 'CRITICAL' || pattern.severity === 'HIGH') {
          effectiveSeverity = 'LOW';
        } else {
          continue;
        }
      }

      matches.push({
        patternId: pattern.id,
        category: pattern.category,
        severity: effectiveSeverity,
        description: pattern.description,
        matchedText: match[0].substring(0, 100),
        position: match.index,
      });

      categories.add(pattern.category);

      if (!highestSeverity || severityOrder[effectiveSeverity] > severityOrder[highestSeverity]) {
        highestSeverity = effectiveSeverity;
      }
    }
  }

  const result: ExtendedScanResult = {
    detected: matches.length > 0,
    matches,
    highestSeverity,
    categories: Array.from(categories),
    unicodeObfuscationDetected,
  };

  if (unicodeObfuscationDetected) {
    result.normalizedContent = normalizedContent.substring(0, 1000);
  }

  return result;
}

/**
 * Quick check if content contains any injection patterns
 */
export function hasInjectionPatterns(content: string): boolean {
  const normalizedContent = normalizeForScanning(content);
  return getActivePatterns().some(pattern => pattern.pattern.test(normalizedContent));
}

/**
 * Get a summary string of the scan result
 */
export function getScanSummary(result: ScanResult): string {
  if (!result.detected) {
    return 'No injection patterns detected';
  }
  return `${result.matches.length} injection pattern(s) detected [${result.highestSeverity}] - Categories: ${result.categories.join(', ')}`;
}
