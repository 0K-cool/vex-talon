/**
 * Shared Unicode Normalization for Vex-Talon Security Hooks
 *
 * Single source of truth for homoglyph detection and Unicode normalization.
 * Used by L0, L1, L3, L4, and injection-patterns.ts.
 *
 * Covers Cyrillic and Greek lookalikes plus invisible/zero-width characters.
 *
 * @version 1.0.0
 */

// ============================================================================
// Homoglyph Map
// ============================================================================

/**
 * Characters that visually resemble ASCII but are from other Unicode blocks.
 * Used to detect evasion attempts (e.g., Cyrillic 'а' instead of Latin 'a').
 */
export const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0410': 'A', '\u0412': 'B',
  '\u0415': 'E', '\u041A': 'K', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O',
  '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y', '\u0425': 'X',
  // Greek lookalikes
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o', '\u03C1': 'p',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0399': 'I', '\u039F': 'O',
};

/**
 * Zero-width and invisible Unicode characters used for evasion.
 */
export const INVISIBLE_CHARS = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD]/g;

// ============================================================================
// Normalization Function
// ============================================================================

/**
 * Normalize text for security scanning.
 *
 * 1. NFKC normalization (compatibility decomposition + canonical composition)
 * 2. Homoglyph replacement (Cyrillic/Greek → ASCII)
 * 3. Invisible character removal (zero-width, soft hyphens, etc.)
 */
export function normalizeUnicode(text: string): string {
  let normalized = text.normalize('NFKC');
  for (const [homoglyph, replacement] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.split(homoglyph).join(replacement);
  }
  normalized = normalized.replace(INVISIBLE_CHARS, '');
  return normalized;
}

// Alias for backward compatibility with injection-patterns.ts
export const normalizeForScanning = normalizeUnicode;
