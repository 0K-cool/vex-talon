/**
 * Verdict Cache — Phase 2 supporting infrastructure.
 *
 * Avoids re-classifying identical content within a 24h window. Cache
 * key is SHA-256 of the raw content bytes (no normalization — different
 * whitespace = different content = different verdict).
 *
 * Storage: one JSON file per hash, in the cache directory the caller
 * provides. Atomic write via temp-file + rename. Cache files are
 * mode 0o600.
 */

import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';

import type { Verdict } from './classifier';

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheEntry {
  timestamp: number;
  verdict: Verdict;
}

export function hashContent(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function entryPath(hash: string, cacheDir: string): string {
  return join(cacheDir, `${hash}.json`);
}

/**
 * Read a cached verdict. Returns null on cache miss, expired entry,
 * or any read/parse error. Never throws.
 */
export function getCachedVerdict(hash: string, cacheDir: string): Verdict | null {
  const file = entryPath(hash, cacheDir);
  if (!existsSync(file)) return null;
  try {
    const raw = readFileSync(file, 'utf-8');
    const entry = JSON.parse(raw) as CacheEntry;
    if (typeof entry.timestamp !== 'number' || !entry.verdict) return null;
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      // Best-effort cleanup of stale entry.
      try {
        unlinkSync(file);
      } catch {
        // Ignore — stale cleanup failure isn't fatal.
      }
      return null;
    }
    return entry.verdict;
  } catch {
    return null;
  }
}

/**
 * Write a verdict to cache. Atomic via temp-file + rename. Silent on
 * I/O errors — caching is best-effort, never block on it.
 */
export function setCachedVerdict(hash: string, verdict: Verdict, cacheDir: string): void {
  try {
    if (!existsSync(cacheDir)) mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    const entry: CacheEntry = { timestamp: Date.now(), verdict };
    const file = entryPath(hash, cacheDir);
    const tmp = `${file}.tmp.${process.pid}`;
    writeFileSync(tmp, JSON.stringify(entry), { mode: 0o600 });
    renameSync(tmp, file);
  } catch {
    // Cache failure is non-fatal — verdict still propagates to caller.
  }
}

/**
 * Drop entries older than 24h. Safe to call before each classification
 * pass — bounded by directory size, not classification count.
 */
export function purgeExpired(cacheDir: string): void {
  if (!existsSync(cacheDir)) return;
  try {
    const fs = require('fs') as typeof import('fs');
    const files = fs.readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
    const now = Date.now();
    for (const name of files) {
      const file = join(cacheDir, name);
      try {
        const st = statSync(file);
        if (now - st.mtimeMs > CACHE_TTL_MS) unlinkSync(file);
      } catch {
        // Skip
      }
    }
  } catch {
    // Skip
  }
}
