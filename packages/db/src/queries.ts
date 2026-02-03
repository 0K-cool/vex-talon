/**
 * @vex-talon/db - Database Queries
 *
 * Typed query functions for security events and metrics.
 */

import { getDb } from './database';

// ============================================================================
// Types
// ============================================================================

export interface SecurityEvent {
  id?: number;
  timestamp: string;
  session_id: string;
  layer: string;
  hook_type: string;
  tool_name?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: 'block' | 'warn' | 'alert' | 'log';
  pattern_id?: string;
  description?: string;
  file_path?: string;
  matched_text?: string;
  metadata?: string;
}

export interface Session {
  id: string;
  started_at: string;
  ended_at?: string;
  total_events: number;
  total_blocks: number;
  total_warnings: number;
  metadata?: string;
}

export interface LayerCoverage {
  layer: string;
  name: string;
  hook_type: string;
  status: 'active' | 'disabled' | 'error';
  total_invocations: number;
  total_blocks: number;
  total_warnings: number;
  last_invoked?: string;
  owasp_mapping?: string;
  atlas_mapping?: string;
}

export interface DashboardStats {
  total_events: number;
  total_blocks: number;
  total_warnings: number;
  active_layers: number;
  critical_events_24h: number;
  top_patterns: Array<{ pattern_id: string; count: number }>;
}

// ============================================================================
// Event Queries
// ============================================================================

/**
 * Insert a security event
 */
export function insertEvent(event: Omit<SecurityEvent, 'id'>): number {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO security_events (
      timestamp, session_id, layer, hook_type, tool_name, severity,
      action, pattern_id, description, file_path, matched_text, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    event.timestamp || new Date().toISOString(),
    event.session_id,
    event.layer,
    event.hook_type,
    event.tool_name || null,
    event.severity,
    event.action,
    event.pattern_id || null,
    event.description || null,
    event.file_path || null,
    event.matched_text || null,
    event.metadata || null
  );

  return result.lastInsertRowid as number;
}

/**
 * Get recent events
 */
export function getRecentEvents(limit: number = 100): SecurityEvent[] {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM security_events
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(limit) as SecurityEvent[];
}

/**
 * Get events by session
 */
export function getEventsBySession(sessionId: string): SecurityEvent[] {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM security_events
    WHERE session_id = ?
    ORDER BY timestamp DESC
  `).all(sessionId) as SecurityEvent[];
}

/**
 * Get events by layer
 */
export function getEventsByLayer(layer: string, limit: number = 100): SecurityEvent[] {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM security_events
    WHERE layer = ?
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(layer, limit) as SecurityEvent[];
}

/**
 * Get events by severity
 */
export function getEventsBySeverity(
  severity: SecurityEvent['severity'],
  limit: number = 100
): SecurityEvent[] {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM security_events
    WHERE severity = ?
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(severity, limit) as SecurityEvent[];
}

/**
 * Count events in time range
 */
export function countEventsInRange(
  startTime: string,
  endTime: string,
  layer?: string
): number {
  const db = getDb();
  if (layer) {
    return (db.prepare(`
      SELECT COUNT(*) as count FROM security_events
      WHERE timestamp BETWEEN ? AND ? AND layer = ?
    `).get(startTime, endTime, layer) as { count: number }).count;
  }
  return (db.prepare(`
    SELECT COUNT(*) as count FROM security_events
    WHERE timestamp BETWEEN ? AND ?
  `).get(startTime, endTime) as { count: number }).count;
}

// ============================================================================
// Session Queries
// ============================================================================

/**
 * Create or update a session
 */
export function upsertSession(session: Session): void {
  const db = getDb();
  db.prepare(`
    INSERT INTO sessions (id, started_at, ended_at, total_events, total_blocks, total_warnings, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      ended_at = excluded.ended_at,
      total_events = excluded.total_events,
      total_blocks = excluded.total_blocks,
      total_warnings = excluded.total_warnings,
      metadata = excluded.metadata
  `).run(
    session.id,
    session.started_at,
    session.ended_at || null,
    session.total_events,
    session.total_blocks,
    session.total_warnings,
    session.metadata || null
  );
}

/**
 * Get session by ID
 */
export function getSession(sessionId: string): Session | undefined {
  const db = getDb();
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId) as Session | undefined;
}

/**
 * Get recent sessions
 */
export function getRecentSessions(limit: number = 20): Session[] {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM sessions
    ORDER BY started_at DESC
    LIMIT ?
  `).all(limit) as Session[];
}

// ============================================================================
// Layer Coverage Queries
// ============================================================================

/**
 * Get all layer coverage stats
 */
export function getAllLayerCoverage(): LayerCoverage[] {
  const db = getDb();
  return db.prepare('SELECT * FROM layer_coverage ORDER BY layer').all() as LayerCoverage[];
}

/**
 * Update layer stats
 */
export function updateLayerStats(
  layer: string,
  invocations: number = 0,
  blocks: number = 0,
  warnings: number = 0
): void {
  const db = getDb();
  db.prepare(`
    UPDATE layer_coverage SET
      total_invocations = total_invocations + ?,
      total_blocks = total_blocks + ?,
      total_warnings = total_warnings + ?,
      last_invoked = datetime('now')
    WHERE layer = ?
  `).run(invocations, blocks, warnings, layer);
}

/**
 * Set layer status
 */
export function setLayerStatus(layer: string, status: LayerCoverage['status']): void {
  const db = getDb();
  db.prepare('UPDATE layer_coverage SET status = ? WHERE layer = ?').run(status, layer);
}

// ============================================================================
// Dashboard Queries
// ============================================================================

/**
 * Get dashboard statistics
 */
export function getDashboardStats(): DashboardStats {
  const db = getDb();

  const totals = db.prepare(`
    SELECT
      COUNT(*) as total_events,
      SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as total_blocks,
      SUM(CASE WHEN action = 'warn' OR action = 'alert' THEN 1 ELSE 0 END) as total_warnings
    FROM security_events
  `).get() as { total_events: number; total_blocks: number; total_warnings: number };

  const activeLayers = db.prepare(`
    SELECT COUNT(*) as count FROM layer_coverage WHERE status = 'active'
  `).get() as { count: number };

  const critical24h = db.prepare(`
    SELECT COUNT(*) as count FROM security_events
    WHERE severity = 'CRITICAL' AND timestamp > datetime('now', '-24 hours')
  `).get() as { count: number };

  const topPatterns = db.prepare(`
    SELECT pattern_id, COUNT(*) as count
    FROM security_events
    WHERE pattern_id IS NOT NULL
    GROUP BY pattern_id
    ORDER BY count DESC
    LIMIT 10
  `).all() as Array<{ pattern_id: string; count: number }>;

  return {
    total_events: totals.total_events || 0,
    total_blocks: totals.total_blocks || 0,
    total_warnings: totals.total_warnings || 0,
    active_layers: activeLayers.count || 0,
    critical_events_24h: critical24h.count || 0,
    top_patterns: topPatterns,
  };
}

/**
 * Get events per hour for the last N hours
 */
export function getEventsPerHour(hours: number = 24): Array<{ hour: string; count: number }> {
  const db = getDb();
  return db.prepare(`
    SELECT
      strftime('%Y-%m-%d %H:00', timestamp) as hour,
      COUNT(*) as count
    FROM security_events
    WHERE timestamp > datetime('now', '-' || ? || ' hours')
    GROUP BY hour
    ORDER BY hour
  `).all(hours) as Array<{ hour: string; count: number }>;
}

/**
 * Get block rate by layer
 */
export function getBlockRateByLayer(): Array<{ layer: string; total: number; blocks: number; rate: number }> {
  const db = getDb();
  return db.prepare(`
    SELECT
      layer,
      COUNT(*) as total,
      SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as blocks,
      ROUND(CAST(SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100, 2) as rate
    FROM security_events
    GROUP BY layer
    ORDER BY layer
  `).all() as Array<{ layer: string; total: number; blocks: number; rate: number }>;
}
