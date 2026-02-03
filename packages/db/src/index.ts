/**
 * @vex-talon/db - Database layer for security dashboard
 *
 * SQLite-based storage for security events, metrics, and coverage data.
 *
 * Features:
 * - Security event storage and querying
 * - Session tracking
 * - Layer coverage statistics
 * - Dashboard aggregations
 * - JSONL log ingestion
 * - File watching for real-time updates
 */

export const VERSION = '0.1.0';

// Database connection
export { initDb, getDb, closeDb, resetDb, getDbPath } from './database';

// Schema
export { SCHEMA_VERSION, CREATE_TABLES, SEED_LAYERS, MIGRATIONS } from './schema';

// Queries
export {
  // Event queries
  insertEvent,
  getRecentEvents,
  getEventsBySession,
  getEventsByLayer,
  getEventsBySeverity,
  countEventsInRange,
  // Session queries
  upsertSession,
  getSession,
  getRecentSessions,
  // Layer coverage
  getAllLayerCoverage,
  updateLayerStats,
  setLayerStatus,
  // Dashboard queries
  getDashboardStats,
  getEventsPerHour,
  getBlockRateByLayer,
  // Types
  type SecurityEvent,
  type Session,
  type LayerCoverage,
  type DashboardStats,
} from './queries';

// Ingestion
export {
  ingestLogFile,
  ingestLogsDirectory,
  watchLogFile,
  unwatchLogFile,
  unwatchAllLogFiles,
  startSession,
  endSession,
} from './ingest';
