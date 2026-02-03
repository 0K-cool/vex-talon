/**
 * @vex-talon/db - Database Connection
 */

import Database from 'better-sqlite3';
import { join } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { CREATE_TABLES, SEED_LAYERS, SCHEMA_VERSION, MIGRATIONS } from './schema';

let db: Database.Database | null = null;

export function getDbPath(): string {
  const customPath = process.env.VEX_TALON_DB_PATH;
  if (customPath) return customPath;
  const dataDir = join(process.cwd(), '.vex-talon', 'data');
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  return join(dataDir, 'security.db');
}

export function initDb(dbPath?: string): Database.Database {
  if (db) return db;
  const path = dbPath || getDbPath();
  db = new Database(path);
  db.pragma('journal_mode = WAL');
  runMigrations(db);
  return db;
}

export function getDb(): Database.Database {
  if (!db) return initDb();
  return db;
}

export function closeDb(): void {
  if (db) { db.close(); db = null; }
}

function runMigrations(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  const row = database.prepare('SELECT MAX(version) as version FROM schema_migrations').get() as { version: number | null };
  const currentVersion = row?.version || 0;
  for (let version = currentVersion + 1; version <= SCHEMA_VERSION; version++) {
    const migration = MIGRATIONS[version];
    if (migration) {
      database.exec(migration);
      database.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(version);
    }
  }
}

export function resetDb(): void {
  if (db) {
    db.exec('DROP TABLE IF EXISTS security_events');
    db.exec('DROP TABLE IF EXISTS sessions');
    db.exec('DROP TABLE IF EXISTS layer_coverage');
    db.exec('DROP TABLE IF EXISTS metrics');
    db.exec('DROP TABLE IF EXISTS pattern_stats');
    db.exec('DROP TABLE IF EXISTS schema_migrations');
    runMigrations(db);
  }
}

export { Database };
