/**
 * @vex-talon/db - Database Schema
 *
 * SQLite schema for security events, metrics, and layer coverage.
 */

export const SCHEMA_VERSION = 1;

/**
 * SQL statements to create the database schema
 */
export const CREATE_TABLES = `
-- Security Events Table
-- Stores all security hook events (blocks, warnings, alerts)
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  session_id TEXT NOT NULL,
  layer TEXT NOT NULL,           -- L0, L1, L2, etc.
  hook_type TEXT NOT NULL,       -- PreToolUse, PostToolUse, SessionStart, etc.
  tool_name TEXT,                -- Tool that triggered the event
  severity TEXT NOT NULL,        -- CRITICAL, HIGH, MEDIUM, LOW
  action TEXT NOT NULL,          -- block, warn, alert, log
  pattern_id TEXT,               -- ID of the pattern that matched
  description TEXT,              -- Human-readable description
  file_path TEXT,                -- File involved (if applicable)
  matched_text TEXT,             -- Text that matched the pattern (truncated)
  metadata TEXT                  -- JSON blob for additional context
);

-- Sessions Table
-- Tracks Claude Code sessions for aggregation
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at TEXT,
  total_events INTEGER DEFAULT 0,
  total_blocks INTEGER DEFAULT 0,
  total_warnings INTEGER DEFAULT 0,
  metadata TEXT
);

-- Layer Coverage Table
-- Tracks which security layers are active and their stats
CREATE TABLE IF NOT EXISTS layer_coverage (
  layer TEXT PRIMARY KEY,        -- L0, L1, etc.
  name TEXT NOT NULL,            -- Human-readable name
  hook_type TEXT NOT NULL,       -- PreToolUse, PostToolUse, etc.
  status TEXT DEFAULT 'active',  -- active, disabled, error
  total_invocations INTEGER DEFAULT 0,
  total_blocks INTEGER DEFAULT 0,
  total_warnings INTEGER DEFAULT 0,
  last_invoked TEXT,
  owasp_mapping TEXT,            -- JSON array of OWASP LLM IDs
  atlas_mapping TEXT             -- JSON array of ATLAS technique IDs
);

-- Metrics Table
-- Time-series metrics for dashboard charts
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  metric_type TEXT NOT NULL,     -- events_per_hour, blocks_per_day, etc.
  layer TEXT,                    -- Optional: layer-specific metric
  value REAL NOT NULL,
  metadata TEXT
);

-- Pattern Stats Table
-- Track which patterns fire most often
CREATE TABLE IF NOT EXISTS pattern_stats (
  pattern_id TEXT PRIMARY KEY,
  layer TEXT NOT NULL,
  category TEXT,
  severity TEXT NOT NULL,
  total_matches INTEGER DEFAULT 0,
  last_matched TEXT,
  false_positives INTEGER DEFAULT 0
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_layer ON security_events(layer);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
`;

/**
 * Seed data for layer coverage
 */
export const SEED_LAYERS = `
INSERT OR IGNORE INTO layer_coverage (layer, name, hook_type, owasp_mapping, atlas_mapping) VALUES
('L0', 'Secure Code Enforcer', 'PreToolUse', '["LLM02"]', '[]'),
('L1', 'Governor Agent', 'PreToolUse', '["LLM01","LLM02"]', '["AML.T0051"]'),
('L2', 'Secure Code Linter', 'PostToolUse', '["LLM02"]', '[]'),
('L3', 'Memory Validation', 'Pre+PostToolUse', '["Agentic ASI06"]', '["AML.T0064"]'),
('L4', 'Injection Scanner', 'PostToolUse', '["LLM01"]', '["AML.T0051"]'),
('L5', 'Output Sanitizer', 'PostToolUse', '["LLM05"]', '[]'),
('L6', 'Git Pre-commit', 'GitHook', '["LLM02"]', '[]'),
('L7', 'Image Safety Scanner', 'PostToolUse', '["LLM01"]', '["AML.T0048"]'),
('L8', 'Evaluator Agent', 'GitHook', '["LLM02"]', '[]'),
('L9', 'Egress Scanner', 'PreToolUse', '["LLM02"]', '["AML.T0035","AML.T0057"]'),
('L10', 'Native Sandbox', 'Builtin', '[]', '[]'),
('L11', 'Leash Kernel Sandbox', 'External', '[]', '[]'),
('L12', 'Least Privilege Profiles', 'SessionStart', '[]', '[]'),
('L13', 'Strawberry Hallucination', 'MCP', '[]', '[]'),
('L14', 'Supply Chain Scanner', 'PostToolUse', '["LLM03"]', '["AML.T0047"]'),
('L15', 'RAG Security Scanner', 'PreIndex', '["LLM04","LLM08"]', '["AML.T0048"]'),
('L16', 'Human', 'Manual', '[]', '[]'),
('L17', 'Spend Alerting', 'PostToolUse', '["LLM10"]', '[]'),
('L18', 'MCP Audit', 'SessionStart', '["LLM01","LLM02"]', '["AML.T0051","AML.T0053"]'),
('L19', 'Skill Scanner', 'PreToolUse+SessionStart', '["LLM01"]', '[]');
`;

/**
 * Schema migration helpers
 */
export const MIGRATIONS: Record<number, string> = {
  1: CREATE_TABLES + SEED_LAYERS,
  // Future migrations go here
  // 2: 'ALTER TABLE security_events ADD COLUMN new_field TEXT;',
};
