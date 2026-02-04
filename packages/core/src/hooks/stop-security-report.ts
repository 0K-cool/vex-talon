#!/usr/bin/env bun

/**
 * Security Report Generator - Stop Hook
 *
 * Part of Vex-Talon 20-layer defense-in-depth architecture.
 *
 * Purpose: Generate a consolidated security report at session end.
 * Pattern: Stop Hook (runs when session ends)
 *
 * Data Sources (audit logs):
 * - L0-secure-code-enforcer-audit.jsonl
 * - L1-governor-agent-audit.jsonl
 * - L2-secure-code-linter-audit.jsonl
 * - L3-memory-validation-audit.jsonl
 * - L4-injection-scanner-audit.jsonl
 * - L5-output-sanitizer-audit.jsonl
 * - L7-image-safety-scanner-audit.jsonl
 * - L9-egress-scanner-audit.jsonl
 * - L14-supply-chain-scanner-audit.jsonl
 * - L19-skill-scanner-audit.jsonl
 *
 * Output: ~/.vex-talon/reports/security-report-{timestamp}.html
 *
 * @version 0.1.0 (vex-talon)
 * @date 2026-02-04
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';
import { TALON_DIR, LOGS_DIR, ensureDirectories } from './lib/talon-paths';

// ============================================================================
// Report Configuration
// ============================================================================

const REPORTS_DIR = join(TALON_DIR, 'reports');
const AUTO_OPEN_THRESHOLD = 1; // Open browser if >= this many CRITICAL/HIGH events

// Hook names that generate audit logs
const AUDIT_SOURCES = [
  { hookName: 'L0-secure-code-enforcer', layer: 'L0', displayName: 'Secure Code Enforcer' },
  { hookName: 'L1-governor-agent', layer: 'L1', displayName: 'Governor Agent' },
  { hookName: 'L2-secure-code-linter', layer: 'L2', displayName: 'Secure Code Linter' },
  { hookName: 'L3-memory-validation', layer: 'L3', displayName: 'Memory Validation' },
  { hookName: 'L4-injection-scanner', layer: 'L4', displayName: 'Injection Scanner' },
  { hookName: 'L5-output-sanitizer', layer: 'L5', displayName: 'Output Sanitizer' },
  { hookName: 'L7-image-safety-scanner', layer: 'L7', displayName: 'Image Safety Scanner' },
  { hookName: 'L9-egress-scanner', layer: 'L9', displayName: 'Egress Scanner' },
  { hookName: 'L14-supply-chain-scanner', layer: 'L14', displayName: 'Supply Chain Scanner' },
  { hookName: 'L19-skill-scanner', layer: 'L19', displayName: 'Skill Scanner' },
];

// ============================================================================
// Types
// ============================================================================

interface StopInput {
  stop_hook_active?: boolean;
  session_id?: string;
  transcript_path?: string;
}

interface AuditEntry {
  timestamp: string;
  session_id?: string;
  tool_name?: string;
  tool?: string;
  command?: string;
  file_path?: string;
  decision?: 'allow' | 'block' | 'warn';
  risk?: string;
  severity?: string;
  findings?: Array<{ name?: string; severity?: string; pattern?: string }>;
  detected?: Array<{ pkg?: string; reason?: string }>;
  triggers?: string[];
  content?: string;
  [key: string]: unknown;
}

interface SecurityEvent {
  timestamp: string;
  layer: string;
  layerName: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  tool?: string;
  filePath?: string;
  command?: string;
  decision?: string;
  summary: string;
  details: Record<string, unknown>;
}

// ============================================================================
// Audit Log Processing
// ============================================================================

function readAuditLog(hookName: string): AuditEntry[] {
  const path = join(LOGS_DIR, `${hookName}-audit.jsonl`);
  if (!existsSync(path)) return [];

  try {
    const content = readFileSync(path, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);

    // Only process last 1000 entries to limit report size
    const recentLines = lines.slice(-1000);

    return recentLines.map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter((e): e is AuditEntry => e !== null);
  } catch {
    return [];
  }
}

function determineSeverity(entry: AuditEntry): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  // Check explicit severity fields
  if (entry.severity) {
    const sev = entry.severity.toUpperCase();
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(sev)) {
      return sev as SecurityEvent['severity'];
    }
  }

  // Check risk level
  if (entry.risk) {
    const risk = entry.risk.toUpperCase();
    if (risk === 'CRITICAL') return 'CRITICAL';
    if (risk === 'HIGH') return 'HIGH';
    if (risk === 'MEDIUM') return 'MEDIUM';
    if (risk === 'LOW') return 'LOW';
  }

  // Check decision (blocked = high severity)
  if (entry.decision === 'block') return 'HIGH';
  if (entry.decision === 'warn') return 'MEDIUM';

  // Check findings
  if (entry.findings?.some(f => f.severity === 'CRITICAL')) return 'CRITICAL';
  if (entry.findings?.some(f => f.severity === 'HIGH')) return 'HIGH';

  // Check for malicious packages
  if (entry.detected && entry.detected.length > 0) return 'CRITICAL';

  return 'INFO';
}

function processAuditEntries(
  entries: AuditEntry[],
  layer: string,
  layerName: string,
  sessionId?: string
): SecurityEvent[] {
  return entries
    .filter(e => !sessionId || !e.session_id || e.session_id === sessionId)
    .filter(e => {
      // Filter to only security-relevant events (not just info logs)
      const severity = determineSeverity(e);
      return severity !== 'INFO' || e.decision === 'block' || e.findings?.length;
    })
    .map(e => {
      const severity = determineSeverity(e);

      // Build summary based on entry type
      let summary = '';
      if (e.decision === 'block') {
        summary = `Blocked: ${e.tool_name || e.tool || 'operation'}`;
      } else if (e.findings?.length) {
        summary = `Detected ${e.findings.length} pattern(s)`;
      } else if (e.detected?.length) {
        summary = `Detected ${e.detected.length} malicious package(s)`;
      } else if (e.triggers?.length) {
        summary = `Triggered: ${e.triggers.slice(0, 2).join(', ')}`;
      } else {
        summary = e.decision || 'Security event';
      }

      return {
        timestamp: e.timestamp,
        layer,
        layerName,
        severity,
        tool: e.tool_name || e.tool,
        filePath: e.file_path,
        command: e.command?.substring(0, 100),
        decision: e.decision,
        summary,
        details: e,
      };
    });
}

// ============================================================================
// HTML Report Generation
// ============================================================================

function generateHTML(events: SecurityEvent[], sessionId?: string): string {
  const now = new Date().toISOString();

  // Aggregate statistics
  const stats = {
    total: events.length,
    critical: events.filter(e => e.severity === 'CRITICAL').length,
    high: events.filter(e => e.severity === 'HIGH').length,
    medium: events.filter(e => e.severity === 'MEDIUM').length,
    low: events.filter(e => e.severity === 'LOW').length,
    blocked: events.filter(e => e.decision === 'block').length,
  };

  // Group by layer
  const byLayer: Record<string, SecurityEvent[]> = {};
  for (const e of events) {
    const layer = e.layer;
    if (!byLayer[layer]) byLayer[layer] = [];
    byLayer[layer]!.push(e);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vex-Talon Security Report - ${now.split('T')[0]}</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border-color: #30363d;
      --text-primary: #c9d1d9;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #3fb950;
      --info: #58a6ff;
      --accent: #58a6ff;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 20px;
    }

    .container { max-width: 1200px; margin: 0 auto; }

    header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-color);
    }

    .logo { font-size: 32px; }

    h1 { font-size: 24px; font-weight: 600; }

    .meta {
      color: var(--text-secondary);
      font-size: 14px;
      margin-left: auto;
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .stat-value {
      font-size: 32px;
      font-weight: 700;
    }

    .stat-label {
      color: var(--text-secondary);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .stat-critical .stat-value { color: var(--critical); }
    .stat-high .stat-value { color: var(--high); }
    .stat-medium .stat-value { color: var(--medium); }
    .stat-low .stat-value { color: var(--low); }
    .stat-blocked .stat-value { color: var(--critical); }

    .filters {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }

    .filter-btn {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 6px 12px;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s;
    }

    .filter-btn:hover { border-color: var(--accent); }
    .filter-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }

    .section {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      margin-bottom: 16px;
    }

    .section-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px;
      cursor: pointer;
      border-bottom: 1px solid var(--border-color);
    }

    .section-header:hover { background: var(--bg-tertiary); }

    .layer-badge {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 600;
      font-family: monospace;
    }

    .section-title { font-weight: 600; flex: 1; }

    .section-count {
      background: var(--bg-tertiary);
      border-radius: 12px;
      padding: 2px 8px;
      font-size: 12px;
    }

    .section-content { padding: 16px; }
    .section-content.collapsed { display: none; }

    .event {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      margin-bottom: 8px;
      overflow: hidden;
    }

    .event-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px;
      cursor: pointer;
    }

    .event-header:hover { background: rgba(88, 166, 255, 0.05); }

    .severity-badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .severity-CRITICAL { background: var(--critical); color: #fff; }
    .severity-HIGH { background: var(--high); color: #fff; }
    .severity-MEDIUM { background: var(--medium); color: #000; }
    .severity-LOW { background: var(--low); color: #000; }
    .severity-INFO { background: var(--info); color: #fff; }

    .event-summary { flex: 1; font-size: 14px; }

    .event-time {
      color: var(--text-muted);
      font-size: 12px;
      font-family: monospace;
    }

    .event-details {
      border-top: 1px solid var(--border-color);
      padding: 12px;
      font-size: 13px;
      display: none;
    }

    .event-details.expanded { display: block; }

    .detail-row {
      display: flex;
      gap: 12px;
      margin-bottom: 8px;
    }

    .detail-label {
      color: var(--text-secondary);
      min-width: 100px;
      font-weight: 500;
    }

    .detail-value {
      font-family: monospace;
      word-break: break-all;
    }

    pre {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 12px;
      overflow-x: auto;
      font-size: 12px;
      margin-top: 8px;
    }

    .empty-state {
      text-align: center;
      padding: 48px;
      color: var(--text-secondary);
    }

    .empty-state .icon { font-size: 48px; margin-bottom: 16px; }

    footer {
      margin-top: 24px;
      padding-top: 16px;
      border-top: 1px solid var(--border-color);
      text-align: center;
      color: var(--text-muted);
      font-size: 12px;
    }

    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">🦖⚡</div>
      <div>
        <h1>Vex-Talon Security Report</h1>
        <div class="meta">Session: ${sessionId || 'All sessions'}</div>
      </div>
      <div class="meta">${new Date().toLocaleString()}</div>
    </header>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-value">${stats.total}</div>
        <div class="stat-label">Total Events</div>
      </div>
      <div class="stat-card stat-critical">
        <div class="stat-value">${stats.critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-value">${stats.high}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="stat-value">${stats.medium}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card stat-low">
        <div class="stat-value">${stats.low}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card stat-blocked">
        <div class="stat-value">${stats.blocked}</div>
        <div class="stat-label">Blocked</div>
      </div>
    </div>

    <div class="filters">
      <button class="filter-btn active" data-filter="all">All</button>
      <button class="filter-btn" data-filter="CRITICAL">Critical</button>
      <button class="filter-btn" data-filter="HIGH">High</button>
      <button class="filter-btn" data-filter="MEDIUM">Medium</button>
      <button class="filter-btn" data-filter="blocked">Blocked</button>
    </div>

    ${Object.keys(byLayer).length === 0 ? `
    <div class="empty-state">
      <div class="icon">✅</div>
      <h2>No Security Events</h2>
      <p>No security events were detected in this session.</p>
    </div>
    ` : Object.entries(byLayer).sort((a, b) => a[0].localeCompare(b[0])).map(([layer, layerEvents]) => `
    <div class="section">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="layer-badge">${layer}</span>
        <span class="section-title">${layerEvents[0]?.layerName || 'Unknown'}</span>
        <span class="section-count">${layerEvents.length}</span>
        <span>▼</span>
      </div>
      <div class="section-content">
        ${layerEvents.map(e => `
        <div class="event" data-severity="${e.severity}" data-decision="${e.decision || ''}">
          <div class="event-header" onclick="toggleEvent(this)">
            <span class="severity-badge severity-${e.severity}">${e.severity}</span>
            <span class="event-summary">${escapeHtml(e.summary)}</span>
            ${e.tool ? `<code>${e.tool}</code>` : ''}
            <span class="event-time">${new Date(e.timestamp).toLocaleTimeString()}</span>
          </div>
          <div class="event-details">
            ${e.tool ? `<div class="detail-row"><span class="detail-label">Tool</span><span class="detail-value">${e.tool}</span></div>` : ''}
            ${e.filePath ? `<div class="detail-row"><span class="detail-label">File</span><span class="detail-value">${escapeHtml(e.filePath)}</span></div>` : ''}
            ${e.command ? `<div class="detail-row"><span class="detail-label">Command</span><span class="detail-value">${escapeHtml(e.command)}</span></div>` : ''}
            ${e.decision ? `<div class="detail-row"><span class="detail-label">Decision</span><span class="detail-value">${e.decision}</span></div>` : ''}
            <div class="detail-row"><span class="detail-label">Timestamp</span><span class="detail-value">${e.timestamp}</span></div>
            <pre>${escapeHtml(JSON.stringify(e.details, null, 2))}</pre>
          </div>
        </div>
        `).join('')}
      </div>
    </div>
    `).join('')}

    <footer>
      <p>Generated by <a href="https://github.com/0K-cool/vex-talon">Vex-Talon</a> 🦖⚡ • Defense-in-Depth Security for Claude Code</p>
    </footer>
  </div>

  <script>
    function toggleSection(header) {
      const content = header.nextElementSibling;
      content.classList.toggle('collapsed');
      header.querySelector('span:last-child').textContent =
        content.classList.contains('collapsed') ? '▶' : '▼';
    }

    function toggleEvent(header) {
      const details = header.nextElementSibling;
      details.classList.toggle('expanded');
    }

    // Filtering
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filter = btn.dataset.filter;
        document.querySelectorAll('.event').forEach(event => {
          if (filter === 'all') {
            event.style.display = '';
          } else if (filter === 'blocked') {
            event.style.display = event.dataset.decision === 'block' ? '' : 'none';
          } else {
            event.style.display = event.dataset.severity === filter ? '' : 'none';
          }
        });
      });
    });
  </script>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  try {
    // Read stop hook input
    let rawInput = '';
    try {
      rawInput = await Promise.race([
        Bun.stdin.text(),
        new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 500)),
      ]);
    } catch {
      // No input or timeout - proceed anyway for stop hook
    }

    let input: StopInput = {};
    if (rawInput?.trim()) {
      try {
        input = JSON.parse(rawInput);
      } catch {
        // Invalid JSON - proceed with defaults
      }
    }

    // Ensure directories exist
    ensureDirectories();
    if (!existsSync(REPORTS_DIR)) {
      mkdirSync(REPORTS_DIR, { recursive: true, mode: 0o700 });
    }

    // Collect all security events from audit logs
    const allEvents: SecurityEvent[] = [];

    for (const source of AUDIT_SOURCES) {
      const entries = readAuditLog(source.hookName);
      const events = processAuditEntries(
        entries,
        source.layer,
        source.displayName,
        input.session_id
      );
      allEvents.push(...events);
    }

    // Sort by timestamp (newest first)
    allEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    // Only generate report if there are security events
    if (allEvents.length === 0) {
      console.error('✅ TALON: No security events detected in this session.');
      process.exit(0);
    }

    // Generate HTML report
    const html = generateHTML(allEvents, input.session_id);

    // Write report
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const reportPath = join(REPORTS_DIR, `security-report-${timestamp}.html`);
    writeFileSync(reportPath, html, { mode: 0o600 });

    // Summary for user
    const criticalHigh = allEvents.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').length;
    console.error(`\n📊 TALON Security Report: ${allEvents.length} events (${criticalHigh} critical/high)`);
    console.error(`   Report: ${reportPath}`);

    // Auto-open in browser if significant events detected (CRITICAL/HIGH only)
    if (criticalHigh >= AUTO_OPEN_THRESHOLD) {
      try {
        // macOS: open, Linux: xdg-open, Windows: start
        const platform = process.platform;
        const openCmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
        execSync(`${openCmd} "${reportPath}"`, { stdio: 'ignore' });
      } catch {
        // Silently fail if browser open doesn't work
      }
    }

    process.exit(0);
  } catch (err) {
    console.error(`[stop-security-report] Error: ${(err as Error).message}`);
    process.exit(0);
  }
}

main();
