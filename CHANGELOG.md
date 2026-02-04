# Changelog

All notable changes to Vex-Talon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-04

### Added - Initial Release

**20-Layer Defense-in-Depth Security for Claude Code**

- **12 Ported Security Layers**
  - L0: Secure Code Enforcer (PreToolUse - BLOCK)
  - L1: Governor Agent (PreToolUse - BLOCK)
  - L2: Secure Code Linter (PostToolUse - ALERT)
  - L3: Memory Validation (PreToolUse - ALERT)
  - L4: Injection Scanner (PostToolUse - ALERT)
  - L5: Output Sanitizer (PostToolUse - WARN)
  - L7: Image Safety Scanner (PostToolUse - ALERT)
  - L9: Egress Scanner (PreToolUse - BLOCK)
  - L12: Least Privilege (SessionStart - LOG)
  - L14: Supply Chain Scanner (PostToolUse - WARN)
  - L17: Spend Alerting (PostToolUse - ALERT)
  - L19: Skill Scanner (PreToolUse - BLOCK)

- **Stop Hook: Security Report**
  - Aggregates all security events from session
  - Generates HTML report at session end
  - Auto-opens browser for CRITICAL/HIGH events
  - Saves to `.talon/reports/` directory

- **Dual Notification Pattern**
  - All PostToolUse hooks notify BOTH user (console.error) AND AI (additionalContext)
  - User sees visual alerts with colors and details
  - Claude/Vex receives context injection warning about untrusted content
  - Defense-in-depth: detection influences AI interpretation

- **Dashboard Template**
  - 0K SaaS Dashboard Template synced to zerok-dashboard repo
  - GitHub-inspired dark theme
  - 20-layer defense grid visualization
  - Framework coverage matrices (OWASP LLM, OWASP Agentic, MITRE ATLAS)

- **Plugin Configuration**
  - `.claude-plugin/plugin.json` with all 12 layers enabled by default
  - Configurable via `.vex-talon.json` or plugin settings
  - Layer enable/disable without code changes

### Technical

- **Monorepo Structure**
  - `@vex-talon/core` - Security hooks and pattern configs
  - `@vex-talon/db` - SQLite event storage
  - `@vex-talon/ui` - Themed component library
  - `@vex-talon/dashboard` - Next.js monitoring dashboard

- **Framework Coverage**
  - OWASP LLM Top 10 2025: 9/10 coverage
  - OWASP Agentic Top 10 2026: Full coverage
  - MITRE ATLAS: 16+ technique mappings

---

**Vex-Talon** - Sharp, fast, defensive. 🦅
