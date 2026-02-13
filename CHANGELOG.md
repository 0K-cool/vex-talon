# Changelog

All notable changes to Vex-Talon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-13

### Added

- **L4 Injection Scanner: Session Escalation (Persistence Defense)**
  - Cumulative detection tracking across tool calls within a session
  - Three escalation levels: NORMAL → ELEVATED (3+ signals) → CRITICAL (5+ signals)
  - ELEVATED: WARN actions escalate to ALERT
  - CRITICAL: All detections escalate to ALERT (maximum vigilance)
  - Near-misses (heuristic triggers) count at half weight
  - Session state tracked per `session_id`, auto-resets on new session
  - Audit log includes `escalation_level`, `session_detection_count`, `session_near_miss_count`
  - stderr warning when escalation level changes

### Research

- Based on Anthropic Opus 4.6 System Card (February 2026) persistence scaling data
- Single-attempt attack success: 17.8% → 200 attempts: 78.6% (without safeguards)
- Multiple detections in one session indicate persistent attack campaign, warranting escalated thresholds

---

## [1.1.0] - 2026-02-11

### Added

- **L5 Output Sanitizer: ANSI Terminal Injection Detection**
  - 6 new patterns defending against the Terminal DiLLMa attack (SAGAI 2025 IEEE S&P workshop case study)
  - OSC 52 clipboard manipulation (CRITICAL) — read/write terminal clipboard
  - DCS device control strings (HIGH) — send commands to terminal emulator
  - 8-bit CSI filter bypass (HIGH) — evade 7-bit escape sequence filters
  - Bracketed paste mode manipulation (HIGH) — enable paste injection attacks
  - OSC title-set social engineering (MEDIUM) — change terminal window title
  - Sixel graphics data embedding (MEDIUM) — embedded data in image sequences
  - New file extensions scanned: `.sh`, `.bash`, `.zsh`, `.py`, `.rb`, `.pl`
  - Context-aware warnings: ANSI-specific remediation vs XSS-specific remediation

### Changed

- L5 Output Sanitizer now covers both web (XSS) and terminal (ANSI injection) attack vectors
- Pattern count: 7 → 13 (6 new ANSI patterns)
- File extension coverage: 8 → 14 (6 new terminal extensions)

### Research

- Based on analysis of "Systems Security Foundations for Agentic Computing" (Google, UCSD, UW Madison, EmbraceTheRed, December 2025)
- Terminal DiLLMa case study: ANSI escape sequences in LLM output hijack terminal emulators for clipboard manipulation, data exfiltration via DNS, and unauthorized actions

---

## [1.0.0] - 2026-02-04

### Added - Initial Public Release

**20-Layer Defense-in-Depth Security for Claude Code**

- **14 Ported Security Hooks**

  *PreToolUse (Block Before Execution):*
  - L0: Secure Code Enforcer - Blocks CRITICAL vulnerabilities before code is written
  - L1: Governor Agent - 33+ policy enforcement rules with input modification
  - L3: Memory Validation - Detects injection in MCP memory operations
  - L9: Egress Scanner - Prevents data exfiltration via secrets, bulk data, blocked destinations
  - L14-pre: Supply Chain Pre-Install - Blocks 60+ known malicious packages (+ optional OSM API)
  - L19: Skill Scanner - Scans skills for injection patterns before invocation

  *PostToolUse (Detect After Execution):*
  - L2: Secure Code Linter - Post-write security analysis with static analysis + optional LLM review
  - L4: Injection Scanner - Detects prompt injection in tool outputs (89+ patterns)
  - L5: Output Sanitizer - Scans web files for XSS vectors
  - L7: Image Safety Scanner - Detects steganography and visual prompt injection
  - L14: Supply Chain Post-Install - Runs npm audit / pip-audit after installations
  - L17: Spend Alerting - Tracks session costs with threshold warnings

  *Session Lifecycle:*
  - L12: Least Privilege Profiles - Permission profiles (dev, audit, client-work, research)
  - STOP: Security Report - Generates HTML report at session end

- **Dual Notification Pattern**
  - All PostToolUse hooks notify BOTH user (console.error) AND AI (additionalContext)
  - Defense-in-depth: detection influences AI interpretation of flagged content

- **Externalized Security Configs**
  - JSON configs in `~/.vex-talon/config/` for custom patterns
  - 60-second cache TTL with automatic fallback to built-in defaults

- **Plugin Commands**
  - `/talon` - Main security command
  - `/talon-status` - Layer status overview
  - `/talon-report` - Generate security report
  - `/talon-intel-update` - Update security intelligence

- **Plugin Skills**
  - `security-scan` - On-demand security scanning
  - `security-intel-update` - Update detection patterns

- **Framework Coverage**
  - OWASP LLM Top 10 2025: 9/10 coverage
  - OWASP Agentic Top 10 2026: Full coverage
  - MITRE ATLAS: 16+ technique mappings

- **4 Rounds of Security Audits** - Score: 91/100

### Technical

- **Monorepo Structure**
  - `@vex-talon/core` - Security hooks, policies, detection patterns, and shared libraries
  - `@vex-talon/db` - SQLite database layer for security event storage and querying

- **Shared Libraries**
  - Atomic file operations (crash-safe writes)
  - Circuit breaker (fault tolerance)
  - Config loader (60s TTL cache with fallback)
  - Profile loader (permission enforcement)
  - Unicode normalization (homoglyph detection)

---

**Vex-Talon** - Sharp, fast, always watching.
