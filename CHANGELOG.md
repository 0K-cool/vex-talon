# Changelog

All notable changes to Vex-Talon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
