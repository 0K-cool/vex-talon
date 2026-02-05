---
name: scan
description: Run Vex-Talon security scan on files, directories, or staged changes
arguments:
  - name: target
    description: File path, directory, or "staged" for git staged changes (default: current directory)
    required: false
  - name: layers
    description: Comma-separated layer IDs to run (e.g., "L0,L4,L9") or "all" (default: all ported)
    required: false
  - name: severity
    description: Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW) (default: LOW)
    required: false
---

# Vex-Talon Security Scan

Run the 20-layer defense-in-depth security scan manually.

## Arguments

- `target`: What to scan
  - File path (e.g., `src/api/auth.ts`)
  - Directory path (e.g., `src/`)
  - `staged` - Scan git staged changes
  - Default: Current directory

- `layers`: Which security layers to run
  - `all` - All 12 ported layers
  - Comma-separated IDs: `L0,L4,L9,L14`
  - Default: All ported layers

- `severity`: Minimum severity threshold
  - `CRITICAL` - Only critical findings
  - `HIGH` - Critical and high
  - `MEDIUM` - Critical, high, and medium
  - `LOW` - All findings (default)

## Available Layers

| Layer | Name | Action | Scans For |
|-------|------|--------|-----------|
| **L0** | Secure Code Enforcer | BLOCK | SQL injection, command injection, hardcoded secrets |
| **L1** | Governor Agent | BLOCK | Policy violations, .env access, destructive ops |
| **L2** | Secure Code Linter | ALERT | Post-write security issues, unsafe patterns |
| **L3** | Memory Validation | ALERT | Memory poisoning, injection in MCP memory |
| **L4** | Injection Scanner | ALERT | Prompt injection patterns (89+ patterns) |
| **L5** | Output Sanitizer | WARN | XSS vectors, innerHTML, eval() |
| **L7** | Image Safety | ALERT | Steganography, visual prompt injection |
| **L9** | Egress Scanner | BLOCK | Data exfiltration, blocked destinations |
| **L12** | Least Privilege | LOG | Permission profile recommendations |
| **L14** | Supply Chain | WARN | Malicious packages, npm/pip audit |
| **L17** | Spend Alerting | ALERT | Cost threshold monitoring |
| **L19** | Skill Scanner | BLOCK | Skill injection patterns |

## Execution

When the user runs `/vex-talon:scan`, execute the following:

### 1. Parse Arguments

```
Target: {{ target | default: "." }}
Layers: {{ layers | default: "all" }}
Severity: {{ severity | default: "LOW" }}
```

### 2. Determine Scan Scope

**If target is "staged":**
- Get list of staged files: `git diff --cached --name-only`
- Scan each staged file

**If target is a file:**
- Verify file exists
- Scan single file

**If target is a directory:**
- Find relevant files (exclude node_modules, .git, etc.)
- Scan each file

### 3. Run Security Layers

For each target file, run applicable layers:

**Code Files (.ts, .js, .py, .sh, .go, .rs, .java):**
- L0: Secure Code Enforcer (CRITICAL patterns)
- L2: Secure Code Linter (security analysis)
- L5: Output Sanitizer (XSS patterns for web files)

**All Text Files:**
- L4: Injection Scanner (prompt injection)
- L9: Egress Scanner (exfiltration patterns)

**Package Files (package.json, requirements.txt, Cargo.toml):**
- L14: Supply Chain Scanner

**Image Files (.png, .jpg, .gif, .webp):**
- L7: Image Safety Scanner

**Skill Files (.md in skills/):**
- L19: Skill Scanner

### 4. Generate Report

Output a security report with:

```
═══════════════════════════════════════════════════════════════
           VEX-TALON SECURITY SCAN REPORT
═══════════════════════════════════════════════════════════════

Target: {{ target }}
Layers: {{ layers_run }}
Scan Time: {{ timestamp }}

───────────────────────────────────────────────────────────────
FINDINGS SUMMARY
───────────────────────────────────────────────────────────────

🔴 CRITICAL: {{ critical_count }}
🟠 HIGH:     {{ high_count }}
🟡 MEDIUM:   {{ medium_count }}
🟢 LOW:      {{ low_count }}

───────────────────────────────────────────────────────────────
DETAILED FINDINGS
───────────────────────────────────────────────────────────────

[For each finding:]

{{ severity_icon }} {{ severity }} | {{ layer_id }} | {{ file_path }}:{{ line }}
   Pattern: {{ pattern_id }}
   Description: {{ description }}
   Matched: {{ matched_text }}

   Recommendation: {{ recommendation }}

───────────────────────────────────────────────────────────────
FRAMEWORK COVERAGE
───────────────────────────────────────────────────────────────

OWASP LLM 2025:    {{ owasp_covered }}/10
OWASP Agentic:     {{ agentic_covered }}/10
MITRE ATLAS:       {{ atlas_techniques }} techniques

═══════════════════════════════════════════════════════════════
```

### 5. Exit Codes

- `0` - No CRITICAL or HIGH findings
- `1` - HIGH findings detected (warning)
- `2` - CRITICAL findings detected (should block)

## Examples

**Scan current directory:**
```
/vex-talon:scan
```

**Scan staged changes before commit:**
```
/vex-talon:scan staged
```

**Scan specific file with only injection detection:**
```
/vex-talon:scan src/api/handler.ts L4
```

**Scan with high severity threshold:**
```
/vex-talon:scan . all HIGH
```

## Integration

This command uses the same detection patterns as the automatic hooks, allowing manual verification before:
- Committing code
- Deploying to production
- Code reviews
- Security audits

The patterns are loaded from:
- `packages/core/src/lib/injection-patterns.ts` (89 injection patterns)
- `packages/core/src/lib/code-patterns.ts` (55 code security patterns)
- External configs in `.vex-talon/configs/`
