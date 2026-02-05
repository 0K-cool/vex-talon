---
name: intel-update
description: Update Vex-Talon security intelligence - sync attack patterns and framework compliance to runtime config files
arguments:
  - name: scope
    description: What to update - "all", "attacks", "frameworks", or "memory" (default: all)
    required: false
  - name: check
    description: Check for updates without applying (--check flag)
    required: false
---

# Vex-Talon Security Intelligence Update

Keep security layers current with latest attack patterns and framework compliance.

## Arguments

- `scope`: What to update
  - `all` - Full update (default)
  - `attacks` - Attack patterns only (NOVA + 0din.ai)
  - `frameworks` - Framework compliance only (ATLAS + OWASP)
  - `memory` - Memory poisoning patterns only

- `check`: Preview mode
  - Include `--check` to see what would be updated without applying

## Execution

When the user runs `/vex-talon:intel-update`, execute the security-intel-update skill.

**CRITICAL:** The skill MUST write findings to `~/.vex-talon/config/` JSON files that hooks consume at runtime. Do NOT write to memory/*.md — those are documentation, not runtime configs.

### Target Config Files

| Config Path | Hooks That Read It |
|-------------|-------------------|
| `~/.vex-talon/config/injection/patterns.json` | L4, L19 |
| `~/.vex-talon/config/memory/config.json` | L3 Memory Validation, L3 Auto Memory Guardian |
| `~/.vex-talon/config/framework/atlas-owasp-mappings.json` | Stop Report |

### 1. Check Current Status

Read existing configs to show current state:

```bash
cat ~/.vex-talon/config/injection/patterns.json 2>/dev/null | jq '.metadata' || echo "No injection config yet"
cat ~/.vex-talon/config/memory/config.json 2>/dev/null | jq '.metadata' || echo "No memory config yet"
cat ~/.vex-talon/config/framework/atlas-owasp-mappings.json 2>/dev/null | jq '.metadata' || echo "No framework config yet"
```

Display status:
```
╔══════════════════════════════════════════════════════════════╗
║           VEX-TALON SECURITY INTELLIGENCE STATUS             ║
╠══════════════════════════════════════════════════════════════╣
║  Config Files:                                               ║
║    injection/patterns.json:  {{ exists/missing }}             ║
║    memory/config.json:       {{ exists/missing }}             ║
║    framework/mappings.json:  {{ exists/missing }}             ║
║                                                              ║
║  Last Updated: {{ date or "never" }}                         ║
╚══════════════════════════════════════════════════════════════╝
```

### 2. Execute Update (based on scope)

**If scope includes "attacks":**

1. **NOVA Framework** — WebFetch GitHub, extract rules, convert to config-loader JSON format
2. **0din.ai** — Playwright scrape if available, otherwise WebSearch fallback (see skill for details)
   - ⚠️ 0din.ai requires Playwright MCP for full data. If unavailable, fall back to WebSearch (partial data).
3. **Write to `~/.vex-talon/config/injection/patterns.json`** (merge, deduplicate by ID)

**If scope includes "frameworks":**

1. **MITRE ATLAS** — WebFetch techniques page
2. **OWASP LLM/Agentic** — WebFetch and WebSearch for latest
3. **Write to `~/.vex-talon/config/framework/atlas-owasp-mappings.json`**

**If scope includes "memory":**

1. **Research** — WebSearch for new memory poisoning techniques
2. **OWASP Agentic ASI06** — Check for updates
3. **Write to `~/.vex-talon/config/memory/config.json`** (merge patterns into categories)

### 3. Generate Report

```
═══════════════════════════════════════════════════════════════
        VEX-TALON SECURITY INTELLIGENCE UPDATE
═══════════════════════════════════════════════════════════════

Date: {{ timestamp }}
Scope: {{ scope }}

───────────────────────────────────────────────────────────────
CONFIG FILES UPDATED
───────────────────────────────────────────────────────────────

  ~/.vex-talon/config/injection/patterns.json  ({{ status }})
  ~/.vex-talon/config/memory/config.json       ({{ status }})
  ~/.vex-talon/config/framework/mappings.json  ({{ status }})

───────────────────────────────────────────────────────────────
ATTACK PATTERNS
───────────────────────────────────────────────────────────────

NOVA: {{ count }} patterns ({{ new }} new)
0din: {{ count }} patterns ({{ new }} new)

───────────────────────────────────────────────────────────────
FRAMEWORK COMPLIANCE
───────────────────────────────────────────────────────────────

ATLAS: {{ version }} ({{ technique_count }} techniques)
OWASP LLM: {{ version }} ({{ coverage }}/10)
OWASP Agentic: {{ version }} ({{ coverage }}/10)

───────────────────────────────────────────────────────────────
MEMORY POISONING
───────────────────────────────────────────────────────────────

Patterns: {{ total }} ({{ new }} new)
Sources: {{ sources_checked }}

═══════════════════════════════════════════════════════════════
Next Review: {{ +30 days }}
═══════════════════════════════════════════════════════════════

Sources:
{{ source_urls }}
```

## Examples

```
/vex-talon:intel-update              # Full update (all sources → config files)
/vex-talon:intel-update attacks      # NOVA + 0din → injection/patterns.json
/vex-talon:intel-update frameworks   # ATLAS + OWASP → framework/mappings.json
/vex-talon:intel-update memory       # Research → memory/config.json
/vex-talon:intel-update --check      # Preview without writing
```

## Update Frequency

| Source | Recommended |
|--------|-------------|
| Full Update | Monthly (1st Monday) |
| NOVA/0din | Weekly (if active) |
| Frameworks | Quarterly |
| Memory | Monthly |
