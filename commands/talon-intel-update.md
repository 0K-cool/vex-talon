---
name: talon-intel-update
description: Update Vex-Talon security intelligence - sync attack patterns and framework compliance
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

When the user runs `/talon-intel-update`, execute the security-intel-update skill.

### 1. Check Current Status

Display current versions and last update dates:

```
╔══════════════════════════════════════════════════════════════╗
║           VEX-TALON SECURITY INTELLIGENCE STATUS             ║
╠══════════════════════════════════════════════════════════════╣
║  Framework Versions:                                         ║
║    MITRE ATLAS: {{ atlas_version }}                          ║
║    OWASP LLM:   {{ owasp_version }}                          ║
║    OWASP Agentic: {{ agentic_version }}                      ║
║                                                              ║
║  Pattern Sources:                                            ║
║    NOVA Rules:  {{ nova_count }} rules (last: {{ date }})    ║
║    0din.ai:     {{ odin_count }} disclosures                 ║
║                                                              ║
║  Coverage:                                                   ║
║    OWASP LLM:    9/10 covered                                ║
║    OWASP Agentic: 8/10 covered, 2 partial                    ║
║    ATLAS:        16 techniques mapped                        ║
╚══════════════════════════════════════════════════════════════╝
```

### 2. Execute Update (based on scope)

**If scope includes "attacks":**

1. **NOVA Framework Sync**
   ```
   WebFetch: https://github.com/Nova-Hunting/nova/tree/main/rules
   Prompt: List all .nov rule files. Extract rule_id, description, keywords, severity.
   ```
   - Compare with existing patterns
   - Add new patterns to injection-patterns.json
   - Log additions to update report

2. **0din.ai Sync**
   ```
   mcp__playwright__browser_navigate: https://0din.ai/disclosures
   mcp__playwright__browser_snapshot: Extract disclosure list
   ```
   - Get disclosure IDs, titles, severities
   - Extract attack taxonomies
   - Add new patterns to configs

**If scope includes "frameworks":**

1. **MITRE ATLAS Check**
   ```
   WebFetch: https://atlas.mitre.org/techniques
   Prompt: List LLM-related techniques (AML.T0051-T0068). Note version and any NEW techniques.
   ```
   - Compare with current mappings
   - Update coverage tables if changed

2. **OWASP Check**
   ```
   WebFetch: https://genai.owasp.org/llm-top-10/
   Prompt: List OWASP LLM Top 10 2025/2026 items. Note any changes.

   WebFetch: https://genai.owasp.org/
   Prompt: Check OWASP Agentic 2026 items (ASI01-ASI10). Note any updates.
   ```
   - Compare versions
   - Update coverage status

**If scope includes "memory":**

1. **Research Check**
   ```
   WebSearch: "LLM memory poisoning" OR "agent memory attack" 2026
   WebSearch: "MCP memory" security vulnerability
   ```
   - Find new attack techniques
   - Extract patterns
   - Update memory-patterns.json

### 3. Generate Report

```
═══════════════════════════════════════════════════════════════
        VEX-TALON SECURITY INTELLIGENCE UPDATE
═══════════════════════════════════════════════════════════════

Date: {{ timestamp }}
Scope: {{ scope }}

───────────────────────────────────────────────────────────────
ATTACK PATTERNS
───────────────────────────────────────────────────────────────

NOVA Framework:
  Status: {{ nova_status }}
  New Rules: {{ nova_new_count }}
  {{ nova_new_rules_list }}

0din.ai:
  Status: {{ odin_status }}
  New Disclosures: {{ odin_new_count }}
  {{ odin_new_list }}

───────────────────────────────────────────────────────────────
FRAMEWORK COMPLIANCE
───────────────────────────────────────────────────────────────

MITRE ATLAS:
  Current: {{ atlas_version }}
  New Techniques: {{ atlas_new_count }}

OWASP LLM:
  Version: {{ owasp_version }}
  Coverage: {{ owasp_coverage }}/10

OWASP Agentic:
  Version: {{ agentic_version }}
  Coverage: {{ agentic_coverage }}/10

───────────────────────────────────────────────────────────────
MEMORY POISONING
───────────────────────────────────────────────────────────────

Research Sources Checked: {{ memory_sources_count }}
New Patterns Found: {{ memory_new_count }}
{{ memory_new_patterns }}

───────────────────────────────────────────────────────────────
FILES UPDATED
───────────────────────────────────────────────────────────────

{{ updated_files_list }}

═══════════════════════════════════════════════════════════════
Next Review: {{ next_review_date }} (+30 days)
═══════════════════════════════════════════════════════════════
```

## Examples

**Full update (all sources):**
```
/talon-intel-update
```

**Check for updates without applying:**
```
/talon-intel-update --check
```

**Update attack patterns only:**
```
/talon-intel-update attacks
```

**Update framework compliance only:**
```
/talon-intel-update frameworks
```

**Update memory poisoning patterns:**
```
/talon-intel-update memory
```

## Update Frequency

| Source | Recommended |
|--------|-------------|
| Full Update | Monthly (1st Monday) |
| NOVA/0din | Weekly (if active development) |
| Frameworks | Quarterly |
| Memory Patterns | Monthly |

## Related Commands

- `/talon` - Run security scan
- `/talon-status` - View security layer status
- `/talon-report` - Generate security report
