---
name: security-intel-update
description: Update Vex-Talon's security intelligence - syncs attack patterns (NOVA, 0din.ai, PromptIntel) AND framework compliance (ATLAS, OWASP). Updates the actual config files that hooks consume at runtime. USE WHEN user says "update security", "security intel update", "sync patterns", or when security coverage seems stale.
---

# Security Intelligence Update

Keep Vex-Talon's security layers current with latest attack patterns and framework compliance.

## CRITICAL: Update Runtime Config Files

**This skill MUST update the JSON config files that hooks consume at runtime.**

The config-loader (`packages/core/src/hooks/lib/config-loader.ts`) reads from `~/.vex-talon/config/`. Hooks fall back to hardcoded defaults if configs don't exist. When you find new patterns, you MUST write them to these files — NOT to memory/*.md files.

### Target Config Files (hooks consume these)

| Config File | Hook Consumer | Schema |
|-------------|--------------|--------|
| `~/.vex-talon/config/injection/patterns.json` | L4 Injection Scanner, L19 Skill Scanner | `InjectionPatternConfig` |
| `~/.vex-talon/config/code-enforcer/patterns.json` | L0 Secure Code Enforcer | `CodeEnforcerConfig` |
| `~/.vex-talon/config/egress/config.json` | L9 Egress Scanner | `EgressConfig` |
| `~/.vex-talon/config/supply-chain/config.json` | L14 Supply Chain Scanner | `SupplyChainConfig` |
| `~/.vex-talon/config/memory/config.json` | L3 Memory Validation, L3 Auto Memory Guardian | `MemoryConfig` |
| `~/.vex-talon/config/framework/atlas-owasp-mappings.json` | Stop Report (coverage calc) | `FrameworkMappings` |

**If a config file doesn't exist yet, CREATE it with the correct schema.**

### Config Schemas

**injection/patterns.json:**
```json
{
  "metadata": {
    "version": "1.0.0",
    "lastUpdated": "2026-02-05",
    "source": "NOVA + 0din.ai + PromptIntel + manual"
  },
  "patterns": [
    {
      "id": "nova-policy-puppetry",
      "category": "instruction_override",
      "severity": "CRITICAL",
      "pattern": "<interaction-config>|<system-prompt>",
      "description": "XML policy config injection (NOVA)",
      "source": "NOVA"
    }
  ]
}
```

**memory/config.json:**
```json
{
  "metadata": {
    "version": "1.0.0",
    "lastUpdated": "2026-02-05",
    "source": "Security intel update"
  },
  "thresholds": {
    "maxEntityNameLength": 100,
    "maxObservationLength": 2000,
    "maxObservationsPerBatch": 50,
    "maxEntitiesPerBatch": 20,
    "maxRelationsPerBatch": 50
  },
  "patterns": {
    "instructionInjection": [
      {
        "id": "mem-inj-ignore",
        "pattern": "ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+(instructions?|prompts?|rules?)",
        "severity": "CRITICAL",
        "description": "Instruction override in memory content"
      }
    ],
    "fakeFacts": [],
    "encodedContent": [],
    "contextManipulation": [],
    "sensitiveData": []
  },
  "trustedSources": ["user_direct_input"],
  "allowedEntityTypes": ["person", "project", "location", "work", "interest"]
}
```

**framework/atlas-owasp-mappings.json:**
```json
{
  "metadata": {
    "lastUpdated": "2026-02-05",
    "atlasVersion": "4.x",
    "owaspLlmVersion": "2025",
    "owaspAgenticVersion": "2026"
  },
  "atlas": {
    "techniques": [
      { "id": "AML.T0051", "name": "LLM Prompt Injection", "layers": ["L1", "L4", "L7", "L19"] }
    ]
  },
  "owaspLlm": {
    "items": [
      { "id": "LLM01", "name": "Prompt Injection", "layers": ["L1", "L4", "L7", "L19"], "status": "covered" }
    ]
  },
  "owaspAgentic": {
    "items": [
      { "id": "ASI01", "name": "Agent Prompt Injection", "layers": ["L1", "L4", "L19"], "status": "covered" }
    ]
  }
}
```

---

## Overview

| Domain | Sources | Target Config |
|--------|---------|---------------|
| **Attack Patterns** | NOVA Framework, 0din.ai, PromptIntel | `injection/patterns.json` |
| **Framework Compliance** | MITRE ATLAS, OWASP LLM/Agentic | `framework/atlas-owasp-mappings.json` |
| **Memory Poisoning** | Academic papers, AI security blogs | `memory/config.json` |
| **Standards Tracking** | Shield.md (Thomas Roccia) | `framework/atlas-owasp-mappings.json` |

## Commands

| Command | Description |
|---------|-------------|
| `/vex-talon:talon-intel-update` | Full update (all sources) |
| `/vex-talon:talon-intel-update attacks` | Attack patterns only (NOVA + 0din + PromptIntel) |
| `/vex-talon:talon-intel-update frameworks` | Framework compliance only |
| `/vex-talon:talon-intel-update memory` | Memory poisoning patterns only |
| `/vex-talon:talon-intel-update --check` | Check for updates without applying |

---

## Part 1: Attack Pattern Updates

### Sources

| Source | Type | Access |
|--------|------|--------|
| **NOVA Framework** | GitHub repo | WebFetch to GitHub |
| **0din.ai** | Bug bounty platform | Playwright MCP scraping |
| **PromptIntel** | Malicious prompt samples + threat intel (Thomas Roccia) | Official API (key required) |

### NOVA Framework

**Repository:** https://github.com/fr0gger/nova

Fetch latest rules:
```
WebFetch: https://github.com/fr0gger/nova/tree/main/rules
Prompt: List all .nov rule files with their rule_id, description, keywords, and severity
```

**NOVA Rule Format:**
```yaml
rule_id: policy_puppetry
description: Detects XML policy config injection
keywords: ["<interaction-config>", "<system-prompt>"]
severity: CRITICAL
```

**Convert to config-loader format and WRITE to `~/.vex-talon/config/injection/patterns.json`:**
```json
{
  "id": "nova-policy-puppetry",
  "category": "instruction_override",
  "severity": "CRITICAL",
  "pattern": "<interaction-config>|<system-prompt>",
  "description": "XML policy config injection",
  "source": "NOVA"
}
```

### 0din.ai Disclosures

**Website:** https://0din.ai/disclosures

**⚠️ Playwright MCP Required:** 0din.ai is a JavaScript-rendered SPA. You MUST check if Playwright MCP tools are available before attempting to scrape it.

**Check availability:**
```
Try calling mcp__playwright__browser_navigate — if the tool doesn't exist, Playwright is NOT available.
```

**If Playwright IS available (preferred):**
```
1. mcp__playwright__browser_navigate({ url: "https://0din.ai/disclosures" })
2. mcp__playwright__browser_snapshot()
3. Extract disclosure list, severity, taxonomies
```

**If Playwright is NOT available (fallback):**
```
1. WebSearch: "0din.ai disclosure" site:0din.ai 2026
2. WebSearch: "0din.ai LLM vulnerability" new disclosure 2026
3. WebFetch: https://0din.ai — extract any server-rendered content
4. Note in report: "0din.ai data from WebSearch (Playwright unavailable — results may be incomplete)"
```

**⚠️ Fallback limitation:** WebSearch/WebFetch cannot access JavaScript-rendered disclosure details (severity scores, taxonomy breakdowns, test parameters). The fallback provides disclosure titles and summaries only. For full extraction, ensure Playwright MCP is configured.

**Extract (from either method):**
- Disclosure ID, title, severity
- Test scores (model, temperature) — *Playwright only*
- Attack taxonomies → convert to regex patterns

**Convert and APPEND to `~/.vex-talon/config/injection/patterns.json`**

### PromptIntel (IoPC Threat Feed)

**Website:** https://promptintel.novahunting.ai/
**Author:** Thomas Roccia (same author as NOVA Framework)
**API Base URL:** `https://api.promptintel.novahunting.ai/api/v1`
**API Docs:** https://promptintel.novahunting.ai/api
**Auth:** `Authorization: Bearer ak_your_api_key` (health endpoint is public)
**Third-party sync repo:** https://github.com/xampla/threatfeeds-to-nova (community tool — NOT official PromptIntel or NOVA)

PromptIntel is an IoPC (Indicators of Prompt Compromise) platform by Thomas Roccia that collects malicious prompt samples.

**API Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | Public | Health check, version info |
| `/prompts` | GET | API key | List prompts (page, limit, search, severity, category) |
| `/prompts/{id}` | GET | API key | Get specific prompt by ID |
| `/prompts/search` | POST | API key | Advanced search with filters |
| `/taxonomy` | GET | API key | Full threat taxonomy (4 categories) |

**Categories for filtering:** `manipulation`, `abuse`, `patterns`, `outputs`

**Rule Quality Tiers (as seen in xampla community sync):**

| Tier | Prefix | Quality | Count (~) | Use |
|------|--------|---------|-----------|-----|
| **Hand-Crafted** | `PI_HC_*` | High — novel patterns, semantic matching | ~9 | Cherry-pick all |
| **Auto-Generated** | `PI_AUTO_*` | Basic — keyword matching, some overlap | ~40 | Selective |
| **MoltThreats** | `Molt_AUTO_*` | Threat intel — IOCs, campaign-specific | ~20 | Reference only |

**Cherry-Pick Strategy:** Focus on HC (hand-crafted) rules — these contain novel attack patterns not in NOVA core. AUTO rules often overlap with existing patterns. Molt rules are campaign-specific threat intel (IOCs, infrastructure) less relevant for prompt injection detection.

**Key HC Rules (high value for Vex-Talon):**
- `PI_HC_88ebf0a9_RoutineDataExfiltration` — disguised data exfil as routine operations
- `PI_HC_4f7fc901_ReceiveCommandExecPrompt` — reverse shell / command execution
- `PI_HC_157f6289_Join_Injection_string` — URL concatenation concealment
- `PI_HC_5ab46e79_AnonymousDataExfiltration` — anonymous exfil channels

**Method 1: Official API (preferred)**

```bash
# Health check (no key needed)
curl https://api.promptintel.novahunting.ai/api/v1/health

# List latest critical prompts (requires API key)
curl -H "Authorization: Bearer $PROMPTINTEL_API_KEY" \
  "https://api.promptintel.novahunting.ai/api/v1/prompts?limit=50&severity=critical"

# Advanced search for manipulation patterns
curl -X POST -H "Authorization: Bearer $PROMPTINTEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "injection", "filters": {"severity": ["high", "critical"], "categories": ["manipulation"]}}' \
  https://api.promptintel.novahunting.ai/api/v1/prompts/search

# Get full taxonomy
curl -H "Authorization: Bearer $PROMPTINTEL_API_KEY" \
  https://api.promptintel.novahunting.ai/api/v1/taxonomy
```

**Method 2: Browse via Playwright (visual exploration)**

```
1. mcp__playwright__browser_navigate({ url: "https://promptintel.novahunting.ai/feed" })
2. mcp__playwright__browser_snapshot()  # Get prompt listings
3. For each new entry:
   - Click to view details
   - Extract: title, severity, category, keywords
   - Navigate back
```

**Method 3: Third-party GitHub Repo (community pre-synced NOVA rules)**

⚠️ `xampla/threatfeeds-to-nova` is a community-maintained repo, NOT official PromptIntel or NOVA. Rules may lag behind the official source.

```
WebFetch: https://github.com/xampla/threatfeeds-to-nova/tree/main/rules/PromptIntel
Prompt: List all PI_HC_* rule files with rule_id, description, keywords, semantics, severity
```

**Method 4: WebSearch Fallback**

```
WebSearch: site:promptintel.novahunting.ai new samples 2026
WebSearch: "PromptIntel" "Thomas Roccia" new rules 2026
```

**Convert patterns and WRITE to `~/.vex-talon/config/injection/patterns.json`:**
```json
{
  "id": "pi-hc-routine-data-exfil",
  "category": "data_exfiltration",
  "severity": "HIGH",
  "pattern": "routine\\s+(data|backup|sync).*?(send|upload|transfer|post)",
  "description": "Disguised data exfiltration as routine operations (PromptIntel HC)",
  "source": "PromptIntel"
}
```

### Writing Attack Patterns

After fetching from sources:

1. Read existing `~/.vex-talon/config/injection/patterns.json` (or start fresh)
2. Merge new patterns (deduplicate by `id`)
3. Update `metadata.lastUpdated`
4. Validate JSON with `jq '.' ~/.vex-talon/config/injection/patterns.json`
5. Write back

**IMPORTANT:** Preserve existing patterns — only ADD new ones. Never delete user-customized patterns.

---

## Part 2: Framework Compliance

### Sources

| Source | URL | Focus |
|--------|-----|-------|
| **MITRE ATLAS** | https://atlas.mitre.org/techniques | AI/ML attack techniques |
| **OWASP LLM** | https://genai.owasp.org/llm-top-10/ | LLM application risks |
| **OWASP Agentic** | https://genai.owasp.org/ | Autonomous agent risks |
| **Shield.md** | https://nova-hunting.github.io/shield.md/ | AI agent security spec (Thomas Roccia) |

### Vex-Talon Relevant ATLAS Techniques

**Include (agentic code assistants):**
- AML.T0035 - Exfiltration via ML Inference API
- AML.T0047 - ML Supply Chain Compromise
- AML.T0048 - Adversarial Example (visual injection)
- AML.T0051 - LLM Prompt Injection (direct/indirect)
- AML.T0053 - LLM Plugin Compromise
- AML.T0056 - LLM Meta Prompt Extraction
- AML.T0057 - LLM Data Leakage
- AML.T0062 - Exfiltration via Agent Tools
- AML.T0063 - AI Agent Context Poisoning
- AML.T0064 - Memory Manipulation
- AML.T0065 - Thread Injection
- AML.T0066 - Modify AI Agent Configuration
- AML.T0067 - RAG Credential Harvesting
- AML.T0068 - RAG Poisoning

### Layer Coverage Mapping

| OWASP LLM | Layers | Status |
|-----------|--------|--------|
| LLM01 Prompt Injection | L1, L4, L7, L19 | Covered |
| LLM02 Sensitive Info | L0, L1, L9 | Covered |
| LLM03 Supply Chain | L14 | Covered |
| LLM04 Data Poisoning | L3†, L15* | Covered |
| LLM05 Output Handling | L5 | Covered |
| LLM06 Excessive Agency | L9, L12 | Covered |
| LLM07 System Prompt Leakage | L9 | Covered |
| LLM08 Embedding Weaknesses | L15* | Optional |
| LLM09 Misinformation | L13* | Optional |
| LLM10 Unbounded Consumption | L17 | Covered |

| OWASP Agentic | Layers | Status |
|---------------|--------|--------|
| ASI01 Agent Prompt Injection | L1, L4, L19 | Covered |
| ASI02 Credential Misuse | L1, L9 | Covered |
| ASI04 Dependency Chain | L14, L19 | Covered |
| ASI05 Output Mishandling | L5 | Covered |
| ASI06 Memory Poisoning | L3† | Detection |
| ASI07 Multi-Agent | L12 | Partial |
| ASI08 Cascading Hallucinations | L1, L2 | Partial |
| ASI09 Resource Exploitation | L17 | Covered |
| ASI10 Uncontrolled Permissions | L12, L1 | Covered |

### Writing Framework Mappings

**WRITE to `~/.vex-talon/config/framework/atlas-owasp-mappings.json`:**

1. Fetch latest from ATLAS and OWASP
2. Compare with existing file (or create fresh)
3. Update version numbers and coverage
4. Note any new gaps requiring new layers
5. Write JSON

---

## Part 3: Memory Poisoning Patterns

### Why This Matters

Memory poisoning persists across sessions. L3 Memory Validation (PreToolUse) and L3 Auto Memory Guardian (SessionStart) both consume these patterns.

### Sources to Monitor

| Source | URL | Frequency |
|--------|-----|-----------|
| OWASP Agentic | owasp.org/www-project-top-10-for-agentic-ai/ | Quarterly |
| Simon Willison | simonwillison.net | Weekly |
| Anthropic Research | anthropic.com/research | Monthly |
| arXiv cs.CR | arxiv.org/list/cs.CR/recent | Weekly |
| Trail of Bits | blog.trailofbits.com | Monthly |

### Search Queries

```
WebSearch: "LLM memory poisoning" OR "agent memory attack" 2026
WebSearch: "MCP memory server" security vulnerability 2026
WebSearch: "knowledge graph poisoning" language model 2026
```

### Writing Memory Patterns

**WRITE to `~/.vex-talon/config/memory/config.json`:**

1. Read existing config (or create with schema above)
2. Add new patterns to appropriate category:
   - `instructionInjection` — command override patterns
   - `fakeFacts` — false context injection
   - `encodedContent` — obfuscation techniques
   - `contextManipulation` — fake system markers
   - `sensitiveData` — credential/PII patterns
3. Each pattern needs: `id`, `pattern` (regex), `severity`, `description`
4. Update `metadata.lastUpdated`
5. Validate JSON
6. Write back

**Pattern Development Guidelines:**
- Specific enough to avoid false positives on legitimate memory
- Regex must compile without error
- No nested quantifiers (ReDoS risk — config-loader rejects these)
- Include severity classification
- Test against legitimate content before adding

---

## Full Update Workflow

### Step 1: Check Current Status

Read existing configs:
```bash
cat ~/.vex-talon/config/injection/patterns.json 2>/dev/null | jq '.metadata' || echo "No injection config"
echo "PromptIntel HC patterns:" && cat ~/.vex-talon/config/injection/patterns.json 2>/dev/null | jq '[.patterns[] | select(.source == "PromptIntel")] | length' || echo "0"
cat ~/.vex-talon/config/memory/config.json 2>/dev/null | jq '.metadata' || echo "No memory config"
cat ~/.vex-talon/config/framework/atlas-owasp-mappings.json 2>/dev/null | jq '.metadata' || echo "No framework config"
```

### Step 2: Fetch & Update (per scope)

Execute the relevant Part (1, 2, 3) above.

**For each update:**
1. Fetch from source
2. Read existing config file (or use empty template)
3. Merge new patterns (preserve existing, deduplicate by ID)
4. Update metadata.lastUpdated
5. Validate JSON: `jq '.' <file>`
6. Write to `~/.vex-talon/config/<path>`

### Step 2.5: Check Shield.md Evolution (Quarterly)

1. Check Shield.md repo for version changes:
```
WebFetch: https://nova-hunting.github.io/shield.md/
Prompt: What is the current Shield.md version? List threat categories, action types, and any changes since v0.

gh api repos/Nova-Hunting/shield.md/commits --jq '.[0:5] | .[] | "\(.sha[0:7]) \(.commit.message) (\(.commit.author.date[0:10]))"'
```
2. Track key evolution signals:
   - Version bump (v0 → v1 = external enforcement, major milestone)
   - New threat categories beyond the original 11
   - Community adoption (stars, forks, integrations)
   - Tooling (parsers, validators, runtime enforcers)
3. Note findings in report under "Standards Tracking"

### Step 3: Generate Report

Show what was found, what was added, and which config files were updated.

### Step 4: Verify

After writing configs, verify hooks can load them:
```bash
# Quick validation
jq '.' ~/.vex-talon/config/injection/patterns.json > /dev/null && echo "injection: valid"
jq '.' ~/.vex-talon/config/memory/config.json > /dev/null && echo "memory: valid"
jq '.' ~/.vex-talon/config/framework/atlas-owasp-mappings.json > /dev/null && echo "framework: valid"
```

---

## Update Frequency

| Source | Recommended | Rationale |
|--------|-------------|-----------|
| NOVA Framework | Monthly | 1-2 rules/quarter |
| 0din.ai | Weekly | 1-3/week |
| PromptIntel | Monthly | Daily API updates, cherry-pick HC rules monthly |
| MITRE ATLAS | Quarterly | Infrequent updates |
| OWASP LLM | Quarterly | Annual cycle |
| OWASP Agentic | Quarterly | New framework |
| Shield.md | Quarterly | Watch for v1 (external enforcement), adoption signals |
| Memory Patterns | Monthly | Emerging area |

**Trigger:** First Monday of month, or when coverage seems stale.

---

## External Resources

### Frameworks
- MITRE ATLAS: https://atlas.mitre.org/techniques
- OWASP LLM: https://genai.owasp.org/llm-top-10/
- OWASP Agentic: https://genai.owasp.org/

### Attack Patterns
- NOVA Framework: https://github.com/fr0gger/nova
- 0din.ai: https://0din.ai/disclosures
- PromptIntel (Thomas Roccia): https://promptintel.novahunting.ai/
- Third-party NOVA sync (xampla, community): https://github.com/xampla/threatfeeds-to-nova

### Standards & Specs
- Shield.md Spec: https://nova-hunting.github.io/shield.md/
- Shield.md Repo: https://github.com/Nova-Hunting/shield.md
- Shield.md Blog: https://blog.securitybreak.io/shield-md-a-security-standard-for-openclaw-and-ai-agents-b38637031460

### Research
- Simon Willison: https://simonwillison.net/
- Anthropic Research: https://anthropic.com/research
- Trail of Bits: https://blog.trailofbits.com/

---

**Version:** 2.2.0
**Ported from:** Vex PAI security-intel-update skill v1.3.0
**Updated:** 2026-02-13
**Changes:** Added Shield.md (Thomas Roccia) as standards tracking source — quarterly check for spec evolution, v1 milestone, community adoption
