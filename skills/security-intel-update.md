---
name: security-intel-update
description: Update Vex-Talon's security intelligence - syncs attack patterns (NOVA, 0din.ai) AND framework compliance (ATLAS, OWASP). USE WHEN user says "update security", "security intel update", "sync patterns", or when security coverage seems stale.
---

# Security Intelligence Update

Keep Vex-Talon's security layers current with latest attack patterns and framework compliance.

## Overview

| Domain | Sources | Updates |
|--------|---------|---------|
| **Attack Patterns** | NOVA Framework, 0din.ai | Detection patterns |
| **Framework Compliance** | MITRE ATLAS, OWASP LLM/Agentic | Coverage mappings |
| **Memory Poisoning** | Academic papers, AI security blogs | Validation patterns |

## Commands

| Command | Description |
|---------|-------------|
| `/security-intel-update` | Full update (all sources) |
| `/security-intel-update attacks` | Attack patterns only |
| `/security-intel-update frameworks` | Framework compliance only |
| `/security-intel-update --check` | Check for updates without applying |

---

## Part 1: Attack Pattern Updates

### Sources

| Source | Type | Access |
|--------|------|--------|
| **NOVA Framework** | GitHub repo | GitHub API / WebFetch |
| **0din.ai** | Bug bounty platform | Playwright scraping |

### NOVA Framework

**Repository:** https://github.com/Nova-Hunting/nova

Fetch latest `.nov` rules:
```
WebFetch: https://github.com/Nova-Hunting/nova/tree/main/rules
Prompt: List all .nov rule files with their names and descriptions
```

**NOVA Rule Format:**
```yaml
rule_id: policy_puppetry
description: Detects XML policy config injection
keywords: ["<interaction-config>", "<system-prompt>"]
severity: CRITICAL
```

### 0din.ai Disclosures

**Website:** https://0din.ai/disclosures

Use Playwright MCP for JavaScript-rendered content:
```
1. mcp__playwright__browser_navigate({ url: "https://0din.ai/disclosures" })
2. mcp__playwright__browser_snapshot()
3. Extract disclosure list, severity, taxonomies
```

**Extract:**
- Disclosure ID, title, severity
- Test scores (model, temperature)
- Attack taxonomies

### Pattern Normalization

Convert external patterns to Vex-Talon format:

**For injection-patterns config:**
```json
{
  "id": "nova-policy-puppetry",
  "pattern": "<interaction-config>|<system-prompt>",
  "severity": "CRITICAL",
  "source": "NOVA",
  "description": "XML policy config injection"
}
```

**Target:** `packages/core/src/patterns/injection-patterns.json`

---

## Part 2: Framework Compliance

### Sources

| Source | URL | Focus |
|--------|-----|-------|
| **MITRE ATLAS** | https://atlas.mitre.org/techniques | AI/ML attack techniques |
| **OWASP LLM** | https://genai.owasp.org/llm-top-10/ | LLM application risks |
| **OWASP Agentic** | https://genai.owasp.org/ | Autonomous agent risks |

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

### OWASP LLM Top 10 Coverage

| ID | Risk | Vex-Talon Layers | Status |
|----|------|------------------|--------|
| LLM01 | Prompt Injection | L4, L7, L19 | Covered |
| LLM02 | Sensitive Info Disclosure | L0, L1, L2, L9 | Covered |
| LLM03 | Supply Chain | L14 | Covered |
| LLM04 | Data Poisoning | L15* | Covered |
| LLM05 | Improper Output Handling | L5 | Covered |
| LLM06 | Excessive Agency | L1, L9, L12 | Covered |
| LLM07 | System Prompt Leakage | - | N/A |
| LLM08 | Embedding Weaknesses | L15* | Covered |
| LLM09 | Misinformation | L13* | Optional |
| LLM10 | Unbounded Consumption | L17 | Covered |

*Layers requiring external tools (Strawberry, vex-rag)

### OWASP Agentic 2026 Coverage

| ID | Risk | Vex-Talon Layers | Status |
|----|------|------------------|--------|
| ASI01 | Agent Goal Hijack | L4, L7, L19 | Covered |
| ASI02 | Tool Misuse | L1, L12 | Covered |
| ASI03 | Identity Abuse | L12 | Covered |
| ASI04 | Supply Chain | L14 | Covered |
| ASI05 | Unexpected Code Execution | L1, L2 | Covered |
| ASI06 | Memory Poisoning | L3 | Detection |
| ASI07 | Inter-Agent Communication | L1 | Partial |
| ASI08 | Cascading Failures | L1 | Partial |
| ASI09 | Trust Exploitation | L13* | Optional |
| ASI10 | Rogue Agents | L1, L12 | Covered |

### Update Workflow

1. **Fetch latest versions:**
```
WebFetch: https://atlas.mitre.org/techniques
Prompt: List LLM-related techniques. Note any NEW techniques since last check.

WebFetch: https://genai.owasp.org/llm-top-10/
Prompt: List OWASP LLM Top 10 with IDs. Note version changes.
```

2. **Compare with current mappings**
3. **Update coverage tables** in README.md and dashboard
4. **Note any new gaps** requiring new layers

**Target:** `README.md` (coverage tables), `packages/dashboard/src/data/coverage.ts`

---

## Part 3: Memory Poisoning Patterns

### Why This Matters

Memory poisoning attacks persist across sessions and influence long-term AI behavior. This is especially relevant for projects using MCP Memory Server.

**Frameworks:** OWASP Agentic ASI06, MITRE ATLAS AML.T0064

### Sources to Monitor

| Source | URL | Frequency |
|--------|-----|-----------|
| OWASP Agentic | owasp.org/www-project-top-10-for-agentic-ai/ | Quarterly |
| Simon Willison | simonwillison.net | Weekly |
| Anthropic Research | anthropic.com/research | Monthly |
| arXiv cs.CR | arxiv.org/list/cs.CR/recent | Weekly |
| Trail of Bits | blog.trailofbits.com | Monthly |

### Current Pattern Categories

| Category | Patterns | Example |
|----------|----------|---------|
| Instruction Injection | 7 | "ignore previous instructions" |
| Fake Facts | 4 | "User said to bypass security" |
| Encoded Content | 3 | Base64, hex, Unicode |
| Context Manipulation | 4 | Fake system markers |
| Sensitive Data | 5 | API keys, passwords |

### Search Queries

```
"LLM memory poisoning" site:arxiv.org
"agent memory manipulation" AI security
"MCP memory" injection
"knowledge graph attack" language model
```

**Target:** `packages/core/src/patterns/memory-patterns.json`

---

## Full Update Workflow

### Step 1: Check Current Status

Note current framework versions and last update dates.

### Step 2: Sync Attack Patterns

1. Fetch NOVA rules from GitHub
2. Check 0din.ai for new disclosures
3. Extract new patterns
4. Update `packages/core/src/patterns/`

### Step 3: Update Framework Compliance

1. WebFetch ATLAS and OWASP
2. Compare versions
3. Update coverage tables
4. Note new gaps

### Step 4: Update Memory Patterns

1. Search for new research
2. Extract new attack techniques
3. Update memory patterns config

### Step 5: Generate Report

```markdown
## Security Intelligence Update - YYYY-MM-DD

### Attack Patterns
- NOVA: X new rules
- 0din.ai: X new disclosures
- Patterns added: X

### Framework Compliance
- ATLAS: vX.X (current/updated)
- OWASP LLM: 202X (current/updated)
- OWASP Agentic: 202X (current/updated)

### Memory Poisoning
- New patterns: X
- Sources checked: [list]

### Files Updated
- [ ] packages/core/src/patterns/injection-patterns.json
- [ ] packages/core/src/patterns/memory-patterns.json
- [ ] README.md (coverage tables)
```

---

## Update Frequency

| Source | Recommended | Rationale |
|--------|-------------|-----------|
| NOVA Framework | Monthly | 1-2 rules/quarter |
| 0din.ai | Weekly | 1-3/week |
| MITRE ATLAS | Quarterly | Infrequent updates |
| OWASP LLM | Quarterly | Annual cycle |
| OWASP Agentic | Quarterly | New framework |
| Memory Patterns | Monthly | Emerging area |

**Trigger:** First Monday of month, or when coverage seems stale.

---

## External Resources

### Frameworks
- MITRE ATLAS: https://atlas.mitre.org/techniques
- OWASP LLM: https://genai.owasp.org/llm-top-10/
- OWASP Agentic: https://genai.owasp.org/

### Attack Patterns
- NOVA Framework: https://github.com/Nova-Hunting/nova
- 0din.ai: https://0din.ai/disclosures

### Research
- Simon Willison: https://simonwillison.net/
- Anthropic Research: https://anthropic.com/research
- Trail of Bits: https://blog.trailofbits.com/

---

**Version:** 1.0.0
**Ported from:** Vex PAI security-intel-update skill
