# Vex-Talon

![Vex-Talon Banner](vex-talon-banner.jpg)

**20-layer defense-in-depth security plugin for Claude Code.**

*Vex (velociraptor) + Talon (claw) — sharp, fast, always watching. Defense-in-depth security that strikes before threats land.*

Zero cloud dependencies. OWASP LLM 2025 + MITRE ATLAS coverage. Works out of the box.

```bash
/plugin install vex-talon@0K-cool/vex-talon
```

---

## Why Vex-Talon?

Claude Code is powerful. But with great power comes great attack surface:

- **Prompt injection** via files, images, MCP tools, and web content
- **Data exfiltration** through tool calls, curl commands, and encoded payloads
- **Supply chain attacks** via malicious npm/pip packages
- **Memory poisoning** through MCP memory server manipulation
- **Credential exposure** from hardcoded secrets and .env files
- **Unbounded spending** from runaway agent loops

Most developers run Claude Code with zero security layers. Vex-Talon adds 20.

---

## What You Get (Out of the Box)

14 security hooks activate automatically after installation. No configuration required.

### PreToolUse Hooks (Block Before Execution)

| Layer | Name | What It Does |
|-------|------|-------------|
| **L0** | Secure Code Enforcer | Blocks CRITICAL vulnerabilities (SQL injection, command injection, hardcoded secrets) before code is written |
| **L1** | Governor Agent | 33+ policy enforcement rules. Blocks dangerous operations, modifies risky inputs (e.g., `curl \| sh` replaced with safe warning) |
| **L3** | Memory Validation | Detects instruction injection, fake facts, and context manipulation in MCP memory operations |
| **L9** | Egress Scanner | Prevents data exfiltration via secrets in URLs, bulk data transfer, base64-encoded payloads, and blocked destinations (pastebin, ngrok, webhook.site) |
| **L14** | Supply Chain Pre-Install | Blocks 60+ known malicious packages before installation. Optional real-time API via OpenSourceMalware.com |
| **L19** | Skill Scanner | Scans skills for injection patterns, dangerous commands, credential exposure, and external URLs before invocation |

### PostToolUse Hooks (Detect After Execution)

| Layer | Name | What It Does |
|-------|------|-------------|
| **L2** | Secure Code Linter | Post-write security analysis with static analysis + optional LLM review |
| **L4** | Injection Scanner | Detects prompt injection in tool outputs (89+ patterns including NOVA framework rules) |
| **L5** | Output Sanitizer | Scans web files for XSS vectors: innerHTML, dangerouslySetInnerHTML, eval(), document.write |
| **L7** | Image Safety Scanner | Detects steganography, visual prompt injection, and adversarial content in images |
| **L14** | Supply Chain Post-Install | Runs `npm audit` / `pip-audit` after package installations and warns on vulnerabilities |
| **L17** | Spend Alerting | Tracks session costs and alerts at $5 / $10 / $20 thresholds (OWASP LLM10) |

### SessionStart & Stop Hooks

| Layer | Name | What It Does |
|-------|------|-------------|
| **L12** | Least Privilege Profiles | Initializes session with permission profiles (dev, audit, client-work, research) |
| **STOP** | Security Report | Generates HTML security report at session end with all events, severity breakdown, and recommendations |

### Dual Notification Pattern

All PostToolUse hooks implement a dual notification pattern:

1. **`console.error()`** - Visual alert displayed directly to the user
2. **`additionalContext`** - Warning injected into the AI's context window

This ensures both the user AND the AI are aware of detected threats. PostToolUse hooks cannot block content that's already in context, but `additionalContext` tells Claude to treat flagged content as untrusted.

---

## Installation

### Requirements

- [Claude Code](https://claude.com/claude-code) (CLI)
- [Bun](https://bun.sh) runtime (hooks are TypeScript)

### Install the Plugin

```bash
/plugin install vex-talon@0K-cool/vex-talon
```

All 14 hooks activate on your next Claude Code session.

### Verify

```bash
/plugin list          # Should show vex-talon
```

Security events log to `~/.vex-talon/logs/` and a summary report generates when your session ends.

---

## Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `OSM_API_TOKEN` | OpenSourceMalware.com API key for real-time supply chain scanning | _(none - uses hardcoded blocklist only)_ |
| `VEX_TALON_PROFILE` | Permission profile: `dev`, `audit`, `client-work`, `research` | `dev` |
| `TALON_DIR` | Custom data directory | `~/.vex-talon` |

### Permission Profiles (L12)

Control what tools and directories are accessible per session:

```bash
# Full access (default)
claude

# Read-only for security audits
VEX_TALON_PROFILE=audit claude

# No external network access (confidential work)
VEX_TALON_PROFILE=client-work claude

# Read-only with web search (research mode)
VEX_TALON_PROFILE=research claude
```

| Profile | Tools | Network | Writes |
|---------|-------|---------|--------|
| `dev` | All | All | All |
| `audit` | Read, Glob, Grep, Bash, Web | All | None |
| `client-work` | All except WebFetch/WebSearch | Blocked | Limited |
| `research` | Read, Glob, Grep, Web | All | None |

### Supply Chain API (L14)

The PreToolUse supply chain scanner has two modes:

**Without API token (default):** 60+ hardcoded malicious packages blocked instantly. No network calls, works offline.

**With API token:** Real-time lookups against [OpenSourceMalware.com](https://opensourcemalware.com/) + 24-hour local cache + hardcoded blocklist.

```bash
# Sign up at https://opensourcemalware.com for a free API token
export OSM_API_TOKEN=your_token_here
claude
```

Supported package managers: npm, yarn, pnpm, pip, cargo, go.

### Extending Detection Patterns

Add custom security patterns without modifying hook code. Place JSON configs in `~/.vex-talon/config/`:

| Config File | Purpose |
|-------------|---------|
| `injection/patterns.json` | Custom prompt injection patterns |
| `egress/config.json` | Blocked destinations, secret patterns, PII patterns |
| `code-enforcer/patterns.json` | Vulnerability detection patterns |
| `image-safety/config.json` | Stego signatures, visual injection patterns |
| `output-sanitizer/patterns.json` | XSS/output sanitization rules |
| `supply-chain/config.json` | Additional malicious package entries |

Configs are loaded with 60-second cache TTL and automatic fallback to built-in defaults if the file is missing or invalid.

---

## What You Should Consider Adding

Vex-Talon provides the hook-based security layers. The full 20-layer architecture includes layers you can set up yourself for even deeper protection.

### Git Hooks (Recommended)

| Layer | What | How to Set Up |
|-------|------|--------------|
| **L6** Git Pre-commit | Scan staged commits for secrets, API keys, and PII before they enter git history | Add [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog) to `.git/hooks/pre-commit` |
| **L8** Evaluator Agent | Post-commit validation that scans committed diffs for security issues | Add a `.git/hooks/post-commit` script that runs static analysis on changed files |

### Claude Code Built-in Features (Already Available)

| Layer | What | How to Enable |
|-------|------|--------------|
| **L10** Native Sandbox | OS-level sandbox (Seatbelt on macOS, bubblewrap on Linux) restricts file and network access | `claude --sandbox` or `/sandbox` inside Claude Code |
| **L16** Human Decision | You approve or deny each tool call before Claude Code executes it | Built into Claude Code's permission system (default behavior) |

### Optional External Tools (Advanced)

| Layer | What | Requires |
|-------|------|----------|
| **L11** Leash Kernel Sandbox | eBPF-based kernel sandbox with no prompt-injection bypass. For high-security and client work | [Leash](https://github.com/anthropics/leash) binary (Linux with eBPF) |
| **L13** Strawberry Hallucination Detector | Information-theoretic hallucination detection via KL divergence. For threat intel, client deliverables | [hallucination-detector MCP](https://github.com/0K-cool/hallucination-detector) + OpenAI API key |
| **L15** RAG Security Scanner | Anti-poisoning for RAG knowledge bases: injection detection, Unicode normalization, provenance tracking | [vex-rag](https://github.com/0K-cool/vex-rag) plugin |
| **L18** MCP Audit | Pre-deployment security scanning for MCP servers using NOVA injection rules | [Proximity](https://github.com/anthropics/proximity) scanner |

---

## Framework Coverage

### OWASP LLM Top 10 (2025) - 9/10

| # | Vulnerability | Vex-Talon Coverage |
|---|--------------|-------------------|
| LLM01 | Prompt Injection | L1 Governor, L4 Injection Scanner, L7 Image Safety, L19 Skill Scanner |
| LLM02 | Sensitive Information Disclosure | L0 Code Enforcer, L1 Governor, L9 Egress Scanner |
| LLM03 | Supply Chain Vulnerabilities | L14 Pre-Install (block) + Post-Install (audit) |
| LLM04 | Data and Model Poisoning | L3 Memory Validation, L15 RAG Security* |
| LLM05 | Improper Output Handling | L5 Output Sanitizer |
| LLM06 | Excessive Agency | L9 Egress Scanner, L12 Least Privilege |
| LLM07 | System Prompt Leakage | L9 Egress Scanner |
| LLM08 | Vector and Embedding Weaknesses | L15 RAG Security* |
| LLM09 | Misinformation | L13 Strawberry* |
| LLM10 | Unbounded Consumption | L17 Spend Alerting |

_*Requires optional external tool_

### MITRE ATLAS - 16+ Techniques

Covers AML.T0047 (Supply Chain Compromise), AML.T0048 (Adversarial Examples), AML.T0051 (Prompt Injection), AML.T0035 (Exfiltration), AML.T0057 (Data Leakage), AML.T0064 (Data Poisoning), and more.

### OWASP Agentic Top 10 (2026)

Covers ASI01 (Agent Prompt Injection), ASI04 (Dependency Chain Attacks), ASI06 (Memory and Context Manipulation), and more.

---

## Architecture

```
                         USER REQUEST
                              |
                    +---------+---------+
                    |                   |
               PreToolUse          PostToolUse
               (PREVENT)            (DETECT)
                    |                   |
          +--------+-------+    +------+--------+
          |   |   |   |    |    |   |   |   |   |
         L0  L1  L3  L9  L14   L2  L4  L5  L7 L14
         L19              pre   L17              post
          |   |   |   |    |    |   |   |   |   |
          v   v   v   v    v    v   v   v   v   v
        BLOCK              BLOCK ALERT          WARN
                    |                   |
                    +---------+---------+
                              |
                         SESSION END
                              |
                     STOP: Security Report
                              |
                    HTML report with all events
```

**Design principles:**

- **PreToolUse** hooks can BLOCK or MODIFY before execution (fail-closed on crash)
- **PostToolUse** hooks can only ALERT and inform (fail-open - content already in context)
- **Defense-in-depth** - multiple overlapping layers catch what one might miss
- **Zero trust** - validate everything, trust nothing

---

## Packages

| Package | Description |
|---------|-------------|
| `@vex-talon/core` | Security hooks, policies, detection patterns, and shared libraries |
| `@vex-talon/db` | SQLite database layer for security event storage and querying |

---

## Data Storage

All data stays local. Zero cloud dependencies. Zero telemetry.

```
~/.vex-talon/
  logs/           # JSONL audit logs per hook (auto-rotated at 5MB)
  state/          # Hook state (session tracking, API cache)
  config/         # User-provided security config overrides
  quarantine/     # Quarantined files (if applicable)
```

---

## FAQ

**Does this slow down Claude Code?**
PreToolUse hooks typically complete in <50ms. PostToolUse hooks run asynchronously. The supply chain API has a 5-second timeout and 24-hour cache.

**What happens if a hook crashes?**
PreToolUse hooks are fail-closed (block on crash, security-first). PostToolUse hooks are fail-open (content already in context, blocking serves no purpose).

**Can I disable specific layers?**
Yes. Configure `enabledLayers` in the plugin settings.

**Does it work on Windows?**
macOS and Linux are fully supported. Windows is untested.

**Is my data sent anywhere?**
No. Everything runs 100% locally. The only optional network call is to OpenSourceMalware.com for supply chain scanning (opt-in via `OSM_API_TOKEN`).

**How does this compare to other AI security tools?**
Most tools operate at 1-2 layers (typically just prompt injection scanning). Vex-Talon provides 20 layers covering the full OWASP LLM Top 10, from code security to exfiltration prevention to spend control. See our [competitive landscape analysis](https://github.com/0K-cool/vex/blob/main/output/research/vex-talon-competitive-landscape-2026.md) for details.

---

## Uninstall

```bash
/plugin uninstall vex-talon

# Optionally remove local data
rm -rf ~/.vex-talon
```

---

## Security

Vex-Talon itself is developed with security in mind:

- **No telemetry** - Zero data sent anywhere
- **Local-only** - All checks run on your machine
- **Auditable** - Open source, review every hook
- **Minimal deps** - Reduced supply chain surface
- **4 rounds of security audit** - Score: 91/100

### Reporting Vulnerabilities

Found a security issue? Please report via [GitHub Security Advisories](https://github.com/0K-cool/vex-talon/security/advisories).

---

## License

MIT

---

## Credits

Built by [Kelvin Lomboy](https://github.com/0K-cool).

Frameworks: [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [OWASP Agentic Top 10 2026](https://owasp.org/www-project-agentic-security/), [MITRE ATLAS](https://atlas.mitre.org/).

Threat intelligence: [OpenSourceMalware.com](https://opensourcemalware.com/), [NOVA Framework](https://github.com/anthropics/nova).
