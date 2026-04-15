---
name: status
description: Show 0K-Talon security layer status and recent activity
---

# 0K-Talon Status

Display the current status of all 20 security layers and recent activity.

## Output

```
═══════════════════════════════════════════════════════════════
              0K-TALON SECURITY STATUS
═══════════════════════════════════════════════════════════════

PORTED LAYERS (12/20)
───────────────────────────────────────────────────────────────
✅ L0  Secure Code Enforcer    PreToolUse   BLOCK   5 events
✅ L1  Governor Agent          PreToolUse   BLOCK   12 events
✅ L2  Secure Code Linter      PostToolUse  ALERT   3 events
✅ L3  Memory Validation       PreToolUse   ALERT   0 events
✅ L4  Injection Scanner       PostToolUse  ALERT   8 events
✅ L5  Output Sanitizer        PostToolUse  WARN    2 events
✅ L7  Image Safety Scanner    PostToolUse  ALERT   0 events
✅ L9  Egress Scanner          PreToolUse   BLOCK   4 events
✅ L12 Least Privilege         SessionStart LOG     1 event
✅ L14 Supply Chain Scanner    PostToolUse  WARN    1 event
✅ L17 Spend Alerting          PostToolUse  ALERT   3 events
✅ L19 Skill Scanner           PreToolUse   BLOCK   2 events

DOCUMENTATION LAYERS (5)
───────────────────────────────────────────────────────────────
📄 L6  Git Pre-commit          Setup guide available
📄 L8  Evaluator Agent         Setup guide available
📄 L10 Native Sandbox          Reference documentation
📄 L15 RAG Security Scanner    0k-rag integration guide
📄 L16 Human Decision          Reference documentation

OPTIONAL LAYERS (3)
───────────────────────────────────────────────────────────────
⚙️  L11 Leash Kernel Sandbox   Requires: Leash binary
⚙️  L13 Strawberry Hallucination Requires: MCP server
⚙️  L18 MCP Audit              Requires: Proximity scanner

FRAMEWORK COVERAGE
───────────────────────────────────────────────────────────────
OWASP LLM 2025:     9/10 ████████████████████░░ 90%
OWASP Agentic 2026: 10/10 ██████████████████████ 100%
MITRE ATLAS:        16+ techniques mapped

RECENT ACTIVITY (Last 24h)
───────────────────────────────────────────────────────────────
🔴 CRITICAL: 2
🟠 HIGH:     5
🟡 MEDIUM:   8
🟢 LOW:      12

QUICK ACTIONS
───────────────────────────────────────────────────────────────
/0k-talon:status          Refresh this status dashboard
/0k-talon:intel-update    Update threat patterns and frameworks
/0k-talon:report          Generate detailed security report
/0k-talon:scan            Run security scan

═══════════════════════════════════════════════════════════════
```

## Execution

1. Read layer configuration from plugin settings
2. Query event logs for activity counts
3. Calculate framework coverage percentages
4. Display formatted status

## Related Commands

- `/0k-talon:scan` - Run security scan
- `/0k-talon:report` - Generate detailed report
