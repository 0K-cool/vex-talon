---
name: talon-report
description: Generate comprehensive security report for the current project
arguments:
  - name: format
    description: Output format (markdown, json, html) (default: markdown)
    required: false
  - name: output
    description: Output file path (default: stdout)
    required: false
---

# Vex-Talon Security Report Generator

Generate a comprehensive security assessment report for the current project.

## Arguments

- `format`: Report output format
  - `markdown` - Markdown report (default)
  - `json` - Machine-readable JSON
  - `html` - Styled HTML report

- `output`: Where to save the report
  - File path to save report
  - Default: Display in conversation

## Report Contents

### 1. Executive Summary

- Project name and scan timestamp
- Overall security posture (SECURE, AT_RISK, CRITICAL)
- Key findings count by severity
- Top 3 recommendations

### 2. Defense Layer Status

| Layer | Status | Events (24h) | Last Triggered |
|-------|--------|--------------|----------------|
| L0 | ✅ Active | 5 | 2 hours ago |
| L1 | ✅ Active | 12 | 30 min ago |
| ... | ... | ... | ... |

### 3. Framework Coverage Analysis

**OWASP LLM Top 10 2025:**
- LLM01 Prompt Injection: ✅ Covered (L4, L19)
- LLM02 Sensitive Info: ✅ Covered (L0, L1, L9)
- LLM03 Supply Chain: ✅ Covered (L14)
- ...

**MITRE ATLAS:**
- AML.T0048 Prompt Injection: ✅ 8 rules
- AML.T0049 Jailbreak: ✅ 2 rules
- AML.T0051 Data Leakage: ✅ 4 rules
- ...

### 4. Detailed Findings

For each finding:
- Severity and layer
- File location and line number
- Pattern matched
- Code snippet
- Remediation steps
- OWASP/ATLAS mapping

### 5. Trend Analysis

- Events over time (7 days)
- Most triggered patterns
- Attack vector distribution

### 6. Recommendations

Prioritized list of security improvements:
1. [CRITICAL] Address hardcoded API key in config.ts
2. [HIGH] Enable L9 egress scanning for API routes
3. [MEDIUM] Add input validation to user handlers

## Execution

When user runs `/talon-report`:

1. **Collect Data**
   - Read event logs from `.vex-talon/logs/`
   - Scan current codebase for active issues
   - Load layer configuration

2. **Analyze Coverage**
   - Map active layers to OWASP/ATLAS
   - Identify coverage gaps
   - Calculate security posture score

3. **Generate Report**
   - Format according to requested output
   - Include actionable recommendations
   - Save or display

## Examples

**Generate markdown report:**
```
/talon-report
```

**Generate JSON for CI/CD integration:**
```
/talon-report json ./security-report.json
```

**Generate HTML for stakeholder review:**
```
/talon-report html ./reports/security-assessment.html
```
