# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vex-Talon, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Go to [GitHub Security Advisories](https://github.com/0K-cool/vex-talon/security/advisories)
2. Click "New draft security advisory"
3. Provide a description of the vulnerability, steps to reproduce, and potential impact

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix or mitigation** as soon as reasonably possible
- **Credit** in the release notes (unless you prefer anonymity)

### Scope

The following are in scope:

- Security hook bypasses (e.g., evading L0-L19 detection)
- Pattern detection gaps (injection patterns, egress rules, supply chain blocklist)
- Vulnerabilities in shared libraries (config-loader, circuit-breaker, atomic-file)
- Information disclosure through audit logs or reports
- Denial of service against hook execution

### Out of Scope

- Vulnerabilities in Claude Code itself (report to [Anthropic](https://www.anthropic.com/responsible-disclosure))
- Issues requiring physical access to the machine
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |
