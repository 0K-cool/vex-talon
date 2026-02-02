# Vex-Talon 🦅

**20-Layer Defense-in-Depth Security for Claude Code**

Vex-Talon packages Vex's battle-tested security architecture into a distributable Claude Code plugin with a monitoring dashboard.

## Features

- **17 Bundled Security Layers** - Pre-execution, post-execution, and git hooks
- **Security Dashboard** - Real-time monitoring of blocks, alerts, and coverage
- **OWASP/ATLAS Coverage** - Maps to OWASP LLM Top 10 2025 and MITRE ATLAS
- **Themed Components** - Reusable UI library for security dashboards
- **Zero Cloud Dependencies** - 100% local processing, no data exfiltration

## Security Layers

| Layer | Name | Type | Status |
|-------|------|------|--------|
| L0 | Secure Code Enforcer | PreToolUse | Bundled |
| L1 | Governor Agent | PreToolUse | Bundled |
| L2 | Secure Code Linter | PostToolUse | Bundled |
| L3 | Memory Validation | Pre/PostToolUse | Bundled |
| L4 | Injection Scanner | PostToolUse | Bundled |
| L5 | Output Sanitizer | PostToolUse | Bundled |
| L6 | Git Pre-commit | Git Hook | Bundled |
| L7 | Image Safety Scanner | PostToolUse | Bundled |
| L8 | Evaluator Agent | Git Hook | Bundled |
| L9 | Egress Scanner | PreToolUse | Bundled |
| L10 | Native Sandbox | Built-in | Bundled |
| L11 | Leash Kernel Sandbox | Kernel | Optional |
| L12 | Least Privilege Profiles | SessionStart | Bundled |
| L13 | Strawberry Hallucination | On-demand | Optional |
| L14 | Supply Chain Scanner | PostToolUse | Bundled |
| L15 | RAG Security Scanner | Pre-index | Bundled |
| L16 | Human | Manual | Bundled |
| L17 | Spend Alerting | PostToolUse | Bundled |
| L18 | MCP Audit | Pre-deploy | Optional |
| L19 | Skill Scanner | PreToolUse | Bundled |

## Installation

```bash
# Clone the repository
git clone https://github.com/0K-cool/vex-talon.git
cd vex-talon

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Start the dashboard
pnpm --filter @vex-talon/dashboard dev
```

## Packages

| Package | Description |
|---------|-------------|
| `@vex-talon/core` | Security hooks, policies, and pattern configs |
| `@vex-talon/db` | SQLite database layer for event storage |
| `@vex-talon/ui` | Themed component library (shadcn/ui based) |
| `@vex-talon/dashboard` | Next.js security monitoring dashboard |

## Usage with Claude Code

```bash
# Add Vex-Talon as a plugin
claude plugins add ./path/to/vex-talon

# Or if published
claude plugins add vex-talon
```

## Dashboard

The security dashboard runs on port 3333 by default:

```bash
pnpm --filter @vex-talon/dashboard dev
# Open http://localhost:3333
```

## Configuration

Edit `.claude-plugin/plugin.json` or create a local `.vex-talon.json`:

```json
{
  "enabledLayers": ["L0", "L1", "L2", "L4"],
  "dashboardPort": 3333,
  "auditLogDir": ".claude/logs"
}
```

## Development

```bash
# Run all packages in dev mode
pnpm dev

# Run tests
pnpm test

# Lint
pnpm lint

# Type check
pnpm typecheck
```

## Architecture

```
vex-talon/
├── packages/
│   ├── core/       # Security hooks & policies
│   ├── db/         # SQLite database layer
│   ├── ui/         # Component library
│   └── dashboard/  # Next.js dashboard app
├── hooks/          # Claude Code hooks (symlinks)
├── skills/         # Vex-Talon skills
└── commands/       # CLI commands
```

## Credits

- **Vex** - Original 20-layer architecture (Personal AI Infrastructure)
- **OWASP** - LLM Top 10 2025 framework
- **MITRE** - ATLAS threat framework
- **shadcn/ui** - Component primitives

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Vex-Talon** - Sharp, fast, defensive. 🦅
