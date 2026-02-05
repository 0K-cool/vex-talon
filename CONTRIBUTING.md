# Contributing to Vex-Talon

Thanks for your interest in improving Claude Code security.

## How to Contribute

### Reporting Bugs

- Open a [GitHub issue](https://github.com/0K-cool/vex-talon/issues) with steps to reproduce
- Include your OS, Bun version, and Claude Code version
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead

### Suggesting Features

- Open a [GitHub issue](https://github.com/0K-cool/vex-talon/issues) describing the feature
- Explain the security problem it solves and which OWASP/ATLAS framework mapping applies (if any)

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Make your changes
4. Run tests: `pnpm test`
5. Run type checking: `pnpm typecheck`
6. Commit with a descriptive message
7. Push and open a PR

### Adding Detection Patterns

The easiest way to contribute is improving detection coverage:

- **Prompt injection patterns** - `packages/core/src/lib/injection-patterns.ts`
- **Supply chain blocklist** - L14 pre-install hook
- **Egress destinations** - L9 egress scanner
- **Code vulnerability patterns** - L0 secure code enforcer

Include test cases for any new patterns.

## Development Setup

```bash
# Requirements: Bun, pnpm 9+, Node 20+

git clone https://github.com/0K-cool/vex-talon.git
cd vex-talon
pnpm install
pnpm build
pnpm test
```

## Code Style

- TypeScript for all hooks and libraries
- Prettier for formatting (`pnpm format`)
- ESLint for linting (`pnpm lint`)

## Architecture

- **PreToolUse hooks** can BLOCK or MODIFY (fail-closed on crash)
- **PostToolUse hooks** can only ALERT (fail-open - content already in context)
- All hooks must complete in <500ms
- Use the shared libraries in `packages/core/src/hooks/lib/` for common operations

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
