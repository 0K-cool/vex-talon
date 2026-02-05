#!/usr/bin/env bash

# Vex-Talon: Check Bun runtime availability
# Runs as SessionStart hook (bash, no Bun dependency)

if ! command -v bun &>/dev/null; then
  echo "" >&2
  echo "================================================" >&2
  echo "  TALON: Bun runtime not found" >&2
  echo "================================================" >&2
  echo "  Vex-Talon hooks require Bun to run." >&2
  echo "  Install: curl -fsSL https://bun.sh/install | bash" >&2
  echo "  Then restart Claude Code." >&2
  echo "================================================" >&2
  echo "" >&2
fi
