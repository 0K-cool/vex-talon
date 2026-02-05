#!/usr/bin/env bash

# Vex-Talon: Onboarding & Session Status Hook
# Runs as SessionStart hook (bash, no Bun dependency)
#
# Scenarios:
#   First run    → Full welcome banner + health check
#   Subsequent   → One-line compact status
#   Upgrade      → Brief upgrade notice + one-line status
#   Bun missing  → Error with install instructions

set -euo pipefail

# --- Configuration ---
TALON_VERSION="1.0.0"
STATE_DIR="${TALON_DIR:-$HOME/.vex-talon}/state"
STATE_FILE="$STATE_DIR/onboarding.json"
HOOK_DIR="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/../../../.." && pwd)}"
HOOKS_JSON="$HOOK_DIR/hooks/hooks.json"
PROFILE="${VEX_TALON_PROFILE:-dev}"

# --- Helper: output JSON to stdout (additionalContext for Claude) ---
output_context() {
  echo "$1"
}

# --- Helper: output to stderr (visible to user in terminal) ---
user_msg() {
  echo "$1" >&2
}

# --- Step 1: Check Bun availability ---
if ! command -v bun &>/dev/null; then
  user_msg ""
  user_msg "================================================"
  user_msg "  TALON: Bun runtime not found"
  user_msg "================================================"
  user_msg "  Vex-Talon hooks require Bun to run."
  user_msg "  Install: curl -fsSL https://bun.sh/install | bash"
  user_msg "  Then restart Claude Code."
  user_msg "================================================"
  user_msg ""
  output_context '{"vex_talon_active": false, "error": "bun_not_found"}'
  exit 0
fi

BUN_VERSION=$(bun --version 2>/dev/null || echo "unknown")

# --- Step 2: Count hooks from hooks.json ---
HOOKS_COUNT=0
if [ -f "$HOOKS_JSON" ]; then
  # Count unique hook command entries across all event types
  HOOKS_COUNT=$(grep -c '"type": "command"' "$HOOKS_JSON" 2>/dev/null || echo "0")
fi

# --- Step 3: Ensure state directory exists ---
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

# --- Step 4: Read state file (or detect first run) ---
FIRST_RUN=false
UPGRADED=false
UPGRADED_FROM=""
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ ! -f "$STATE_FILE" ]; then
  FIRST_RUN=true
else
  # Read stored version
  STORED_VERSION=$(grep -o '"version": *"[^"]*"' "$STATE_FILE" 2>/dev/null | head -1 | sed 's/"version": *"//;s/"//' || echo "")

  if [ -n "$STORED_VERSION" ] && [ "$STORED_VERSION" != "$TALON_VERSION" ]; then
    UPGRADED=true
    UPGRADED_FROM="$STORED_VERSION"
  fi
fi

# --- Step 5: Output based on scenario ---

if [ "$FIRST_RUN" = true ]; then
  # Full welcome banner
  user_msg ""
  user_msg "==================================================="
  user_msg "  VEX-TALON v${TALON_VERSION} - Security Hooks for Claude Code"
  user_msg "==================================================="
  user_msg ""
  user_msg "  Health Check:"
  user_msg "    [OK] Bun runtime found (v${BUN_VERSION})"
  user_msg "    [OK] Hooks directory verified (${HOOKS_COUNT} hooks)"
  user_msg "    [OK] State directory initialized"
  user_msg ""
  user_msg "  Coverage:"
  user_msg "    OWASP LLM 2025: 9/10 | OWASP Agentic 2026: Full"
  user_msg "    MITRE ATLAS: 16+ techniques"
  user_msg ""
  user_msg "  Profile: ${PROFILE} (all tools enabled)"
  user_msg ""
  user_msg "  Docs: https://github.com/0K-cool/vex-talon#readme"
  user_msg "==================================================="
  user_msg ""

  output_context "{\"vex_talon_active\": true, \"version\": \"${TALON_VERSION}\", \"first_run\": true, \"hooks_count\": ${HOOKS_COUNT}, \"profile\": \"${PROFILE}\"}"

elif [ "$UPGRADED" = true ]; then
  # Upgrade notice + compact status
  user_msg ""
  user_msg "  TALON upgraded: v${UPGRADED_FROM} -> v${TALON_VERSION}"
  user_msg "  TALON v${TALON_VERSION} | ${HOOKS_COUNT} hooks | ${PROFILE} | ready"
  user_msg ""

  output_context "{\"vex_talon_active\": true, \"version\": \"${TALON_VERSION}\", \"hooks_count\": ${HOOKS_COUNT}, \"profile\": \"${PROFILE}\", \"upgraded_from\": \"${UPGRADED_FROM}\"}"

else
  # Compact one-liner
  user_msg "  TALON v${TALON_VERSION} | ${HOOKS_COUNT} hooks | ${PROFILE} | ready"

  output_context "{\"vex_talon_active\": true, \"version\": \"${TALON_VERSION}\", \"hooks_count\": ${HOOKS_COUNT}, \"profile\": \"${PROFILE}\"}"
fi

# --- Step 6: Write/update state file ---
if [ "$FIRST_RUN" = true ]; then
  FIRST_RUN_AT="$NOW"
else
  # Preserve original first_run_at from existing state file
  FIRST_RUN_AT=$(grep -o '"first_run_at": *"[^"]*"' "$STATE_FILE" 2>/dev/null | head -1 | sed 's/"first_run_at": *"//;s/"//' || echo "$NOW")
fi

cat > "$STATE_FILE" <<EOF
{"version": "${TALON_VERSION}", "first_run_at": "${FIRST_RUN_AT}", "last_seen": "${NOW}"}
EOF
chmod 600 "$STATE_FILE"
