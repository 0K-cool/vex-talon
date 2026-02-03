/**
 * @vex-talon/core - Security Hooks
 *
 * Claude Code hooks for the 20-layer defense-in-depth architecture (L0-L19).
 *
 * PreToolUse Hooks (can block):
 * - L0: secure-code-enforcer - Blocks CRITICAL code vulnerabilities
 * - L1: governor (coming soon) - Policy enforcement
 * - L9: egress-scanner (coming soon) - Data exfiltration prevention
 *
 * PostToolUse Hooks (detect and warn):
 * - L2: secure-code-linter (coming soon) - Post-write security analysis
 * - L4: injection-scanner - Detects prompt injection in tool outputs
 * - L5: output-sanitizer (coming soon) - XSS detection
 * - L7: image-safety-scanner (coming soon) - Steganography detection
 * - L14: supply-chain-scanner (coming soon) - Package vulnerability detection
 */

export const HOOK_VERSION = '0.1.0';

// Hook file paths (for settings.json configuration)
export const HOOKS = {
  // PreToolUse hooks
  'secure-code-enforcer': './hooks/secure-code-enforcer.ts',

  // PostToolUse hooks
  'injection-scanner': './hooks/injection-scanner.ts',
} as const;

export type HookName = keyof typeof HOOKS;

/**
 * Get the relative path for a hook
 */
export function getHookPath(hookName: HookName): string {
  return HOOKS[hookName];
}

/**
 * Generate settings.json hook configuration for Vex-Talon
 */
export function generateHooksConfig(basePath: string = '@vex-talon/core'): object {
  return {
    hooks: {
      PreToolUse: [
        {
          hooks: [
            {
              type: 'command',
              command: `bun run ${basePath}/src/hooks/secure-code-enforcer.ts`,
              timeout: 5000,
            },
          ],
        },
      ],
      PostToolUse: [
        {
          hooks: [
            {
              type: 'command',
              command: `bun run ${basePath}/src/hooks/injection-scanner.ts`,
              timeout: 10000,
            },
          ],
        },
      ],
    },
  };
}
