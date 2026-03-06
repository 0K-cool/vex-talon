// CRITICAL: Block curl/wget piped to shell execution
// Maps to: OWASP LLM03 (Supply Chain Vulnerabilities), ATLAS AML.T0047

@id("forbid-curl-pipe-sh")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"execute_command",
    resource is Talon::Tool
)
when {
    context.command like "*curl*|*sh*" ||
    context.command like "*curl*|*bash*" ||
    context.command like "*wget*|*sh*" ||
    context.command like "*wget*|*bash*"
};
