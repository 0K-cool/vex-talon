// IFC: Block network requests when session taint >= CONFIDENTIAL (2)
// Bell-LaPadula "No write-down": confidential data cannot flow to external services
// Maps to: OWASP LLM02 (Sensitive Information Disclosure), ATLAS AML.T0024

@id("forbid-network-when-confidential-taint")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"network_request",
    resource is Talon::Tool
)
when { context.sessionTaintLevel >= 2 };

// IFC: Block shell network commands when taint >= CONFIDENTIAL
// Catches curl, wget, nc, ssh, scp when session has seen confidential data
@id("forbid-shell-network-when-tainted")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"execute_command",
    resource is Talon::Tool
)
when {
    context.sessionTaintLevel >= 2 && (
        context.command like "*curl *" ||
        context.command like "*wget *" ||
        context.command like "*nc *" ||
        context.command like "*scp *"
    )
};
