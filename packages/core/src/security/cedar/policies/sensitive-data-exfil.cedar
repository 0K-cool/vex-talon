// CRITICAL: Block network requests when taint indicates sensitive data in session
// Prevents sensitive data read in session from being exfiltrated via network calls
// Maps to: OWASP LLM02 (Sensitive Information Disclosure), ATLAS AML.T0024

// Block reading files marked SECRET (3) — defense-in-depth with IFC taint
@id("forbid-secret-file-read-in-network-context")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"read_file",
    resource is Talon::File
)
when { resource.sensitivity >= 3 && context.webFetchCount >= 1 };

// Block network requests when taint level indicates confidential data touched
@id("forbid-network-with-confidential-taint")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"network_request",
    resource is Talon::Tool
)
when { context.sessionTaintLevel >= 2 };
