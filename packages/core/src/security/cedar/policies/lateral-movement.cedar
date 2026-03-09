// Lateral Movement Prevention (AML.T0091 / AML.TA0015)
// Block MCP calls to external services when session taint >= SECRET (3)
// Prevents: credential reads (1Password) → data exfiltration (Supabase/Discord)
// Maps to: MITRE ATLAS AML.T0091, OWASP LLM02, OWASP Agentic ASI05

// Block external MCP service calls when session has SECRET taint
// External services: Supabase, shadcn (remote API), any non-local MCP
@id("forbid-mcp-external-when-secret-taint")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"mcp_call",
    resource is Talon::Tool
)
when {
    context.sessionTaintLevel >= 3 &&
    context.serviceType == "external"
};

// Block MCP calls that write data when session has CONFIDENTIAL+ taint
// Even local MCP servers shouldn't receive writes with sensitive data in context
@id("forbid-mcp-write-when-confidential-taint")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"mcp_call",
    resource is Talon::Tool
)
when {
    context.sessionTaintLevel >= 2 &&
    context.isWrite == true &&
    context.serviceType == "external"
};
