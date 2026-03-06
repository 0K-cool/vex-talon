// Phase 3: Trajectory-based step-count limits
// Prevents runaway agents and limits blast radius in tainted sessions
// Maps to: OWASP LLM10 (Unbounded Consumption), ATLAS AML.T0054

// SECRET taint: Hard limit at 50 total tool calls
@id("forbid-secret-taint-over-50-calls")
forbid (
    principal is Talon::Agent,
    action in [Talon::Action::"tool_use"],
    resource
)
when { context.sessionTaintLevel >= 3 && context.toolCallCount >= 50 };

// CONFIDENTIAL taint: Block WebFetch after 10 requests
@id("forbid-confidential-taint-over-10-webfetch")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"network_request",
    resource is Talon::Tool
)
when { context.sessionTaintLevel >= 2 && context.webFetchCount >= 10 };

// CONFIDENTIAL taint: Block shell after 50 commands
@id("forbid-confidential-taint-over-50-shell")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"execute_command",
    resource is Talon::Tool
)
when { context.sessionTaintLevel >= 2 && context.shellCommandCount >= 50 };

// Any taint: Block after 20 consecutive same tool (likely loop/runaway agent)
@id("forbid-consecutive-same-tool-over-20")
forbid (
    principal is Talon::Agent,
    action in [Talon::Action::"tool_use"],
    resource
)
when { context.consecutiveSameTool >= 20 && context.sessionTaintLevel >= 1 };
