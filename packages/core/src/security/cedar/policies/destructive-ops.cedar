// CRITICAL: Block rm -rf on critical directories
// Maps to: OWASP LLM10 (Unbounded Consumption - destruction variant)

@id("forbid-rm-rf-git")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"execute_command",
    resource is Talon::Tool
)
when { context.command like "*rm *-rf*.git*" || context.command like "*rm *-rf */*" };
