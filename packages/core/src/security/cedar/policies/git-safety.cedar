// CRITICAL: Block force push to main/master
// Maps to: OWASP LLM10 (Unbounded Consumption - destruction variant)

@id("forbid-force-push")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"git_operation",
    resource is Talon::Tool
)
when {
    context.command like "*push*--force*" ||
    context.command like "*push*-f *"
};
