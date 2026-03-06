// CRITICAL: Block all access to .env files
// Maps to: OWASP LLM02 (Sensitive Information Disclosure)

@id("forbid-env-read")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"read_file",
    resource is Talon::File
)
when { resource.path like "*.env*" };

@id("forbid-env-write")
forbid (
    principal is Talon::Agent,
    action == Talon::Action::"write_file",
    resource is Talon::File
)
when { resource.path like "*.env*" };
