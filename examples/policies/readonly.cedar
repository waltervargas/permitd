// Read-only policy: allow listing and inspecting but no mutations.

permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"containers:list",
        Permitd::Action::"containers:inspect",
        Permitd::Action::"containers:logs",
        Permitd::Action::"images:list",
        Permitd::Action::"volumes:list",
        Permitd::Action::"networks:list"
    ],
    resource
)
when {
    principal.repository_owner == "myorg"
};
