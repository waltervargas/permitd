// Allow waltervargas/pong workflows to deploy containers and pull images
permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"containers:create",
        Permitd::Action::"containers:start",
        Permitd::Action::"containers:stop",
        Permitd::Action::"containers:remove",
        Permitd::Action::"images:pull"
    ],
    resource
)
when {
    principal.repository == "waltervargas/pong"
};
