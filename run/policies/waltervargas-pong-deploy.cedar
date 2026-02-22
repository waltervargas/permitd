// Allow waltervargas/pong to pull only its own images
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"images:pull",
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    principal.actor in ["waltervargas"] &&
    resource.name like "ghcr.io/waltervargas/pong:*"
};

// Allow waltervargas/pong to manage only pong-* containers
permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"containers:start",
        Permitd::Action::"containers:stop",
        Permitd::Action::"containers:remove"
    ],
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    principal.actor in ["waltervargas"] &&
    resource.name like "pong-*"
};

// Container create: scoped by repo + actor only
// TODO: permitd should extract container name from request body
// to allow resource.name scoping on create (see issue/task)
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"containers:create",
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    principal.actor in ["waltervargas"]
};
