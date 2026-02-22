// Allow waltervargas/pong to pull its own images and postgres
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"images:pull",
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    (principal.actor == "waltervargas" || principal.actor == "kellenr") &&
    resource.name like "ghcr.io/waltervargas/pong:*"
};

permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"images:pull",
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    (principal.actor == "waltervargas" || principal.actor == "kellenr") &&
    resource.name like "docker.io/library/postgres:*"
};

// Allow waltervargas/pong to manage only waltervargas-pong-* containers
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
    (principal.actor == "waltervargas" || principal.actor == "kellenr") &&
    resource.name like "waltervargas-pong-*"
};

// Container create: scoped by repo + actor only
// TODO: permitd should extract container name from request body
// to allow resource.name scoping on create (see issue #2)
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"containers:create",
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    (principal.actor == "waltervargas" || principal.actor == "kellenr")
};

// Allow waltervargas/pong to manage waltervargas-pong-* pods
permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"pods:create",
        Permitd::Action::"pods:start",
        Permitd::Action::"pods:stop",
        Permitd::Action::"pods:remove"
    ],
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    (principal.actor == "waltervargas" || principal.actor == "kellenr") &&
    resource.name like "waltervargas-pong-*"
};

// Allow waltervargas/pong to manage waltervargas-pong-* volumes
permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"volumes:create",
        Permitd::Action::"volumes:remove"
    ],
    resource
)
when {
    principal.repository == "waltervargas/pong" &&
    (principal.actor == "waltervargas" || principal.actor == "kellenr") &&
    resource.name like "waltervargas-pong-*"
};
