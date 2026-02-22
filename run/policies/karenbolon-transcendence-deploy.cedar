// Allow karenbolon/Transcendence to pull only its own images
permit (
    principal is Permitd::Workflow,
    action == Permitd::Action::"images:pull",
    resource
)
when {
    principal.repository == "karenbolon/Transcendence" &&
    principal.actor == "kellenr" &&
    resource.name like "ghcr.io/karenbolon/transcendence:*"
};

// Allow karenbolon/Transcendence to manage only karenbolon-transcendence-* containers
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
    principal.repository == "karenbolon/Transcendence" &&
    principal.actor == "kellenr" &&
    resource.name like "karenbolon-transcendence-*"
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
    principal.repository == "karenbolon/Transcendence" &&
    principal.actor == "kellenr"
};
