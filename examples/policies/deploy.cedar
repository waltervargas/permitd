// Allow a specific GitHub org's workflows to manage containers and images.
// Scope: any workflow from "myorg" can create/start/stop/remove/list/inspect/logs containers
// and pull/list/build images.

permit (
    principal is Permitd::Workflow,
    action in [
        Permitd::Action::"containers:create",
        Permitd::Action::"containers:start",
        Permitd::Action::"containers:stop",
        Permitd::Action::"containers:remove",
        Permitd::Action::"containers:list",
        Permitd::Action::"containers:inspect",
        Permitd::Action::"containers:logs",
        Permitd::Action::"images:pull",
        Permitd::Action::"images:list",
        Permitd::Action::"images:build"
    ],
    resource
)
when {
    principal.repository_owner == "myorg"
};
