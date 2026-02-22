// Guardrail: block ALL requests not from approved users and their repos.
// This forbid overrides any permit policy, preventing overly broad
// permit files from granting access to unauthorized actors.
forbid (
    principal,
    action,
    resource
)
unless {
    (principal.actor == "waltervargas" && principal.repository_owner == "waltervargas") ||
    (principal.actor == "kellenr" && principal.repository_owner == "kellenr") ||
    (principal.actor == "kellenr" && principal.repository_owner == "karenbolon") ||
    (principal.actor == "kellenr" && principal.repository_owner == "waltervargas")
};
