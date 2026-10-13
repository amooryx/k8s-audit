<div align="center">
  <img src="./banner.svg" alt="k8s-audit" width="800">
</div>

# k8s-audit

> Red team security tool — authorized use only.

```bash
python k8s_audit.py --help
```

> **Authorized security testing only.**

## RBAC audit

Run `python k8s_audit.py --rbac` to inspect cluster-wide and namespaced role
bindings, or `python k8s_audit.py --rbac --namespace team-a` to inspect one
namespace's RoleBindings. Findings are based on the referenced Role or
ClusterRole policy rules, not on role names. The check reports wildcard access
and selected high-risk permissions, including access to Secrets and pod exec.
Findings identify the binding namespace to distinguish equal binding names.

This is a read-only audit: it lists namespaces and RBAC objects and reads the
referenced roles; it does not create, update, or delete cluster resources, exec
into pods, or retrieve Secret values. The caller needs permission to list
RoleBindings and ClusterRoleBindings and read Roles and ClusterRoles. API
errors stop the RBAC check instead of being treated as a clean result.

The permission list is intentionally limited and is not a complete Kubernetes
authorization or privilege-escalation analysis. It does not evaluate
`resourceNames`, admission policy, aggregation effects beyond the rules
returned by the API, or effective access through every possible subject and
binding combination. Use it as a set of focused findings, not as proof that a
cluster is secure.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
