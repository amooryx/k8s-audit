#!/usr/bin/env python3
"""
K8s Audit — Kubernetes Security Auditing Tool
Enumerates RBAC misconfigurations, exposed secrets, and privilege escalation paths.
Requires kubernetes client: pip install kubernetes
Author: Omar Khalid (amooryx) | github.com/amooryx/k8s-audit
AUTHORIZED USE ONLY — for authorized cloud/infrastructure pentests.
"""

import argparse
import json
import sys

try:
    from kubernetes import client, config as k8s_config
    from kubernetes.client.rest import ApiException
    HAS_K8S = True
except ImportError:
    HAS_K8S = False

DANGEROUS_VERBS_RESOURCES = [
    ("*",    "*",                   "Wildcard — cluster admin equivalent"),
    ("*",    "pods",                "Full pod control"),
    ("*",    "secrets",             "Full secrets access"),
    ("get",  "secrets",             "Read Secrets"),
    ("list", "secrets",             "List Secrets"),
    ("*",    "clusterroles",        "Modify cluster roles"),
    ("*",    "rolebindings",        "Modify role bindings"),
    ("get",  "pods/exec",           "Exec into pods"),
    ("create", "pods/exec",         "Exec into pods"),
    ("*",    "serviceaccounts",     "Manage service accounts"),
]

RESOURCE_API_GROUPS = {
    "pods": {""},
    "pods/exec": {""},
    "secrets": {""},
    "serviceaccounts": {""},
    "clusterroles": {"rbac.authorization.k8s.io"},
    "rolebindings": {"rbac.authorization.k8s.io"},
}


def _rule_dangerous_permissions(rule) -> set[str]:
    verbs = rule.verbs or []
    resources = rule.resources or []
    api_groups = rule.api_groups or []
    issues = set()
    for dangerous_verb, dangerous_resource, note in DANGEROUS_VERBS_RESOURCES:
        verb_matches = (
            "*" in verbs if dangerous_verb == "*"
            else dangerous_verb in verbs or "*" in verbs
        )
        resource_matches = (
            "*" in resources if dangerous_resource == "*"
            else dangerous_resource in resources or "*" in resources
        )
        group_matches = (
            dangerous_resource == "*"
            or "*" in api_groups
            or bool(RESOURCE_API_GROUPS[dangerous_resource].intersection(api_groups))
        )
        if verb_matches and resource_matches and group_matches:
            issues.add(note)
    return issues


def load_kube_config(kubeconfig: str | None = None):
    if not HAS_K8S:
        print("[!] kubernetes library required: pip install kubernetes")
        sys.exit(1)
    try:
        if kubeconfig:
            k8s_config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                k8s_config.load_incluster_config()
                print("[*] Running in-cluster (pod identity)")
            except Exception:
                k8s_config.load_kube_config()
    except Exception as e:
        print(f"[!] Config error: {e}")
        sys.exit(1)

def list_namespaces(v1) -> list[str]:
    try:
        ns = v1.list_namespace()
        return [n.metadata.name for n in ns.items]
    except ApiException:
        return []

def list_secrets(v1, namespace: str) -> list[dict]:
    try:
        secrets = v1.list_namespaced_secret(namespace)
        return [{"name": s.metadata.name, "type": s.type,
                 "keys": list(s.data.keys()) if s.data else []}
                for s in secrets.items]
    except ApiException:
        return []

def check_rbac(rbac_v1, namespace: str | None) -> list[dict]:
    findings = []
    if namespace:
        bindings = rbac_v1.list_namespaced_role_binding(namespace).items
    else:
        bindings = rbac_v1.list_role_binding_for_all_namespaces().items
        bindings += rbac_v1.list_cluster_role_binding().items

    role_cache = {}
    for binding in bindings:
        role_ref = binding.role_ref
        role_namespace = getattr(binding.metadata, "namespace", None)
        cache_namespace = role_namespace if role_ref.kind == "Role" else None
        cache_key = (role_ref.kind, cache_namespace, role_ref.name)
        if cache_key not in role_cache:
            if role_ref.kind == "Role" and role_namespace:
                role = rbac_v1.read_namespaced_role(role_ref.name, role_namespace)
            elif role_ref.kind == "ClusterRole":
                role = rbac_v1.read_cluster_role(role_ref.name)
            else:
                continue
            role_cache[cache_key] = role.rules or []

        issues = set()
        for rule in role_cache[cache_key]:
            issues.update(_rule_dangerous_permissions(rule))
        subjects = binding.subjects or []
        for subj in subjects:
            if subj.kind in ("ServiceAccount", "User", "Group"):
                for issue in sorted(issues):
                    findings.append({
                        "binding": binding.metadata.name,
                        "namespace": role_namespace,
                        "subject": f"{subj.kind}/{subj.name}",
                        "role":    role_ref.name,
                        "issue":   issue,
                    })
    return findings

def list_pods_with_privesc(v1, namespace: str) -> list[dict]:
    risky = []
    try:
        pods = v1.list_namespaced_pod(namespace)
        for pod in pods.items:
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if sc:
                    issues = []
                    if sc.privileged:
                        issues.append("privileged=true")
                    if sc.run_as_user == 0 or (sc.run_as_root is True):
                        issues.append("runs as root")
                    if sc.allow_privilege_escalation:
                        issues.append("allowPrivilegeEscalation=true")
                    if issues:
                        risky.append({
                            "pod":       pod.metadata.name,
                            "namespace": namespace,
                            "container": container.name,
                            "issues":    issues,
                        })
    except ApiException:
        pass
    return risky

def main():
    parser = argparse.ArgumentParser(
        description="K8s Audit — Kubernetes Security Audit (Authorized use only)",
    )
    parser.add_argument("--kubeconfig",   help="Path to kubeconfig")
    parser.add_argument("--namespace", "-n", help="Namespace (all if omitted)")
    parser.add_argument("--secrets",      action="store_true", help="List accessible secrets")
    parser.add_argument("--rbac",         action="store_true", help="Audit RBAC for dangerous permissions")
    parser.add_argument("--privesc",      action="store_true", help="Find privileged pods")
    parser.add_argument("--all", "-a",    action="store_true")
    parser.add_argument("--out",          help="Output JSON file")
    args = parser.parse_args()

    load_kube_config(args.kubeconfig)
    v1      = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    results = {}

    namespaces = [args.namespace] if args.namespace else list_namespaces(v1)
    print(f"[+] Auditing {len(namespaces)} namespaces")

    if args.secrets or args.all:
        all_secrets = []
        for ns in namespaces:
            secrets = list_secrets(v1, ns)
            for s in secrets:
                s["namespace"] = ns
            all_secrets.extend(secrets)
        sensitive = [s for s in all_secrets if any(
            kw in s["name"] for kw in ["token", "secret", "cred", "key", "password", "cert"]
        )]
        print(f"[+] Secrets accessible: {len(all_secrets)} ({len(sensitive)} with sensitive names)")
        for s in sensitive[:10]:
            print(f"    [!!!] {s['namespace']}/{s['name']} ({s['type']}) keys={s['keys']}")
        results["secrets"] = all_secrets

    if args.rbac or args.all:
        rbac_findings = check_rbac(rbac_v1, args.namespace)
        print(f"[+] RBAC dangerous bindings: {len(rbac_findings)}")
        for f in rbac_findings[:10]:
            binding_name = f"{f['namespace']}/{f['binding']}" if f["namespace"] else f["binding"]
            print(f"    [!!!] {f['subject']} via {binding_name}: {f['issue']}")
        results["rbac"] = rbac_findings

    if args.privesc or args.all:
        priv_pods = []
        for ns in namespaces:
            priv_pods.extend(list_pods_with_privesc(v1, ns))
        print(f"[+] Privileged/risky pods: {len(priv_pods)}")
        for p in priv_pods:
            print(f"    [!!!] {p['namespace']}/{p['pod']} ({p['container']}): {', '.join(p['issues'])}")
        results["privileged_pods"] = priv_pods

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
