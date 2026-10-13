import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import k8s_audit


def binding(name, role_kind, role_name, namespace, subjects=None):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        role_ref=SimpleNamespace(kind=role_kind, name=role_name),
        subjects=subjects or [
            SimpleNamespace(kind="ServiceAccount", name="audited-service")
        ],
    )


def role(*rules):
    return SimpleNamespace(rules=list(rules))


def rule(verbs, resources, api_groups=None):
    return SimpleNamespace(
        verbs=verbs,
        resources=resources,
        api_groups=api_groups if api_groups is not None else [
            "",
            "rbac.authorization.k8s.io",
        ],
    )


class CheckRbacTests(unittest.TestCase):
    def test_uses_granted_rules_instead_of_role_name(self):
        api = Mock()
        api.list_namespaced_role_binding.return_value.items = [
            binding("read-config", "Role", "secrets", "team-a")
        ]
        api.read_namespaced_role.return_value = role(
            rule(["get"], ["configmaps"])
        )

        findings = k8s_audit.check_rbac(api, "team-a")

        self.assertEqual(findings, [])
        api.read_namespaced_role.assert_called_once_with("secrets", "team-a")

    def test_finds_dangerous_rule_and_ignores_safe_rule_name(self):
        api = Mock()
        api.list_namespaced_role_binding.return_value.items = [
            binding("reader", "Role", "ordinary-reader", "team-a")
        ]
        api.read_namespaced_role.return_value = role(
            rule(["get"], ["secrets"]),
            rule(["get"], ["configmaps"]),
        )

        findings = k8s_audit.check_rbac(api, "team-a")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["role"], "ordinary-reader")
        self.assertEqual(findings[0]["issue"], "Read Secrets")

    def test_checks_all_namespaced_and_cluster_role_bindings(self):
        api = Mock()
        api.list_role_binding_for_all_namespaces.return_value.items = [
            binding("namespace-binding", "Role", "pod-reader", "team-a")
        ]
        api.list_cluster_role_binding.return_value.items = [
            binding("cluster-binding", "ClusterRole", "pod-admin", None)
        ]
        api.read_namespaced_role.return_value = role(
            rule(["get"], ["secrets"])
        )
        api.read_cluster_role.return_value = role(
            rule(["*"], ["pods"])
        )

        findings = k8s_audit.check_rbac(api, None)

        self.assertEqual(
            {finding["binding"] for finding in findings},
            {"namespace-binding", "cluster-binding"},
        )
        self.assertEqual(
            {finding["binding"]: finding["namespace"] for finding in findings},
            {"namespace-binding": "team-a", "cluster-binding": None},
        )
        api.read_namespaced_role.assert_called_once_with("pod-reader", "team-a")
        api.read_cluster_role.assert_called_once_with("pod-admin")

    def test_detects_wildcard_verb_and_resource_rule(self):
        issues = k8s_audit._rule_dangerous_permissions(
            rule(["*"], ["*"])
        )

        self.assertIn("Wildcard — cluster admin equivalent", issues)

    def test_detects_pod_exec_creation_permission(self):
        issues = k8s_audit._rule_dangerous_permissions(
            rule(["create"], ["pods/exec"])
        )

        self.assertIn("Exec into pods", issues)

    def test_ignores_similarly_named_resources_in_other_api_groups(self):
        issues = k8s_audit._rule_dangerous_permissions(
            rule(["get"], ["secrets"], ["example.com"])
        )

        self.assertEqual(issues, set())


if __name__ == "__main__":
    unittest.main()
