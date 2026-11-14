"""Static safety contract for the temporary AUTO-1B-S0 App auth probe."""
from pathlib import Path
import re
import unittest

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "sandbox-app-auth-probe.yml"
)
PIN = "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"


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


if __name__ == "__main__":
    unittest.main()
