import unittest

from cli.presenter import build_user_summary, priority_from_score


class UserPresenterTests(unittest.TestCase):
    def test_priority_unavailable_for_failed_status(self):
        self.assertEqual(priority_from_score(300, "analysis_error"), "unavailable")

    def test_summary_is_not_malicious_prediction(self):
        summary = build_user_summary(
            {
                "terminal_status": "success",
                "final_score": 225,
                "lifecycle_hooks": [{"hook": "postinstall", "command": "node install.js"}],
                "reachable_file_count": 1,
                "evidence": {
                    "behaviors": ["child_process"],
                    "same_hook_scope_combos": ["external_endpoint+child_process"],
                    "taint_evidence": "absent",
                },
                "recommended_review_locations": [{"file": "install.js", "line": 10, "reason": "process execution"}],
            }
        )
        self.assertEqual(summary["review_priority"]["level"], "high")
        self.assertFalse(summary["is_malicious_prediction"])
        self.assertFalse(summary["review_priority"]["is_malicious_verdict"])
        self.assertEqual(summary["status_message"], "Analysis completed.")
        self.assertEqual(summary["engine_profile"], "public-preview-2026-06")

    def test_unsupported_language_has_manual_action(self):
        summary = build_user_summary({"terminal_status": "unsupported_language", "final_score": None})
        self.assertEqual(summary["review_priority"]["level"], "unavailable")
        self.assertIn("Manually inspect", summary["safe_next_actions"][0])


if __name__ == "__main__":
    unittest.main()
