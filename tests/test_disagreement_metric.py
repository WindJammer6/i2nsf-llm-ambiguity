import unittest

import spe_hl as main3
from scripts import run_main_experiment as matrix


class DisagreementMetricTests(unittest.TestCase):
    def test_structural_condition_is_excluded(self):
        policies = [
            ("a.xml", {"i2nsf-cfi-policy.rules.condition": ""}),
            ("b.xml", {}),
        ]

        result = main3.compute_disagreement_score(policies)

        self.assertEqual(result["num_fields"], 0)
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["field_results"], [])

    def test_behavioral_leaves_remain_included(self):
        paths = [
            "i2nsf-cfi-policy.rules.event.system-event",
            "i2nsf-cfi-policy.rules.condition.ddos.rate-limit.packet-rate-threshold",
            "i2nsf-cfi-policy.rules.action.primary-action.action",
            "i2nsf-cfi-policy.rules.action.secondary-action.log-action",
        ]
        policies = [
            ("a.xml", {path: "a" for path in paths}),
            ("b.xml", {path: "b" for path in paths}),
        ]

        result = main3.compute_disagreement_score(policies)

        self.assertEqual(result["num_fields"], len(paths))
        self.assertEqual({item["path"] for item in result["field_results"]}, set(paths))

    def test_repeated_leaf_indices_are_normalized(self):
        path = "i2nsf-cfi-policy.rules.condition.context.time.period.day[0]"
        self.assertTrue(main3.is_behavioral_disagreement_path(path))

    def test_all_behavioral_paths_have_clarification_categories(self):
        uncategorized = {
            path
            for path in main3.BEHAVIORAL_DS_PATHS
            if main3.categorize_disagreement_path(path) == "other"
        }
        self.assertEqual(uncategorized, set())

    def test_all_behavioral_paths_have_field_analysis_categories(self):
        categories = {matrix.classify_ds_path(path) for path in main3.BEHAVIORAL_DS_PATHS}
        self.assertNotIn("Unmapped", categories)


if __name__ == "__main__":
    unittest.main()
