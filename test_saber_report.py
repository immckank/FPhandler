import json
import os
import tempfile
import unittest

from saber_report import SaberReportStore, append_candidates, report_path_for_sar
from semantic_rules import validate


class FakeDefect:
    def __init__(self):
        self.context = None

    def get_source_loc(self):
        return {"fl": "src/a.c", "ln": 12, "cl": 3}

    def set_slice_context(self, text):
        self.context = text


class SaberReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.report = os.path.join(self.tmp.name, "report.json")
        with open(self.report, "w", encoding="utf-8") as stream:
            json.dump({
                "schema": "saber-report/v2",
                "alerts": [{
                    "alert": {
                        "id": "UNINIT@src/a.c:12->src/b.c:20",
                        "kind": "UNINIT_USE",
                        "source": {"file": "src/a.c", "line": 12, "col": 3},
                        "trace": [{
                            "role": "source", "function": "make",
                            "location": {"file": "src/a.c", "line": 12},
                            "description": "created here",
                        }],
                    },
                    "solver": {"status": "sat"},
                    "triage": None,
                    "semantic_candidates": [],
                }],
            }, stream)

    def tearDown(self):
        self.tmp.cleanup()

    def test_match_context_and_atomic_triage_update(self):
        store = SaberReportStore(self.report)
        defect = FakeDefect()
        record = store.attach_context(defect)
        self.assertIsNotNone(record)
        self.assertIn("Stable alert id", defect.context)
        result = {
            "classification": "FP",
            "reason": "initialized by make",
            "function_name": "consume",
            "semantic_candidates": [],
        }
        store.record_triage(record, result)
        reloaded = SaberReportStore(self.report)
        triage = reloaded.data["alerts"][0]["triage"]
        self.assertEqual(triage["analysis_result"]["classification"], "FP")
        self.assertTrue(triage["analysis_time"].endswith("+00:00"))
        self.assertEqual(
            reloaded.data["alerts"][0]["llm_enrichment"]["source_context"], ""
        )

    def test_output_dir_is_the_only_report_location(self):
        path = report_path_for_sar(
            "/legacy/location/sample_uninit.txt", self.tmp.name
        )
        self.assertEqual(path, os.path.join(self.tmp.name, "sample_uninit_report.json"))

    def test_candidate_repository_is_proposed_and_valid(self):
        repository = os.path.join(self.tmp.name, "rules.json")
        count = append_candidates(repository, "alert-1", [{
            "kind": "initializer",
            "function": "project_init",
            "target_arg": 0,
            "effect": "full",
            "confidence": 0.95,
            "reason": "writes every field",
        }])
        self.assertEqual(count, 1)
        with open(repository, encoding="utf-8") as stream:
            data = json.load(stream)
        self.assertEqual(data["rules"][0]["status"], "proposed")
        self.assertEqual(validate(data), [])


if __name__ == "__main__":
    unittest.main()
