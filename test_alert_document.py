import json
import os
import tempfile
import unittest

from alert_document import AlertDocument, UnifiedAlert, validate_document


def uaf_document():
    return {
        "alert_id": "sha256:" + "a" * 64,
        "category": "USE_AFTER_FREE",
        "path": [
            {
                "role": "allocation",
                "location": {"file": "src/a.c", "line": 3, "column": 1},
            },
            {
                "role": "free",
                "location": {"file": "src/a.c", "line": 8, "column": 2},
            },
            {
                "role": "use",
                "location": {"file": "src/a.c", "line": 12, "column": 4},
            },
        ],
        "evidence": {"memory_object": {}, "checker": {}},
        "classification": None,
        "reason": "",
    }


class AlertDocumentTests(unittest.TestCase):
    def test_non_leak_requires_one_path(self):
        document = uaf_document()
        self.assertEqual(validate_document(document), [])
        document["paths"] = []
        self.assertIn("non-leak alert must not contain paths", validate_document(document))

    def test_leak_uses_safe_paths_and_complement(self):
        document = {
            "alert_id": "sha256:" + "b" * 64,
            "category": "MEMORY_LEAK",
            "allocation": {"role": "allocation", "location": {}},
            "paths": [],
            "leak_condition": {"op": "and", "terms": []},
            "classification": None,
            "reason": "",
        }
        self.assertEqual(validate_document(document), [])

    def test_primary_location_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "alert.json")
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(uaf_document(), stream)
            document = AlertDocument.load(path)
            alert = UnifiedAlert(document)
            self.assertEqual(alert.get_source_loc()["ln"], 12)
            document.write_classification(
                {"classification": "FP", "reason": "mutually exclusive branches"}
            )
            reloaded = AlertDocument.load(path)
            self.assertEqual(reloaded.data["classification"], "FP")
            self.assertEqual(reloaded.data["reason"], "mutually exclusive branches")


if __name__ == "__main__":
    unittest.main()
