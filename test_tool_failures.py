import json
import tempfile
import unittest
from unittest.mock import patch

from tool_failures import ToolFailureRecorder, classify_tool_failure


class TestClassifyToolFailure(unittest.TestCase):
    def test_none_response(self):
        failure = classify_tool_failure(None)
        self.assertEqual(failure["kind"], "null_response")

    def test_no_such_file_string(self):
        failure = classify_tool_failure("No such file, please check filename.")
        self.assertEqual(failure["kind"], "no_such_file")

    def test_error_dict(self):
        failure = classify_tool_failure(
            {"error": "Error finding function body for FalconLog, plesse check if the name is right. True"}
        )
        self.assertEqual(failure["kind"], "error_dict")

    def test_degraded_function_body(self):
        failure = classify_tool_failure(
            {
                "error": False,
                "function_body": "No such file, please check filename.",
                "filename": "source/FalconFS/common/src/include/log/logging.h",
            }
        )
        self.assertEqual(failure["kind"], "degraded_no_such_file")

    def test_success_response(self):
        self.assertIsNone(classify_tool_failure({"function_name": "foo", "function_body": "int foo(){}"}))
        self.assertIsNone(classify_tool_failure("if (isEnabled) {"))


class TestToolFailureRecorder(unittest.TestCase):
    def test_record_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("tool_failures._config") as config_fn:
                config_fn.return_value = type(
                    "Cfg",
                    (),
                    {
                        "RES_ROOT_PATH": tmp,
                        "RUN_LOG_STEM": "test",
                        "RUN_SESSION_TIME_STR": "2026-07-02-13-00-00",
                    },
                )()
                recorder = ToolFailureRecorder()
                recorded = recorder.record(
                    tool="dump_source_snippet",
                    response="No such file, please check filename.",
                    batch_id="B0001",
                    turn=3,
                    arguments={"file_name": "logging.h", "start_line": 1, "end_line": 10},
                )
            self.assertTrue(recorded)
            self.assertEqual(recorder.summary()["total"], 1)
            with open(recorder.path, encoding="utf-8") as handle:
                row = json.loads(handle.readline())
            self.assertEqual(row["tool"], "dump_source_snippet")
            self.assertEqual(row["failure_kind"], "no_such_file")


if __name__ == "__main__":
    unittest.main()
