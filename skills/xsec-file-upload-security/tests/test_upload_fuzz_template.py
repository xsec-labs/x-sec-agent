from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "upload_fuzz_template.py"


def load_module():
    spec = importlib.util.spec_from_file_location("upload_fuzz_template", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class UploadFuzzTemplateTest(unittest.TestCase):
    def test_generates_harmless_cases_from_sample_request(self):
        module = load_module()
        request = module.parse_raw_request(module.SAMPLE_RAW_REQUEST)
        original_filename = module.extract_original_filename(request.body)
        original_content_type = module.extract_part_content_type(request.body)
        cases = module.generate_fuzz_cases(original_filename, original_content_type, max_payloads=0)

        expected_categories = {
            "case_variation",
            "config_files",
            "content_disposition",
            "content_type",
            "control",
            "double_extension",
            "encoding",
            "linux_features",
            "magic_bytes",
            "null_byte",
            "special_chars",
            "suffix",
            "waf_bypass",
            "windows_features",
        }
        self.assertGreaterEqual(len(cases), 1000)
        self.assertEqual(expected_categories, {case.category for case in cases})
        forbidden_fragments = [b"<?php", b"<%", b"Runtime.getRuntime", b"SetHandler", b"auto_prepend_file"]
        for case in cases:
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, case.file_content)

        raw_null_case = next(case for case in cases if case.category == "null_byte" and "\x00" in case.filename)
        mutated_body = module.apply_case_to_body(request.body, raw_null_case)
        self.assertIn(b"\x00", mutated_body)

        png_magic_case = next(case for case in cases if case.category == "magic_bytes" and case.file_content.startswith(b"\x89PNG"))
        self.assertIn(module.MARKER, module.apply_case_to_body(request.body, png_magic_case))

        gif_magic_case = next(case for case in cases if case.category == "magic_bytes" and case.file_content.startswith(b"GIF89a"))
        self.assertIn(module.MARKER, module.apply_case_to_body(request.body, gif_magic_case))

        config_case = next(case for case in cases if case.filename == "web.config")
        self.assertIn(b"xsec-upload-check", config_case.file_content)

        header_case = next(case for case in cases if case.category == "content_disposition" and case.filename_token and "filename==" in case.filename_token)
        self.assertIn(b"filename==", module.apply_case_to_body(request.body, header_case))

        rendered = module.render_raw_request(request, mutated_body)
        self.assertIn(b"Content-Length: ", rendered)
        content_length_line = next(line for line in rendered.splitlines() if line.startswith(b"Content-Length: "))
        content_length = int(content_length_line.split(b":", 1)[1].strip())
        self.assertEqual(content_length, len(mutated_body))

    def test_cli_self_test_writes_cases_jsonl_and_raw_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--self-test",
                    "--limit",
                    "0",
                    "--output-dir",
                    tmp,
                    "--json",
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["status"], "ok")
            self.assertGreaterEqual(summary["case_count"], 1000)
            self.assertIn("magic_bytes", summary["categories"])
            self.assertIn("config_files", summary["categories"])
            self.assertIn("content_disposition", summary["categories"])

            cases_path = Path(tmp) / "cases.jsonl"
            self.assertTrue(cases_path.exists())
            rows = [json.loads(line) for line in cases_path.read_text().splitlines()]
            self.assertEqual(len(rows), summary["case_count"])
            for row in rows:
                self.assertTrue(Path(row["raw_request_path"]).exists())
                self.assertFalse(row["sent"])


if __name__ == "__main__":
    unittest.main()
