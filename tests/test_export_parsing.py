"""Covers scripts/fortios_watch.py's parse_upgrade_export()/parse_upgrade_export_json() and
fetch_official_upgrade_path()'s response validation.

The import used to regex-scan the entire raw text of an export for version-looking substrings,
so a decoy version sitting in an unrelated field (a "note") got spliced into the path as a
fabricated hop. It's now only used as a fallback for genuinely non-JSON text/CSV input; valid
JSON must match an explicitly recognized shape or gets rejected outright.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402


class UpgradeExportParsingTests(unittest.TestCase):
    def test_api_response_shape(self):
        text = json.dumps({"result": {"path": [
            {"version": "7.2.10"}, {"version": "7.4.8"}, {"version": "7.4.11"},
        ]}})
        self.assertEqual(fw.parse_upgrade_export(text), ["7.2.10", "7.4.8", "7.4.11"])

    def test_alternate_shape_plain_string_array(self):
        text = json.dumps({"path": ["7.2.10", "7.4.8", "7.4.11"], "note": "some note"})
        self.assertEqual(fw.parse_upgrade_export(text), ["7.2.10", "7.4.8", "7.4.11"])

    def test_alternate_shape_object_array(self):
        text = json.dumps({"path": [{"version": "7.2.10"}, {"version": "7.4.8"}]})
        self.assertEqual(fw.parse_upgrade_export(text), ["7.2.10", "7.4.8"])

    def test_unrecognized_json_shape_is_rejected_outright(self):
        text = json.dumps({"current": "7.2.10", "target": "7.4.11", "somethingElse": ["7.2.10", "7.4.11"]})
        self.assertIsNone(fw.parse_upgrade_export(text))

    def test_decoy_version_in_unrelated_field_is_ignored(self):
        """Codex's exact repro: a legitimate path[] next to a "note" mentioning an unrelated
        version must never let that version leak into the hop list."""
        text = json.dumps({
            "current": "7.2.10",
            "note": "fixed since 6.4.15",
            "path": ["7.2.10", "7.4.8", "7.4.11"],
        })
        self.assertEqual(fw.parse_upgrade_export(text), ["7.2.10", "7.4.8", "7.4.11"])

    def test_plain_text_csv_fallback_still_works(self):
        text = "Chemin recommande: 7.2.10 > 7.4.8 > 7.4.11"
        self.assertEqual(fw.parse_upgrade_export(text), ["7.2.10", "7.4.8", "7.4.11"])

    def test_mismatched_endpoints_are_rejected(self):
        text = json.dumps({"path": ["7.2.10", "7.4.8", "7.4.11"]})
        result = fw.parse_upgrade_export(text, expected_from="7.2.10", expected_to="8.0.0")
        self.assertIsNone(result)

    def test_matching_endpoints_are_accepted(self):
        text = json.dumps({"path": ["7.2.10", "7.4.8", "7.4.11"]})
        result = fw.parse_upgrade_export(text, expected_from="7.2.10", expected_to="7.4.11")
        self.assertEqual(result, ["7.2.10", "7.4.8", "7.4.11"])

    def test_non_json_garbage_falls_back_to_regex_not_rejected(self):
        text = "some plain notes mentioning 7.6.7 as a target"
        self.assertEqual(fw.parse_upgrade_export(text), ["7.6.7"])


class OfficialUpgradePathValidationTests(unittest.TestCase):
    def setUp(self):
        self._orig_resolve = fw.resolve_fortinet_model
        self._orig_post = fw.post_official_upgrade_tool
        fw.resolve_fortinet_model = lambda *a, **k: "FG60F"

    def tearDown(self):
        fw.resolve_fortinet_model = self._orig_resolve
        fw.post_official_upgrade_tool = self._orig_post

    def test_mismatched_endpoints_are_rejected_not_cached(self):
        fw.post_official_upgrade_tool = lambda payload, timeout: {
            "result": {"path": [{"version": "6.2.4"}, {"version": "7.0.1"}, {"version": "7.4.2"}]}
        }
        request = fw.OfficialPathRequest(
            product="fortigate-fortios", model="FGT60F", from_version="6.2.4", to_version="8.0.0",
        )
        self.assertIsNone(fw.fetch_official_upgrade_path(request, timeout=5))

    def test_matching_endpoints_are_accepted(self):
        fw.post_official_upgrade_tool = lambda payload, timeout: {
            "result": {"path": [{"version": "6.2.4"}, {"version": "7.0.1"}, {"version": "8.0.0"}]}
        }
        request = fw.OfficialPathRequest(
            product="fortigate-fortios", model="FGT60F", from_version="6.2.4", to_version="8.0.0",
        )
        result = fw.fetch_official_upgrade_path(request, timeout=5)
        self.assertIsNotNone(result)
        path, _firmwares = result
        self.assertEqual(path.hops, ("6.2.4", "7.0.1", "8.0.0"))
        self.assertEqual(path.hops[0], request.from_version)
        self.assertEqual(path.hops[-1], request.to_version)


if __name__ == "__main__":
    unittest.main()
