"""The Upgrade Path Tool's JSON API, as Fortinet's own /upgrade-tool/<product> page calls it.

Fortinet retired the two endpoints this collector used until 2026-09
(`/upgrade-tool/products/<slug>.json` and `POST /upgrade-tool/upgrade-path`, both 404) and
replaced them with:

- ``GET /api/tools/upgrade-path/models?product=<slug>`` -> ``[{"name": ..., "value": ...}]``
- ``GET /api/tools/upgrade-path?product=&model=[&from=&to=]``
  -> ``{"availableFrom": [...], "availableTo": [...], "path": [...]}``
  with items ``{"version", "type", "build", "links"}``.

These tests pin the adaptation: the new shapes are parsed faithfully (build from ``build``,
deep links from ``links``, maturity "M"/"F" translated to the "Mature"/"Feature" the catalog and
UI have always stored), and every unusable answer fails closed (raise) instead of being
mistaken for "no versions"/"no path".
"""

import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import json

import fortios_watch as fw

MODELS_RESPONSE = json.dumps(
    [
        {"name": "FMG_1000F", "value": "FMG1KF"},
        {"name": "FMG_VM64", "value": "FMVM64"},
    ]
).encode("utf-8")

PATH_RESPONSE = json.dumps(
    {
        "availableFrom": [
            {"version": "7.0.15", "type": "M", "build": "0632"},
            {"version": "7.6.7", "type": "M", "build": "3704"},
        ],
        "availableTo": [
            {"version": "7.4.11", "type": "M", "build": "2878"},
            {"version": "8.0.1", "type": "F", "build": "0245"},
        ],
        "path": [
            {
                "version": "7.0.15",
                "type": "M",
                "build": "0632",
                "links": {
                    "resolved-issues": "https://docs.fortinet.com/document/fortigate/7.0.15/fortios-release-notes/289806/resolved-issues",
                    "known-issues": "https://docs.fortinet.com/document/fortigate/7.0.15/fortios-release-notes/236526/known-issues",
                    "special-notices": "https://docs.fortinet.com/document/fortigate/7.0.15/fortios-release-notes/708555/special-notices",
                },
            },
            {"version": "7.2.10", "type": "M", "build": "1706", "links": {}},
            {"version": "7.4.11", "type": "M", "build": "2878", "links": {}},
        ],
    }
).encode("utf-8")


class UpgradeToolRequestTests(unittest.TestCase):
    def test_payload_uses_the_new_endpoint_with_get_parameters(self):
        seen = {}

        def fake_read(request, timeout, retries=3):
            seen["url"] = request.full_url
            seen["method"] = request.get_method()
            seen["body"] = request.data
            seen["referer"] = request.headers.get("Referer")
            return b'{"path": []}'

        with patch.object(fw, "read_url_with_retry", side_effect=fake_read):
            fw.fetch_upgrade_tool_payload(
                "fortimanager",
                "FMG1KF",
                timeout=5,
                from_version="6.4.0",
                to_version="7.4.5",
            )

        parsed = urllib.parse.urlparse(seen["url"])
        self.assertEqual(parsed.path, "/api/tools/upgrade-path")
        self.assertEqual(
            urllib.parse.parse_qs(parsed.query),
            {
                "product": ["fortimanager"],
                "model": ["FMG1KF"],
                "from": ["6.4.0"],
                "to": ["7.4.5"],
            },
        )
        self.assertEqual(seen["method"], "GET")
        self.assertIsNone(seen["body"])
        self.assertEqual(seen["referer"], "https://docs.fortinet.com/upgrade-tool/fortimanager")

    def test_optional_bounds_are_omitted_when_only_one_is_given(self):
        seen = {}

        def fake_read(request, timeout, retries=3):
            seen["url"] = request.full_url
            return b'{"path": []}'

        with patch.object(fw, "read_url_with_retry", side_effect=fake_read):
            fw.fetch_upgrade_tool_payload("fortigate", "FGT60F", timeout=5, from_version="7.0.0")

        self.assertNotIn("from=", seen["url"])
        self.assertNotIn("to=", seen["url"])

    def test_a_non_object_response_fails_closed(self):
        with (
            patch.object(fw, "read_url_with_retry", return_value=b"[]"),
            self.assertRaises(fw.UpgradeToolResponseError),
        ):
            fw.fetch_upgrade_tool_payload("fortigate", "FGT60F", timeout=5)


class ProductModelsTests(unittest.TestCase):
    def test_models_are_mapped_from_name_value(self):
        with patch.object(fw, "read_url_with_retry", return_value=MODELS_RESPONSE) as read:
            models = fw.fetch_product_models("fortimanager", timeout=5)

        self.assertEqual(
            models,
            [
                {"product_name": "FMG_1000F", "hardware_model_name": "FMG1KF"},
                {"product_name": "FMG_VM64", "hardware_model_name": "FMVM64"},
            ],
        )
        self.assertIn("models?product=fortimanager", read.call_args.args[0].full_url)

    def test_empty_model_list_is_retried_then_reads_as_no_models(self):
        with (
            patch.object(fw, "read_url_with_retry", return_value=b"[]") as read,
            patch.object(fw.time, "sleep") as sleep,
            patch.object(fw.random, "uniform", return_value=0),
        ):
            models = fw.fetch_product_models("fortimanager", timeout=5)

        self.assertEqual(models, [])
        self.assertEqual(read.call_count, 3)
        self.assertEqual([args[0] for args, _ in sleep.call_args_list], [1, 2])

    def test_a_malformed_model_entry_fails_closed(self):
        with (
            patch.object(fw, "read_url_with_retry", return_value=b'[{"name": "FMG_1000F"}]'),
            self.assertRaises(fw.UpgradeToolResponseError),
        ):
            fw.fetch_product_models("fortimanager", timeout=5)

    def test_alias_resolution_uses_the_new_model_list(self):
        with patch.object(
            fw,
            "fetch_product_models",
            return_value=[
                {"product_name": "FortiGate-100F", "hardware_model_name": "FG100F"},
            ],
        ):
            fw._FORTINET_MODEL_ALIASES.pop("fortigate", None)
            try:
                self.assertEqual(
                    fw.resolve_fortinet_model(
                        fw.DEFAULT_PRODUCT_ID, "FGT100F", timeout=5
                    ),
                    "FG100F",
                )
            finally:
                fw._FORTINET_MODEL_ALIASES.pop("fortigate", None)


class ModelFirmwaresTests(unittest.TestCase):
    def test_firmwares_use_the_build_field_from_available_lists(self):
        with patch.object(fw, "read_url_with_retry", return_value=PATH_RESPONSE):
            firmwares = fw.fetch_model_firmwares("fortimanager", "FMG1KF", timeout=5)

        by_version = {item["version"]: item for item in firmwares}
        self.assertEqual(by_version["7.0.15"]["build"], "0632")
        self.assertEqual(by_version["8.0.1"]["build"], "0245")

    def test_a_model_without_any_version_fails_closed(self):
        empty = json.dumps(
            {"availableFrom": [], "availableTo": [], "path": []}
        ).encode("utf-8")
        with (
            patch.object(fw, "read_url_with_retry", return_value=empty),
            self.assertRaises(fw.UpgradeToolResponseError),
        ):
            fw.fetch_model_firmwares("fortimanager", "NOPE", timeout=5)

    def test_a_malformed_version_entry_fails_closed(self):
        malformed = json.dumps(
            {"availableFrom": [{"build": "1234"}], "availableTo": []}
        ).encode("utf-8")
        with (
            patch.object(fw, "read_url_with_retry", return_value=malformed),
            self.assertRaises(fw.UpgradeToolResponseError),
        ):
            fw.fetch_model_firmwares("fortimanager", "FMG1KF", timeout=5)

    def test_collect_tool_catalog_builds_models_and_builds_from_the_new_api(self):
        responses = {
            "/api/tools/upgrade-path/models?product=fortimanager": MODELS_RESPONSE,
            "/api/tools/upgrade-path?product=fortimanager&model=FMG1KF": PATH_RESPONSE,
            "/api/tools/upgrade-path?product=fortimanager&model=FMVM64": json.dumps(
                {"availableFrom": [{"version": "6.4.0", "build": "2002"}], "availableTo": []}
            ).encode("utf-8"),
        }

        def fake_read(request, timeout, retries=3):
            for suffix, body in responses.items():
                if request.full_url.endswith(suffix):
                    return body
            self.fail(f"unexpected fetch: {request.full_url}")

        with patch.object(fw, "read_url_with_retry", side_effect=fake_read):
            state = fw.collect_tool_catalog("fortimanager", timeout=5)

        product = next(
            item for item in state["products"] if item["id"] == "fortimanager"
        )
        models = {model["id"]: model for model in product["models"]}
        self.assertEqual(set(models), {"FMG1KF", "FMVM64"})
        self.assertEqual(models["FMG1KF"]["label"], "FMG_1000F")
        firmwares = {item["version"]: item for item in models["FMG1KF"]["firmwares"]}
        self.assertEqual(firmwares["7.4.11"]["build"], "2878")
        self.assertEqual(
            firmwares["7.4.11"]["links"]["release-notes"],
            "https://docs.fortinet.com/document/fortimanager/7.4.11/release-notes",
        )


class MaturityTests(unittest.TestCase):
    def test_maturity_abbreviations_are_translated_like_the_historical_catalog(self):
        payload = json.dumps(
            {
                "availableFrom": [
                    {"version": "7.0.15", "type": "M", "build": "0632"},
                    {"version": "7.0.6", "type": "F", "build": "0366"},
                    {"version": "6.4.10", "type": "", "build": "2000"},
                ],
                "availableTo": [{"version": "8.0.1", "type": "F", "build": "0245"}],
                "path": [],
            }
        ).encode("utf-8")
        with patch.object(fw, "read_url_with_retry", return_value=payload):
            maturity = fw.fetch_fortios_version_maturity(timeout=5)

        self.assertEqual(
            maturity,
            {
                "7.0.15": "Mature",
                "7.0.6": "Feature",
                "6.4.10": "None",
                "8.0.1": "Feature",
            },
        )


class OfficialUpgradePathTests(unittest.TestCase):
    def setUp(self):
        self._resolve = fw.resolve_fortinet_model
        fw.resolve_fortinet_model = lambda *a, **k: "FGT60F"

    def tearDown(self):
        fw.resolve_fortinet_model = self._resolve

    def test_new_response_shape_is_parsed(self):
        with patch.object(fw, "read_url_with_retry", return_value=PATH_RESPONSE):
            result = fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product=fw.DEFAULT_PRODUCT_ID,
                    model="FGT60F",
                    from_version="7.0.15",
                    to_version="7.4.11",
                ),
                timeout=5,
            )

        self.assertIsNotNone(result)
        path, firmwares = result
        self.assertEqual(path.hops, ("7.0.15", "7.2.10", "7.4.11"))
        first = firmwares[0]
        self.assertEqual(first.build, "0632")
        self.assertEqual(first.notes, ("resolved", "known", "special"))
        self.assertEqual(
            first.links["resolved"],
            "https://docs.fortinet.com/document/fortigate/7.0.15/fortios-release-notes/289806/resolved-issues",
        )
        self.assertEqual(
            first.links["release-notes"],
            "https://docs.fortinet.com/document/fortigate/7.0.15/fortios-release-notes",
        )

    def test_mismatched_endpoints_are_rejected_not_cached(self):
        payload = json.dumps(
            {"path": [{"version": "6.2.4"}, {"version": "7.0.1"}, {"version": "7.4.2"}]}
        ).encode("utf-8")
        with patch.object(fw, "read_url_with_retry", return_value=payload):
            result = fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product=fw.DEFAULT_PRODUCT_ID,
                    model="FGT60F",
                    from_version="6.2.4",
                    to_version="8.0.0",
                ),
                timeout=5,
            )
        self.assertIsNone(result)

    def test_a_single_hop_path_is_not_a_path(self):
        payload = json.dumps({"path": [{"version": "7.0.15"}]}).encode("utf-8")
        with patch.object(fw, "read_url_with_retry", return_value=payload):
            result = fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product=fw.DEFAULT_PRODUCT_ID,
                    model="FGT60F",
                    from_version="7.0.15",
                    to_version="7.4.11",
                ),
                timeout=5,
            )
        self.assertIsNone(result)

    def test_a_hop_without_a_valid_version_fails_closed(self):
        payload = json.dumps(
            {"path": [{"version": "7.0.15"}, {"note": "hop manquant"}, {"version": "7.4.11"}]}
        ).encode("utf-8")
        with (
            patch.object(fw, "read_url_with_retry", return_value=payload),
            self.assertRaises(fw.UpgradeToolResponseError),
        ):
            fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product=fw.DEFAULT_PRODUCT_ID,
                    model="FGT60F",
                    from_version="7.0.15",
                    to_version="7.4.11",
                ),
                timeout=5,
            )

    def test_downgrade_is_rejected_before_any_http_call(self):
        def unexpected(request, timeout, retries=3):
            self.fail("Fortinet must not be called for an invalid direction")

        with (
            patch.object(fw, "read_url_with_retry", side_effect=unexpected),
            self.assertRaisesRegex(
                ValueError, "La version cible doit être supérieure à la version source"
            ),
        ):
            fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product=fw.DEFAULT_PRODUCT_ID,
                    model="FGT60F",
                    from_version="7.4.12",
                    to_version="7.2.13",
                ),
                timeout=5,
            )

    def test_fortimanager_path_is_fetched_for_non_fortigate_products(self):
        payload = json.dumps(
            {
                "availableFrom": [{"version": "6.4.0", "build": "2002"}],
                "availableTo": [{"version": "7.4.5", "build": "0176"}],
                "path": [
                    {"version": "6.4.0", "build": "2002"},
                    {"version": "7.4.5", "build": "0176"},
                ],
            }
        ).encode("utf-8")
        seen = {}

        def fake_read(request, timeout, retries=3):
            seen["url"] = request.full_url
            return payload

        with patch.object(fw, "read_url_with_retry", side_effect=fake_read):
            result = fw.fetch_official_upgrade_path(
                fw.OfficialPathRequest(
                    product="fortimanager",
                    model="FMG1KF",
                    from_version="6.4.0",
                    to_version="7.4.5",
                ),
                timeout=5,
            )

        self.assertIsNotNone(result)
        path, firmwares = result
        self.assertEqual(path.product, "fortimanager")
        self.assertEqual(path.hops, ("6.4.0", "7.4.5"))
        self.assertEqual(firmwares[-1].build, "0176")
        self.assertIn("product=fortimanager", seen["url"])
        self.assertIn("model=FMG1KF", seen["url"])


if __name__ == "__main__":
    unittest.main()
