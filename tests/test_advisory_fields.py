"""Validation tests for advisory version targeting modes."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fortios_server import parse_advisory_fields  # noqa: E402


class AdvisoryTargetingTests(unittest.TestCase):
    @staticmethod
    def payload(**overrides: object) -> dict[str, object]:
        return {
            "title": "Perte de configuration pendant une bascule",
            "description": "La configuration doit être contrôlée après le redémarrage.",
            **overrides,
        }

    def test_precise_hop_is_persisted_as_the_only_version_target(self) -> None:
        fields = parse_advisory_fields(
            self.payload(
                **{
                    "from": "7.6.6",
                    "to": "7.6.7",
                    "versions": [],
                    "minVersions": [],
                },
            ),
        )

        self.assertEqual(fields["from"], "7.6.6")
        self.assertEqual(fields["to"], "7.6.7")
        self.assertNotIn("versions", fields)
        self.assertNotIn("minVersions", fields)

    def test_precise_hop_requires_two_distinct_versions(self) -> None:
        for targeting in (
            {"from": "7.6.6"},
            {"to": "7.6.7"},
            {"from": "7.6.7", "to": "7.6.7"},
        ):
            with self.subTest(targeting=targeting), self.assertRaises(ValueError):
                parse_advisory_fields(self.payload(**targeting))

    def test_multiple_version_targeting_modes_are_rejected(self) -> None:
        conflicting_payloads = (
            {"versions": ["7.6.7"], "minVersions": ["7.6.6"]},
            {"versions": ["7.6.7"], "from": "7.6.6", "to": "7.6.7"},
            {"minVersions": ["7.6.6"], "from": "7.6.6", "to": "7.6.7"},
        )
        for targeting in conflicting_payloads:
            with self.subTest(targeting=targeting), self.assertRaises(ValueError):
                parse_advisory_fields(self.payload(**targeting))


if __name__ == "__main__":
    unittest.main()
