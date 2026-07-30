"""Execute the production precise-hop matcher with Node.js."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATCHER = ROOT / "app" / "advisory-matching.js"
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "Node.js is required for browser-logic tests")
class AdvisoryMatchingBrowserLogicTests(unittest.TestCase):
    def evaluate(self, expression: str) -> object:
        script = (
            f"const matching = require({json.dumps(str(MATCHER))});"
            f"process.stdout.write(JSON.stringify({expression}));"
        )
        result = subprocess.run(
            [str(NODE), "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_matches_only_the_adjacent_ordered_hop(self) -> None:
        advisory = '{from: "7.6.6", to: "7.6.7"}'
        self.assertTrue(
            self.evaluate(
                f'matching.preciseHopMatches({advisory}, '
                '{hops: ["7.6.5", "7.6.6", "7.6.7", "7.6.8"]})',
            ),
        )
        self.assertFalse(
            self.evaluate(
                f'matching.preciseHopMatches({advisory}, '
                '{hops: ["7.6.6", "7.6.6-p1", "7.6.7"]})',
            ),
        )
        self.assertFalse(
            self.evaluate(
                f'matching.preciseHopMatches({advisory}, '
                '{hops: ["7.6.7", "7.6.6"]})',
            ),
        )

    def test_attributes_the_alert_only_to_the_destination_row(self) -> None:
        advisory = '{from: "7.6.6", to: "7.6.7"}'
        path = '{hops: ["7.6.6", "7.6.7", "7.6.8"]}'
        self.assertFalse(
            self.evaluate(
                f'matching.preciseHopMatchesVersion({advisory}, "7.6.6", {path})',
            ),
        )
        self.assertTrue(
            self.evaluate(
                f'matching.preciseHopMatchesVersion({advisory}, "7.6.7", {path})',
            ),
        )
        self.assertFalse(
            self.evaluate(
                f'matching.preciseHopMatchesVersion({advisory}, "7.6.8", {path})',
            ),
        )


if __name__ == "__main__":
    unittest.main()
