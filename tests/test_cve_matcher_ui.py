"""Browser-side CVE matcher coverage for crossed FortiClient platforms.

The collector scopes affected-ness and exclusions per product AND platform
(Windows/macOS/Linux share the `forticlient` product id). These tests run the *real*
`cveMatchesVersion` functions extracted from the two served frontends (`app/index.html`
and `app/forticlient/app.js`) under Node, so the UI side of that contract is pinned to
exactly the data the collector emits. Purely local: no network access, and skipped when
Node is unavailable.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTENDS = {
    "index": REPO_ROOT / "app" / "index.html",
    "forticlient": REPO_ROOT / "app" / "forticlient" / "app.js",
}

# A CVE exactly as the collector now emits it for a crossed-platform FortiClient bulletin:
# Windows is affected on the whole 7.2 train; macOS 7.2 is affected except the fixed 7.2.9;
# Linux is not affected at all.
CROSSED_PLATFORM_CVE = {
    "affected": [
        {
            "product": "forticlient",
            "models": ["windows"],
            "branch": "7.2",
            "from": None,
            "to": None,
        },
        {
            "product": "forticlient",
            "models": ["macos"],
            "branch": "7.2",
            "from": None,
            "to": None,
            "excluded": ["7.2.9"],
        },
    ]
}

CASES = [
    {"product": "forticlient", "model": "windows", "version": "7.2.9", "expected": True},
    {"product": "forticlient", "model": "windows", "version": "7.2.12", "expected": True},
    {"product": "forticlient", "model": "macos", "version": "7.2.9", "expected": False},
    {"product": "forticlient", "model": "macos", "version": "7.2.12", "expected": True},
    {"product": "forticlient", "model": "linux", "version": "7.2.9", "expected": False},
]


def _extract_function(source: str, name: str) -> str:
    """Extract `function name(...) {...}` by brace matching.

    These helpers contain no braces inside strings or comments, so counting braces is exact.
    """
    match = re.search(rf"(?m)^\s*function {re.escape(name)}\(", source)
    if not match:
        raise AssertionError(f"function {name} not found in source")
    start = match.start()
    brace = source.index("{", match.end())
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unbalanced braces while extracting {name}")


@unittest.skipUnless(shutil.which("node"), "node is required to run the frontend matchers")
class FrontendCveMatcherTests(unittest.TestCase):
    def _run_matcher(self, frontend: Path) -> list[bool]:
        source = frontend.read_text(encoding="utf-8")
        driver = "\n".join(
            [
                _extract_function(source, "branchOf"),
                _extract_function(source, "compareVersions"),
                _extract_function(source, "cveMatchesVersion"),
            ]
        ) + """
const cve = JSON.parse(process.argv[2]);
const cases = JSON.parse(process.argv[3]);
const results = cases.map((item) =>
  cveMatchesVersion(cve, item.product, item.model, item.version)
);
process.stdout.write(JSON.stringify(results));
"""
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "matcher.js"
            script.write_text(driver, encoding="utf-8")
            completed = subprocess.run(
                [
                    "node",
                    str(script),
                    json.dumps(CROSSED_PLATFORM_CVE),
                    json.dumps(CASES),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
        return json.loads(completed.stdout)

    def test_crossed_platforms_match_per_platform(self) -> None:
        expected = [case["expected"] for case in CASES]
        for name, frontend in FRONTENDS.items():
            with self.subTest(frontend=name):
                self.assertEqual(self._run_matcher(frontend), expected)


if __name__ == "__main__":
    unittest.main()
