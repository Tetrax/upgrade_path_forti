"""Server + browser proof that the FG-IR-26-174 false positive is gone end to end.

Regression for the CVE-2026-84393 defect: the coarse CVRF feed made the collector store
whole-branch ranges (FortiOS 7.2/7.4/8.0 "Known Affected", unbounded), so a FortiGate 90G
path 7.2.10 → 7.2.13 → 7.4.12 displayed the CVE as "Toujours vulnérable après ce chemin"
although Fortinet's CSAF limits the impact to 7.6.1–7.6.6.

This test starts from the frozen copy of the production catalogue (tests/fixtures/psirt/,
pre-fix coarse entry included), runs the real reconciliation pass
(`--cve-reconcile-existing`, offline, frozen FG-IR-26-174 documents) over it, serves the
result from a real scripts/fortios_server.py and drives a real browser through the whole 90G
path: the corrected CVE must not appear anywhere, while the genuinely applicable CVEs still
do — with their real resolution hop.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest
from playwright.sync_api import expect

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import fortios_watch as fw

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "psirt"
CATALOG_COPY = FIXTURES / "catalog-live-2026-10-04.json"
ADVISORY_ID = "FG-IR-26-174"
ADVISORY_PAGE_URL = f"{fw.PSIRT_BASE_URL}/psirt/{ADVISORY_ID}"
CSAF_URL = (
    "https://filestore.fortinet.com/fortiguard/psirt/"
    "csaf_ztna-portal-improper-certificate-validation_fg-ir-26-174.json"
)

# Both come from the frozen fixture catalogue: one truly applicable High CVE on this exact
# path (resolved at 7.2.13), and the false positive this regression is about.
APPLICABLE_CVE = "CVE-2025-53844"
APPLICABLE_FIX_HOP = "7.2.13"
FIXED_CVE = "CVE-2026-84393"


def _frozen_documents_transport(url: str, timeout: int) -> str:
    """Inert PSIRT transport: the frozen FG-IR-26-174 documents, nothing else."""
    if url == ADVISORY_PAGE_URL:
        return (FIXTURES / "FG-IR-26-174.advisory.html").read_text(encoding="utf-8")
    if url == CSAF_URL:
        return (FIXTURES / "FG-IR-26-174.csaf.json").read_text(encoding="utf-8")
    raise urllib.error.URLError("not served in this test")


@pytest.fixture(scope="module")
def reconciled_catalog(tmp_path_factory) -> Path:
    """Run the real --cve-reconcile-existing pass (offline) over the frozen catalogue copy."""
    tmp = tmp_path_factory.mktemp("cve-reconcile")
    state_path = tmp / "fortios-data.generated.json"
    fw.write_json(state_path, json.loads(CATALOG_COPY.read_text(encoding="utf-8")))

    saved = {
        name: getattr(fw, name)
        for name in (
            "fetch_text",
            "discover_advisory_ids_from_rss",
            "fetch_psirt_versions",
            "fetch_fortios_lifecycle",
        )
    }
    fw.fetch_text = _frozen_documents_transport
    fw.discover_advisory_ids_from_rss = lambda timeout: []
    fw.fetch_psirt_versions = lambda timeout: set()
    fw.fetch_fortios_lifecycle = lambda timeout: {}
    try:
        exit_code = fw.main([
            "--cve-catalog", "--cve-reconcile-existing",
            "--base", str(state_path), "--output", str(state_path),
            "--report", str(tmp / "report.md"),
            "--health-output", str(tmp / "fortios-health.json"),
            "--official-paths-csv", str(tmp / "no-official-paths.csv"),
            "--advisories-csv", str(tmp / "no-advisories.csv"),
            "--upgrade-exports", str(tmp / "no-upgrade-exports"),
            "--notify-history-output", str(tmp / "notify-history.json"),
            "--notification-settings-output", str(tmp / "notification-settings.json"),
            "--cve-retry-delays-seconds", "",
            "--timeout", "5",
        ])
    finally:
        for name, value in saved.items():
            setattr(fw, name, value)
    assert exit_code == 0, "the reconciliation pass must succeed on the frozen documents"

    fixed = next(
        cve
        for cve in json.loads(state_path.read_text(encoding="utf-8"))["cves"]
        if cve["id"] == FIXED_CVE
    )
    assert fixed["affected"] == [
        {
            "product": "fortigate-fortios",
            "models": [],
            "branch": "7.6",
            "from": "7.6.1",
            "to": "7.6.6",
        }
    ], "sanity check: the pass must have corrected the coarse entry"
    return state_path


@pytest.fixture
def fortios_server_catalog(reconciled_catalog: Path) -> Path:
    """Override conftest's fixture: serve the reconciled catalogue, not the default fixture."""
    return reconciled_catalog


def test_90g_path_never_shows_the_fixed_cve(app_page, fortios_server):
    """The full 90G path in the real UI: only genuinely applicable CVEs remain."""
    fortios_server.set_mock_path_response(["7.2.10", "7.2.13", "7.4.12"])
    app_page.select_option("#productSelect", "fortigate-fortios")
    app_page.select_option("#modelSelect", "FGT90G")
    app_page.select_option("#currentSelect", "7.2.10")
    app_page.select_option("#targetSelect", "7.4.12")
    app_page.click("#goButton")

    expect(app_page.locator(".path-title .to")).to_have_text("7.4.12")

    result = app_page.locator("#result")
    expect(result).to_contain_text("Vulnérabilités connues (CVE PSIRT Fortinet)")
    # The corrected CVE must not be displayed anywhere on the path: no card, no "Toujours
    # vulnérable après ce chemin" badge, no trace in the per-firmware table.
    expect(result).not_to_contain_text(FIXED_CVE)
    # Genuinely applicable CVEs keep being displayed, with their resolution hop.
    expect(result).to_contain_text(APPLICABLE_CVE)
    expect(result).to_contain_text(f"Corrigé en {APPLICABLE_FIX_HOP}")
