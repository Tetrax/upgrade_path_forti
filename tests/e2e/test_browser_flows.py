"""End-to-end browser coverage for FortiOS Upgrade Intelligence, against a fully isolated
instance of scripts/fortios_server.py (see conftest.py) — no real data, no real network call.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect


def select_path(page, *, current: str, target: str, model: str = "FGT60F") -> None:
    page.select_option("#productSelect", "fortigate-fortios")
    page.select_option("#modelSelect", model)
    page.select_option("#currentSelect", current)
    page.select_option("#targetSelect", target)


# 1. App + catalog load -----------------------------------------------------------------

def test_app_and_catalog_load(app_page):
    expect(app_page.locator("#dataStatus")).to_contain_text("JSON généré chargé")
    # The FortiOS product from the fixture catalog must be selectable.
    options = app_page.locator("#productSelect option").all_inner_texts()
    assert any("FortiOS" in option or "FortiGate" in option for option in options)


# 2. Select product/model/version pair ---------------------------------------------------

def test_select_product_model_version(app_page):
    select_path(app_page, current="6.2.4", target="8.0.0")
    assert app_page.eval_on_selector("#productSelect", "el => el.value") == "fortigate-fortios"
    assert app_page.eval_on_selector("#modelSelect", "el => el.value") == "FGT60F"
    assert app_page.eval_on_selector("#currentSelect", "el => el.value") == "6.2.4"
    assert app_page.eval_on_selector("#targetSelect", "el => el.value") == "8.0.0"
    # Changing a dropdown must not surface a path on its own (no click yet).
    expect(app_page.locator("#result")).not_to_contain_text("Recommended path")


# 3 & 4. Successful simulated Fortinet fetch, hops/builds displayed correctly ------------

def test_successful_path_fetch_shows_hops_and_builds(app_page, fortios_server):
    fortios_server.set_mock_path_response(["6.2.4", "7.0.14", "8.0.0"])
    select_path(app_page, current="6.2.4", target="8.0.0")
    app_page.click("#goButton")

    expect(app_page.locator(".path-title .from")).to_have_text("6.2.4")
    expect(app_page.locator(".path-title .to")).to_have_text("8.0.0")
    expect(app_page.locator(".step-track")).to_contain_text("6.2.4")
    expect(app_page.locator(".step-track")).to_contain_text("7.0.14")
    expect(app_page.locator(".step-track")).to_contain_text("8.0.0")

    table = app_page.locator("table").first
    expect(table).to_contain_text("1234")  # build for 6.2.4 from the fixture catalog
    expect(table).to_contain_text("2345")  # build for 7.0.14
    expect(table).to_contain_text("3456")  # build for 8.0.0
    expect(app_page.locator(".offline-banner")).to_have_count(0)


# 5 & 6. Fortinet unavailable -> fallback to cached path, explicit cache banner ----------

def test_fortinet_unavailable_falls_back_to_cached_path_with_banner(app_page, fortios_server):
    fortios_server.set_mock_path_response(["6.2.4", "7.0.14", "8.0.0"])
    select_path(app_page, current="6.2.4", target="8.0.0")
    app_page.click("#goButton")
    expect(app_page.locator(".path-title .to")).to_have_text("8.0.0")  # first fetch cached it

    fortios_server.set_mock_path_error("Simulated Fortinet outage")
    app_page.click("#goButton")

    expect(app_page.locator(".offline-banner")).to_be_visible()
    expect(app_page.locator(".offline-banner")).to_contain_text("cache local")
    # The cached path itself must still be shown, not a blank result.
    expect(app_page.locator(".path-title .to")).to_have_text("8.0.0")
    expect(app_page.locator(".step-track")).to_contain_text("7.0.14")


# 7. Create an internal advisory ----------------------------------------------------------

def test_create_advisory(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/alerte/")
    page.fill("#titleInput", "E2E test advisory")
    page.fill("#descriptionInput", "Created by the E2E suite.")
    page.locator("#versionList").get_by_label("6.2.4").check()
    page.click("#submitButton")

    expect(page.locator("#advisoryList")).to_contain_text("E2E test advisory")


# 8. Edit an advisory ---------------------------------------------------------------------

def test_edit_advisory(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/alerte/")
    page.fill("#titleInput", "Advisory to edit")
    page.fill("#descriptionInput", "Original description.")
    page.locator("#versionList").get_by_label("6.2.4").check()
    page.click("#submitButton")
    expect(page.locator("#advisoryList")).to_contain_text("Advisory to edit")

    page.locator("article", has_text="Advisory to edit").get_by_role("button", name="Modifier").click()
    page.fill("#titleInput", "Advisory edited by E2E")
    page.click("#submitButton")

    expect(page.locator("#advisoryList")).to_contain_text("Advisory edited by E2E")
    expect(page.locator("#advisoryList")).not_to_contain_text("Advisory to edit")


# 9. Delete an advisory ---------------------------------------------------------------------

def test_delete_advisory(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/alerte/")
    page.fill("#titleInput", "Advisory to delete")
    page.fill("#descriptionInput", "Will be removed.")
    page.locator("#versionList").get_by_label("6.2.4").check()
    page.click("#submitButton")
    expect(page.locator("#advisoryList")).to_contain_text("Advisory to delete")

    page.locator("article", has_text="Advisory to delete").get_by_role("button", name="Supprimer").click()

    expect(page.locator("#advisoryList")).not_to_contain_text("Advisory to delete")


# 10 & 11. Upload a small image, then correctly delete it once unused --------------------

def test_upload_and_cleanup_unused_image(page, fortios_server, tmp_path):
    # A minimal valid 1x1 PNG.
    png_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080600000"
        "01f15c4890000000a49444154789c6360000002000155273a0f000000"
        "0049454e44ae426082"
    )
    image_path = tmp_path / "tiny.png"
    image_path.write_bytes(png_bytes)

    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/alerte/")
    page.fill("#titleInput", "Advisory with an image")
    page.fill("#descriptionInput", "Screenshot below.")
    page.locator("#versionList").get_by_label("6.2.4").check()
    page.set_input_files("#imageFileInput", str(image_path))
    expect(page.locator("#formMessage")).to_contain_text("Image ajoutée", timeout=10000)

    page.click("#submitButton")
    expect(page.locator("#advisoryList")).to_contain_text("Advisory with an image")
    assert len(fortios_server.image_files()) == 1, "the uploaded image must exist on disk"

    # Remove the image markdown from the description and save again -- the now-unreferenced
    # image file must be pruned from disk.
    page.locator("article", has_text="Advisory with an image").get_by_role("button", name="Modifier").click()
    page.fill("#descriptionInput", "Screenshot removed.")
    page.click("#submitButton")
    # Wait for the update request to actually complete before checking disk -- the backend does
    # delete the now-unreferenced image correctly, but checking immediately after the click races
    # the in-flight PUT /api/advisories/<id> request.
    expect(page.locator("#formMessage")).to_have_text("Alerte mise à jour.")

    assert fortios_server.image_files() == [], "an image no longer referenced must be deleted"


# 12. Generate and download the Markdown report -------------------------------------------

def test_download_markdown_report(app_page, fortios_server):
    fortios_server.set_mock_path_response(["6.2.4", "7.0.14", "8.0.0"])
    select_path(app_page, current="6.2.4", target="8.0.0")
    app_page.click("#goButton")
    expect(app_page.locator(".path-title .to")).to_have_text("8.0.0")

    with app_page.expect_download() as download_info:
        app_page.get_by_role("button", name="Markdown").click()
    download = download_info.value
    assert download.suggested_filename.endswith(".md")
    content = download.path().read_text(encoding="utf-8") if download.path() else ""
    if content:
        assert "6.2.4" in content and "8.0.0" in content


# 13. Applicable CVEs displayed ------------------------------------------------------------

def test_applicable_cves_displayed(app_page, fortios_server):
    fortios_server.set_mock_path_response(["6.2.4", "7.0.14", "8.0.0"])
    select_path(app_page, current="6.2.4", target="8.0.0")
    app_page.click("#goButton")

    expect(app_page.locator("#result")).to_contain_text("CVE-2026-99999")


# 14. FortiClient page + EMS/FortiClient compatibility management ------------------------

def test_forticlient_compatibility_management(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/forticlient/")
    expect(page.locator("#emsVersionSelect option")).to_have_count(1)

    page.select_option("#emsVersionSelect", "7.4.2")
    page.get_by_label("7.4.1").check()
    page.fill("#noteInput", "Tested by the E2E suite.")
    page.click("#submitButton")

    expect(page.locator("#compatList")).to_contain_text("7.4.2")
    expect(page.locator("#compatList")).to_contain_text("7.4.1")

    page.locator("article", has_text="7.4.2").get_by_role("button", name="Supprimer").click()
    expect(page.locator("#compatList")).not_to_contain_text("Tested by the E2E suite")


# 15. Health-state display ------------------------------------------------------------------

def test_health_state_display(app_page, fortios_server):
    health_payload = {
        "sources": {
            "fortios-docs": {
                "status": "ok", "lastAttemptAt": "2026-07-16T07:15:00Z",
                "lastSuccessAt": "2026-07-16T07:15:00Z", "consecutiveFailures": 0,
                "durationSeconds": 1.2, "itemsCollected": 42,
            },
            "cve-psirt": {
                "status": "error", "lastAttemptAt": "2026-07-16T07:15:00Z",
                "lastSuccessAt": "2026-07-10T07:15:00Z", "consecutiveFailures": 3,
                "lastError": "PSIRT unreachable", "durationSeconds": 0.5,
            },
            "daily-run": {
                "status": "error", "lastAttemptAt": "2026-07-16T07:15:00Z",
                "lastSuccessAt": "2026-07-15T07:15:00Z", "consecutiveFailures": 1,
                "durationSeconds": 5.0,
            },
        },
        "updatedAt": "2026-07-16T07:15:05Z",
    }
    (fortios_server.data_dir / "fortios-health.json").write_text(__import__("json").dumps(health_payload))

    app_page.reload()
    app_page.wait_for_selector("#healthSummaryText:not(:text('Chargement'))")
    expect(app_page.locator("#healthSummaryDot")).to_have_class(re.compile("error"))

    app_page.click("#healthDetails summary")
    expect(app_page.locator("#healthTableContainer")).to_contain_text("PSIRT unreachable")


# 16. Global health dot must reflect ALL sources, not just daily-run ----------------------

def test_health_dot_is_red_when_compat_matrix_fails_even_if_daily_run_is_ok(app_page, fortios_server):
    """Regression: import_forticlient_compat.py's compat-matrix step runs as a separate
    ExecStart= AFTER fortios_watch.py finishes and stamps daily-run's own aggregate status --
    so daily-run can be "ok" while compat-matrix itself failed that same day. The summary dot
    must still turn red in that case, not stay green."""
    health_payload = {
        "sources": {
            "daily-run": {
                "status": "ok", "lastAttemptAt": "2026-07-16T07:15:00Z",
                "lastSuccessAt": "2026-07-16T07:15:00Z", "consecutiveFailures": 0,
                "durationSeconds": 5.0,
            },
            "compat-matrix": {
                "status": "error", "lastAttemptAt": "2026-07-16T07:23:00Z",
                "lastSuccessAt": "2026-07-10T07:23:00Z", "consecutiveFailures": 3,
                "lastError": "PDF de compatibilité introuvable", "durationSeconds": 1.0,
            },
        },
        "updatedAt": "2026-07-16T07:23:05Z",
    }
    (fortios_server.data_dir / "fortios-health.json").write_text(__import__("json").dumps(health_payload))

    app_page.reload()
    app_page.wait_for_selector("#healthSummaryText:not(:text('Chargement'))")
    expect(app_page.locator("#healthSummaryDot")).to_have_class(re.compile("error"))
    expect(app_page.locator("#healthSummaryDot")).not_to_have_class(re.compile("\\bok\\b"))

    app_page.click("#healthDetails summary")
    expect(app_page.locator("#healthTableContainer")).to_contain_text("PDF de compatibilité introuvable")
