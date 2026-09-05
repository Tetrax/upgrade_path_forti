"""End-to-end browser coverage for FortiOS Upgrade Intelligence, against a fully isolated
instance of scripts/fortios_server.py (see conftest.py) — no real data, no real network call.
"""

from __future__ import annotations

import json
import re
import secrets

from playwright.sync_api import expect

from scripts import cert_admin


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


def test_certificate_first_run_creates_the_admin_account(page, fortios_server):
    fortios_server.credentials_path.unlink()
    page.goto(f"{fortios_server.base_url}/cert/")

    expect(page.locator("#setup-view")).to_be_visible()
    expect(page.locator("#login-view")).to_be_hidden()
    expect(page.locator("#setup-username")).to_have_value("admin")
    page.fill("#setup-password", "browser-test-password")
    page.fill("#setup-password-confirmation", "browser-test-password")
    page.fill("#setup-recovery-email", "owner@example.test")
    page.click("#setup-button")

    expect(page.locator("#admin-view")).to_be_visible()
    expect(page.locator("#session-username")).to_have_text("admin")
    page.click("#account-tab")
    expect(page.locator("#account-recovery-email")).to_have_text("o***r@example.test")
    expect(page.locator("#account-recovery-status")).to_have_text("En attente de vérification")
    assert fortios_server.credentials_path.is_file()
    assert "browser-test-password" not in fortios_server.credentials_path.read_text()
    assert not fortios_server.certificate_output_dir.exists()


def test_admin_can_rotate_password_and_must_reauthenticate(page, fortios_server):
    login_cert_admin(page, fortios_server)
    new_password = secrets.token_urlsafe(24)

    page.click("#account-tab")
    expect(page.get_by_role("heading", name="Compte & sécurité", exact=True)).to_be_visible()
    page.click("#change-password-button")
    for selector in (
        "#current-admin-password",
        "#new-admin-password",
        "#confirm-admin-password",
    ):
        expect(page.locator(selector)).to_have_attribute("type", "password")

    page.fill("#current-admin-password", "incorrect-current-password")
    page.fill("#new-admin-password", new_password)
    page.fill("#confirm-admin-password", new_password)
    page.click("#submit-password-change-button")
    expect(page.locator("#password-change-message")).to_have_text(
        "Mot de passe actuel incorrect."
    )
    expect(page.locator("#admin-view")).to_be_visible()

    page.fill("#current-admin-password", fortios_server.admin_password)
    page.fill("#new-admin-password", new_password)
    page.fill("#confirm-admin-password", new_password)
    page.click("#submit-password-change-button")

    expect(page.locator("#login-view")).to_be_visible()
    expect(page.locator("#admin-view")).to_be_hidden()
    expect(page.locator("#login-message")).to_have_text(
        "Mot de passe modifié. Pour votre sécurité, toutes les sessions "
        "administrateur ont été fermées. Reconnectez-vous avec votre nouveau mot de passe."
    )

    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#login-message")).to_have_text(
        "Identifiant ou mot de passe invalide."
    )
    expect(page.locator("#login-view")).to_be_visible()

    page.fill("#password", new_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.get_by_role("heading", name="Notifications de sécurité", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Configuration SMTP", exact=True)).to_be_visible()


def test_account_security_summary_and_global_session_revoke(browser, fortios_server):
    first = browser.new_page()
    second = browser.new_page()
    login_cert_admin(first, fortios_server)
    login_cert_admin(second, fortios_server)

    first.reload()
    first.click("#account-tab")
    expect(first.get_by_role("heading", name="Compte & sécurité", exact=True)).to_be_visible()
    expect(first.locator("#account-username")).to_have_text("admin")
    expect(first.locator("#account-recovery-email")).to_have_text("Non configurée")
    expect(first.locator("#account-session-count")).to_have_text("2 sessions actives")
    expect(first.locator("#account-password-changed-at")).not_to_have_text("—")

    first.click("#revoke-all-sessions-button")
    expect(first.locator("#login-view")).to_be_visible()
    second.reload()
    expect(second.locator("#login-view")).to_be_visible()


def test_admin_can_set_a_pending_recovery_email_without_smtp(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#account-tab")
    page.click("#change-recovery-email-button")

    expect(page.locator("#recovery-email-form")).to_be_visible()
    page.fill("#recovery-email", "owner@example.test")
    page.click("#save-recovery-email-button")

    expect(page.locator("#account-recovery-email")).to_have_text("o***r@example.test")
    expect(page.locator("#account-recovery-status")).to_have_text("En attente de vérification")
    expect(page.locator("#recovery-email-message")).to_contain_text("SMTP")


def test_forgot_password_view_always_shows_the_generic_result(page, fortios_server):
    page.goto(f"{fortios_server.base_url}/cert/")
    page.click("#forgot-password-button")
    expect(page.locator("#forgot-password-form")).to_be_visible()

    page.fill("#forgot-username", "admin")
    page.click("#send-reset-link-button")

    expect(page.locator("#forgot-password-message")).to_have_text(
        "Si ce compte peut être récupéré, un email sera envoyé."
    )
    expect(page.locator("#login-view")).to_be_visible()


def test_verification_link_promotes_the_pending_recovery_email(page, fortios_server):
    revision = cert_admin.credentials_revision(fortios_server.credentials_path)
    cert_admin.set_recovery_email(
        fortios_server.credentials_path,
        "owner@example.test",
        expected_revision=revision,
    )
    token = cert_admin.issue_verification_token(
        fortios_server.credentials_path,
        expected_revision=revision,
    )

    page.goto(f"{fortios_server.base_url}/cert/verify-email?token={token}")
    expect(page.locator("#email-verification-view")).to_be_visible()
    page.click("#verify-recovery-email-button")
    expect(page.locator("#email-verification-message")).to_have_text(
        "Adresse de récupération vérifiée."
    )

    login_cert_admin(page, fortios_server)
    page.click("#account-tab")
    expect(page.locator("#account-recovery-email")).to_have_text("o***r@example.test")
    expect(page.locator("#account-recovery-status")).to_have_text("Vérifiée ✓")


def test_password_reset_link_rotates_credentials_and_revokes_sessions(browser, fortios_server):
    authenticated_page = browser.new_page()
    reset_page = browser.new_page()
    login_cert_admin(authenticated_page, fortios_server)
    revision = cert_admin.credentials_revision(fortios_server.credentials_path)
    cert_admin.set_recovery_email(
        fortios_server.credentials_path,
        "owner@example.test",
        expected_revision=revision,
    )
    verification_token = cert_admin.issue_verification_token(
        fortios_server.credentials_path,
        expected_revision=revision,
    )
    cert_admin.consume_verification_token(
        fortios_server.credentials_path,
        verification_token,
        expected_revision=revision,
    )
    reset_token = cert_admin.issue_password_reset_token(
        fortios_server.credentials_path,
        expected_revision=revision,
    )
    new_password = secrets.token_urlsafe(24)

    reset_page.goto(f"{fortios_server.base_url}/cert/reset-password?token={reset_token}")
    expect(reset_page.locator("#password-reset-view")).to_be_visible()
    reset_page.fill("#reset-password", new_password)
    reset_page.fill("#reset-password-confirmation", new_password)
    reset_page.click("#reset-password-button")

    expect(reset_page.locator("#login-view")).to_be_visible()
    expect(reset_page.locator("#login-message")).to_contain_text("réinitialisé")
    authenticated_page.reload()
    expect(authenticated_page.locator("#login-view")).to_be_visible()

    reset_page.fill("#username", fortios_server.admin_username)
    reset_page.fill("#password", new_password)
    reset_page.click("#login-button")
    expect(reset_page.locator("#admin-view")).to_be_visible()


# 2. Select product/model/version pair ---------------------------------------------------

def test_select_product_model_version(app_page):
    select_path(app_page, current="6.2.4", target="8.0.0")
    assert app_page.eval_on_selector("#productSelect", "el => el.value") == "fortigate-fortios"
    assert app_page.eval_on_selector("#modelSelect", "el => el.value") == "FGT60F"
    assert app_page.eval_on_selector("#currentSelect", "el => el.value") == "6.2.4"
    assert app_page.eval_on_selector("#targetSelect", "el => el.value") == "8.0.0"
    # Changing a dropdown must not surface a path on its own (no click yet).
    expect(app_page.locator("#result")).not_to_contain_text("Recommended path")


def test_target_versions_only_offer_strict_upgrades_after_source_change(app_page):
    app_page.select_option("#productSelect", "fortigate-fortios")
    app_page.select_option("#modelSelect", "FGT60F")
    app_page.select_option("#currentSelect", "6.2.4")
    target_values = app_page.locator("#targetSelect option").evaluate_all("options => options.map(option => option.value)")
    assert target_values == ["7.0.14", "8.0.0"]

    app_page.select_option("#currentSelect", "7.0.14")
    target_values = app_page.locator("#targetSelect option").evaluate_all("options => options.map(option => option.value)")
    assert target_values == ["8.0.0"]
    assert app_page.locator("#targetSelect").input_value() == "8.0.0"

    app_page.select_option("#currentSelect", "8.0.0")
    expect(app_page.locator("#targetSelect option")).to_have_count(0)
    expect(app_page.locator("#targetSelect")).to_be_disabled()


def test_official_path_api_rejects_downgrade_and_equal_version(page, fortios_server):
    page.goto(f"{fortios_server.base_url}/app/")

    for current, target in (("7.2.10", "7.2.8"), ("7.2.10", "7.2.10")):
        response = page.evaluate(
            """async ({current, target}) => {
                const response = await fetch('/api/official-path', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        product: 'fortigate-fortios',
                        model: 'FGT60F',
                        from: current,
                        to: target,
                    }),
                });
                return {status: response.status, body: await response.json()};
            }""",
            {"current": current, "target": target},
        )
        assert response["status"] == 400
        assert response["body"]["error"] == (
            "La version cible doit être supérieure à la version source. "
            "Upgrade Path ne prend pas en charge les downgrades."
        )


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


def test_edit_precise_hop_preserves_versions_missing_from_current_catalog(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/app/alerte/")
    page.fill("#titleInput", "Historical precise hop")
    page.fill("#descriptionInput", "The old transition must remain unchanged.")
    page.click("#versionModeHopButton")
    page.select_option("#hopFromSelect", "6.2.4")
    page.select_option("#hopToSelect", "7.0.14")
    page.click("#submitButton")
    expect(page.locator("#advisoryList")).to_contain_text("6.2.4 → 7.0.14")

    state = fortios_server.read_state()
    product = next(item for item in state["products"] if item["id"] == "fortigate-fortios")
    for model in product["models"]:
        model["firmwares"] = [
            firmware for firmware in model["firmwares"]
            if firmware["version"] not in {"6.2.4", "7.0.14"}
        ]
    (fortios_server.data_dir / "fortios-data.generated.json").write_text(
        json.dumps(state),
        encoding="utf-8",
    )

    page.reload()
    page.locator("article", has_text="Historical precise hop").get_by_role(
        "button",
        name="Modifier",
    ).click()
    expect(page.locator("#hopFromSelect")).to_have_value("6.2.4")
    expect(page.locator("#hopToSelect")).to_have_value("7.0.14")

    page.fill("#titleInput", "Historical precise hop edited")
    page.click("#submitButton")
    expect(page.locator("#formMessage")).to_have_text("Alerte mise à jour.")

    saved = next(
        item for item in fortios_server.read_state()["advisories"]
        if item["title"] == "Historical precise hop edited"
    )
    assert saved["from"] == "6.2.4"
    assert saved["to"] == "7.0.14"


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


def login_cert_admin(page, fortios_server) -> None:
    page.goto(f"{fortios_server.base_url}/cert/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()


def test_notifications_admin_exposes_grouped_smtp_and_email_appearance(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    for heading in (
        "Alertes CVE",
        "Produits surveillés",
        "Destinataires",
        "Configuration SMTP",
        "Apparence des emails",
        "Test d’envoi",
    ):
        expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()

    expect(page.locator("#smtp-security option")).to_have_count(3)
    assert page.locator("#smtp-security option").evaluate_all(
        "options => options.map(option => option.value)",
    ) == ["starttls", "tls", "none"]
    expect(page.locator("#smtp-advanced-options")).not_to_have_attribute("open", "")
    delete_password = page.locator("#delete-smtp-password-button")
    expect(delete_password).to_have_count(1)
    expect(delete_password).to_be_hidden()
    expect(page.locator("#smtp-password")).to_have_attribute("autocomplete", "new-password")
    expect(page.locator("#smtp-password")).to_have_value("")


def test_email_preview_uses_isolated_document_with_real_computed_styles(page, fortios_server):
    csp_violations: list[str] = []

    def record_console(message) -> None:
        if "Content Security Policy directive" in message.text:
            csp_violations.append(message.text)

    page.on("console", record_console)
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    scenario_buttons = page.locator("[data-preview-scenario]")
    expect(scenario_buttons).to_have_count(3)
    expect(page.locator("#send-preview-email-button")).to_have_text(
        "Envoyer cet aperçu par email"
    )

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications/preview")
    ) as preview_response:
        page.click('[data-preview-scenario="multi-product"]')
    preview = preview_response.value.json()

    expect(page.locator("#email-preview-subject")).to_have_text(preview["subject"])
    expect(page.locator("#email-preview-text")).to_have_text(preview["text"])
    preview_frame = page.locator("#email-preview-frame")
    assert preview_frame.get_attribute("srcdoc") is None
    assert preview_frame.get_attribute("sandbox") == ""
    expect(preview_frame).to_have_attribute("src", preview["renderUrl"])

    frame = page.frame(url=re.compile(r"/api/cert/notifications/preview/render/"))
    assert frame is not None
    computed = frame.evaluate(
        """() => {
          const title = document.querySelector('h1');
          const container = title.parentElement;
          const headings = [...document.querySelectorAll('h2')];
          const critical = headings.find(element => element.textContent.includes('CRITICAL'));
          const high = headings.find(element => element.textContent.includes('HIGH'));
          const criticalBlock = critical.parentElement;
          return {
            maxWidth: getComputedStyle(container).maxWidth,
            fontFamily: getComputedStyle(container).fontFamily,
            padding: getComputedStyle(container).padding,
            criticalColor: getComputedStyle(critical).color,
            highColor: getComputedStyle(high).color,
            separatorStyle: getComputedStyle(criticalBlock).borderTopStyle,
            separatorWidth: getComputedStyle(criticalBlock).borderTopWidth,
          };
        }"""
    )
    assert computed == {
        "maxWidth": "680px",
        "fontFamily": "Arial, sans-serif",
        "padding": "20px",
        "criticalColor": "rgb(180, 35, 24)",
        "highColor": "rgb(181, 71, 8)",
        "separatorStyle": "solid",
        "separatorWidth": "1px",
    }
    isolation = frame.evaluate(
        """() => {
          let parentAccess;
          try {
            parentAccess = window.parent.document.title;
          } catch (error) {
            parentAccess = error.name;
          }
          return {origin: window.origin, parentAccess};
        }"""
    )
    assert isolation == {"origin": "null", "parentAccess": "SecurityError"}
    for expected in (
        "Critical : 1",
        "High     : 2",
        "FortiGate / FortiOS : 2",
        "FortiManager : 1",
        "FortiAnalyzer : 1",
        "FortiClient Windows : 1",
    ):
        expect(page.locator("#email-preview-text")).to_contain_text(expected)
    expect(page.locator("#email-preview-text")).to_contain_text(
        "CRITICAL — CVE-2026-00001"
    )
    assert frame.locator("h2", has_text="CVE-2026-00001").count() == 1
    first_cve_block = frame.locator("h2", has_text="CVE-2026-00001").locator("..")
    expect(first_cve_block).to_contain_text("FortiGate / FortiOS")
    expect(first_cve_block).to_contain_text("FortiManager")
    expect(frame.locator("body")).to_contain_text("FortiUpgrade")
    expect(frame.locator("body")).to_contain_text("3 nouvelles vulnérabilités")
    assert csp_violations == []


def test_email_preview_refresh_applies_live_appearance_and_stays_mobile_safe(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    page.fill("#email-display-name", "FortiUpgrade Mobile SOC")
    page.fill("#email-introduction", "Introduction live.")
    page.fill("#email-signature", "Signature live.")

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications/preview")
    ) as preview_response:
        page.click("#preview-email-button")
    preview = preview_response.value.json()

    expect(page.locator("#email-preview-text")).to_contain_text(
        "FortiUpgrade Mobile SOC"
    )
    expect(page.locator("#email-preview-frame")).to_have_attribute(
        "src", preview["renderUrl"]
    )
    frame = page.frame(url=re.compile(r"/api/cert/notifications/preview/render/"))
    assert frame is not None
    expect(frame.locator("body")).to_contain_text("FortiUpgrade Mobile SOC")
    expect(frame.locator("body")).to_contain_text("Introduction live.")
    expect(frame.locator("body")).to_contain_text("Signature live.")

    page.set_viewport_size({"width": 375, "height": 812})
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    assert page.locator("#email-preview-frame").evaluate(
        "element => element.getBoundingClientRect().width <= element.parentElement.getBoundingClientRect().width"
    )


def test_email_preview_keeps_appearance_html_inert(page, fortios_server):
    dialogs: list[str] = []
    page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    page.fill("#email-display-name", "<script>alert(1)</script>")
    page.fill("#email-introduction", "<img src=x onerror=alert(2)>")
    page.fill("#email-signature", "<svg onload=alert(3)>")

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications/preview")
    ) as preview_response:
        page.click("#preview-email-button")
    preview = preview_response.value.json()
    expect(page.locator("#email-preview-frame")).to_have_attribute(
        "src", preview["renderUrl"]
    )

    frame = page.frame(url=re.compile(r"/api/cert/notifications/preview/render/"))
    assert frame is not None
    expect(frame.locator("body")).to_contain_text("<script>alert(1)</script>")
    expect(frame.locator("body")).to_contain_text("<img src=x onerror=alert(2)>")
    expect(frame.locator("body")).to_contain_text("<svg onload=alert(3)>")
    assert frame.locator("script, img, svg").count() == 0
    assert dialogs == []


def test_email_preview_ignores_stale_responses_after_rapid_scenario_changes(
    page, fortios_server
):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    expect(page.locator("#email-preview-message")).to_have_text(
        "Aperçu généré par le renderer réel."
    )
    page.evaluate(
        """
        originalFetch => {
          window.__previewOriginalFetch = window.fetch.bind(window);
          window.fetch = async (url, options) => {
            if (String(url).endsWith('/api/cert/notifications/preview')) {
              const scenario = JSON.parse(options.body).scenario;
              if (scenario === 'multiple') {
                await new Promise(resolve => setTimeout(resolve, 250));
              }
            }
            return window.__previewOriginalFetch(url, options);
          };
        }
        """,
        None,
    )

    page.evaluate(
        """
        () => {
          document.querySelector('[data-preview-scenario="multiple"]').click();
          document.querySelector('[data-preview-scenario="multi-product"]').click();
        }
        """
    )
    page.wait_for_timeout(500)

    expect(page.locator('[data-preview-scenario="multi-product"]')).to_have_attribute(
        "aria-pressed", "true"
    )
    expect(page.locator("#email-preview-text")).to_contain_text("FortiManager : 1")
    expect(page.locator("#email-preview-text")).to_contain_text(
        "FortiClient Windows : 1"
    )


def test_smtp_admin_persists_replaces_and_deletes_secret_without_returning_it(
    page, fortios_server
):
    first_secret = secrets.token_urlsafe(24)
    second_secret = secrets.token_urlsafe(24)
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    page.fill("#smtp-host", "smtp.e2e.example")
    page.fill("#smtp-port", "587")
    page.select_option("#smtp-security", "starttls")
    page.fill("#smtp-username", "smtp-e2e-user")
    page.click("#replace-smtp-password-button")
    page.fill("#smtp-password", first_secret)
    page.fill("#smtp-from-address", "fortiupgrade-e2e@example.test")
    page.fill("#smtp-app-url", "https://fortiupgrade.e2e.example/app/")
    page.click("#smtp-advanced-options summary")
    page.fill("#smtp-timeout", "12")
    page.fill("#email-display-name", "FortiUpgrade E2E")
    page.fill("#email-introduction", "Introduction E2E")
    page.fill("#email-signature", "Signature E2E")

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp")
        and response.request.method == "POST"
    ) as saved_response:
        page.click("#save-smtp-button")
    saved_payload = saved_response.value.json()
    assert saved_payload["smtp"]["passwordConfigured"] is True
    assert first_secret not in json.dumps(saved_payload)
    expect(page.locator("#smtp-message")).to_have_text(
        "Configuration email enregistrée."
    )
    expect(page.locator("#smtp-password-status")).to_have_text(
        "Mot de passe configuré"
    )
    expect(page.locator("#smtp-password")).to_have_value("")
    expect(page.locator("#delete-smtp-password-button")).to_be_visible()

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp")
        and response.request.method == "GET"
    ) as loaded_response:
        page.reload()
    loaded_payload = loaded_response.value.json()
    assert loaded_payload["smtp"]["passwordConfigured"] is True
    assert first_secret not in json.dumps(loaded_payload)
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#smtp-host")).to_have_value("smtp.e2e.example")
    expect(page.locator("#email-display-name")).to_have_value("FortiUpgrade E2E")
    expect(page.locator("#smtp-password")).to_have_value("")

    page.fill("#smtp-host", "smtp-preserved.e2e.example")
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp")
        and response.request.method == "POST"
    ) as preserved_response:
        page.click("#save-smtp-button")
    preserved_payload = preserved_response.value.json()
    assert preserved_payload["smtp"]["passwordConfigured"] is True
    assert first_secret not in json.dumps(preserved_payload)

    page.click("#replace-smtp-password-button")
    page.fill("#smtp-password", second_secret)
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp")
        and response.request.method == "POST"
    ) as replaced_response:
        page.click("#save-smtp-button")
    replaced_payload = replaced_response.value.json()
    assert replaced_payload["smtp"]["passwordConfigured"] is True
    assert second_secret not in json.dumps(replaced_payload)
    expect(page.locator("#smtp-password")).to_have_value("")

    page.once("dialog", lambda dialog: dialog.accept())
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp/password")
        and response.request.method == "DELETE"
    ) as deleted_response:
        page.click("#delete-smtp-password-button")
    deleted_payload = deleted_response.value.json()
    assert deleted_payload["smtp"]["passwordConfigured"] is False
    assert second_secret not in json.dumps(deleted_payload)
    expect(page.locator("#smtp-message")).to_have_text(
        "Mot de passe SMTP supprimé."
    )
    expect(page.locator("#smtp-password-status")).to_have_text("Non configuré")
    expect(page.locator("#delete-smtp-password-button")).to_be_hidden()


def test_smtp_admin_is_labelled_and_has_no_horizontal_overflow(page, fortios_server):
    page.set_viewport_size({"width": 1440, "height": 1000})
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    assert page.locator("#smtp-form input, #smtp-form select, #smtp-form textarea").evaluate_all(
        "elements => elements.every(element => element.labels && element.labels.length > 0)"
    )
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    panel_widths = page.locator(".notifications-grid > .panel, .notifications-grid > form").evaluate_all(
        "elements => elements.map(element => element.getBoundingClientRect().width)"
    )
    assert panel_widths[1] >= panel_widths[0] * 0.75

    page.set_viewport_size({"width": 375, "height": 812})
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    expect(page.locator("#smtp-host")).to_be_visible()
    expect(page.locator("#replace-smtp-password-button")).to_be_visible()
    expect(page.locator("#save-smtp-button")).to_be_visible()


def test_smtp_test_button_uses_backend_operational_state(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    page.evaluate(
        """() => renderSmtpSettings({smtp: {
          host: 'smtp.example.com', port: 0, security: 'starttls',
          allowInsecure: false, username: '', from: 'sender@example.com',
          appUrl: 'https://fortiupgrade.example/app/', timeout: 10,
          emailAppearance: {displayName: 'FortiUpgrade', introduction: '', signature: ''},
          source: 'environment', state: 'incomplete', passwordConfigured: false
        }})"""
    )

    expect(page.locator("#smtp-status-label")).to_have_text(
        "Configuration incomplète"
    )
    expect(page.locator("#test-email-button")).to_be_disabled()
