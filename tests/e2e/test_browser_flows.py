"""End-to-end browser coverage for FortiOS Upgrade Intelligence, against a fully isolated
instance of scripts/fortios_server.py (see conftest.py) — no real data, no real network call.
"""

from __future__ import annotations

import json
import re
import secrets

from playwright.sync_api import expect

from scripts import cert_admin, fortios_notify


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


def test_root_application_loads_without_asset_error_or_console_error(page, fortios_server):
    """The application is served from "/": same page, same assets, no error introduced by the move."""
    asset_failures: list[tuple[int, str]] = []
    console_errors: list[str] = []

    def record_response(response):
        path = response.url.split(f"{fortios_server.base_url}", 1)[-1].split("?", 1)[0]
        if response.status >= 400 and (path.endswith((".css", ".js")) or path in ("/", "/alerte/", "/forticlient/")):
            asset_failures.append((response.status, path))

    page.on("response", record_response)
    page.on("pageerror", lambda error: console_errors.append(str(error)))

    page.goto(f"{fortios_server.base_url}/")
    page.wait_for_selector("#productSelect option", state="attached")
    expect(page.locator("#dataStatus")).to_contain_text("JSON généré chargé")

    assert asset_failures == []
    assert console_errors == []

    # The sub-pages moved with it, and their relative assets still resolve.
    page.goto(f"{fortios_server.base_url}/alerte/")
    expect(page.locator("#titleInput")).to_be_visible()
    page.goto(f"{fortios_server.base_url}/forticlient/")
    expect(page.locator("#emsVersionSelect")).to_be_visible()

    assert asset_failures == []
    assert console_errors == []


def test_legacy_urls_redirect_to_the_canonical_ones_in_one_hop(page, fortios_server):
    """Every legacy URL answers 302 and lands on the canonical URL: one hop, no loop, and "/" and
    "/admin/" are never redirects themselves."""
    redirects: list[tuple[int, str, str]] = []

    def record_redirect(response):
        if 300 <= response.status < 400:
            redirects.append((response.status, response.url, response.headers.get("location", "")))

    page.on("response", record_redirect)
    base_url = fortios_server.base_url
    cases = {
        "/app": "/",
        "/app/": "/",
        "/app/index.html": "/index.html",
        "/app/alerte/": "/alerte/",
        "/app/forticlient/": "/forticlient/",
        "/app/cert": "/admin/",
        "/app/cert/": "/admin/",
        "/cert": "/admin/",
        "/cert/": "/admin/",
    }
    for path, expected in cases.items():
        redirects.clear()
        page.goto(f"{base_url}{path}")
        assert page.url == f"{base_url}{expected}", (path, page.url)
        assert len(redirects) == 1, (path, redirects)
        assert redirects[0][0] == 302, (path, redirects)

    # Canonical URLs themselves never redirect.
    for path in ("/", "/admin/", "/alerte/"):
        redirects.clear()
        page.goto(f"{base_url}{path}")
        assert page.url == f"{base_url}{path}", (path, page.url)
        assert redirects == [], (path, redirects)


def test_legacy_recovery_links_keep_their_token(page, fortios_server):
    """An already-delivered recovery email points at /cert/...?token=... and must still work: the
    302 preserves the query string, and the SPA then posts the very same token under /admin/.

    The SPA deliberately strips the token from the visible URL as soon as it has read it
    (history.replaceState), so the proof is the request body, not the address bar.
    """
    token = "t" * 43
    page.goto(f"{fortios_server.base_url}/cert/verify-email?token={token}")
    assert page.url == f"{fortios_server.base_url}/admin/verify-email", page.url
    expect(page.locator("#email-verification-view")).to_be_visible()
    expect(page.locator("#verify-recovery-email-button")).to_be_enabled()

    with page.expect_request(lambda request: request.url.endswith("/api/cert/verify-email")) as captured:
        page.click("#verify-recovery-email-button")
    assert json.loads(captured.value.post_data or "{}") == {"token": token}

    reset_token = "r" * 43
    page.goto(f"{fortios_server.base_url}/cert/reset-password?token={reset_token}")
    assert page.url == f"{fortios_server.base_url}/admin/reset-password", page.url
    expect(page.locator("#password-reset-view")).to_be_visible()
    expect(page.locator("#reset-password-button")).to_be_enabled()


def test_certificate_first_run_creates_the_admin_account(page, fortios_server):
    fortios_server.credentials_path.unlink()
    page.goto(f"{fortios_server.base_url}/admin/")

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


def test_account_tab_responsive_layout_keeps_the_actions_inside_the_card(page, fortios_server):
    """The account card is a real responsive layout (presentation only, no functional change).

    - desktop: the card uses the admin shell width and the summary is a 2 columns x 2 rows grid;
    - the three account actions always stay inside the panel, in spec order, the destructive one
      last and still styled as the danger button;
    - mobile: a single column, full-width buttons, and no horizontal overflow anywhere.
    """
    login_cert_admin(page, fortios_server)
    page.click("#account-tab")
    expect(page.get_by_role("heading", name="Compte & sécurité", exact=True)).to_be_visible()

    def geometry():
        return page.evaluate(
            """() => {
              const rect = (el) => {
                const r = el.getBoundingClientRect();
                return {
                  left: Math.round(r.left), right: Math.round(r.right),
                  top: Math.round(r.top), bottom: Math.round(r.bottom),
                  width: Math.round(r.width),
                };
              };
              const panel = document.querySelector('.account-panel');
              return {
                panel: rect(panel),
                buttons: Array.from(document.querySelectorAll('.account-primary-actions .btn')).map((btn) => ({
                  id: btn.id,
                  danger: btn.classList.contains('danger'),
                  clipped: btn.scrollWidth > btn.clientWidth + 1,
                  ...rect(btn),
                })),
                cells: Array.from(document.querySelectorAll('.account-summary > div')).map(rect),
                columns: getComputedStyle(document.querySelector('.account-summary'))
                  .gridTemplateColumns.split(' ').filter(Boolean).length,
                overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
              };
            }"""
        )

    def assert_actions_inside_the_card(state, label):
        assert [button["id"] for button in state["buttons"]] == [
            "change-password-button",
            "change-recovery-email-button",
            "revoke-all-sessions-button",
        ], label
        assert state["buttons"][-1]["danger"] is True, label
        for button in state["buttons"]:
            assert state["panel"]["left"] - 1 <= button["left"], (label, button)
            assert button["right"] <= state["panel"]["right"] + 1, (label, button)
            assert button["clipped"] is False, (label, button)
        assert state["overflowX"] <= 0, label

    # Desktop: the card fills the admin shell width — never again the former 620px frame — and the
    # summary keeps its 2 x 2 layout with roomy cells.
    for width, height in ((1920, 1080), (1440, 900)):
        page.set_viewport_size({"width": width, "height": height})
        desktop = geometry()
        assert_actions_inside_the_card(desktop, f"{width}x{height}")
        assert desktop["panel"]["width"] >= 900, desktop["panel"]
        assert desktop["columns"] == 2, desktop["columns"]
        first, second, third, fourth = desktop["cells"]
        assert abs(first["top"] - second["top"]) <= 1
        assert abs(third["top"] - fourth["top"]) <= 1
        assert third["top"] >= first["bottom"] - 1
        assert second["left"] >= first["right"] - 1
        assert fourth["left"] >= third["right"] - 1
        # "Dernière modification : 10 septembre 2026" / "1 session active" stay readable: no cell is
        # compressed into an absurd width.
        assert min(cell["width"] for cell in desktop["cells"]) >= 320, desktop["cells"]
        # The three actions share one row at these widths (wrapping stays allowed, it is just not
        # needed here).
        assert abs(desktop["buttons"][0]["top"] - desktop["buttons"][2]["top"]) <= 1

    # 1024x800: still two columns, still fully contained.
    page.set_viewport_size({"width": 1024, "height": 800})
    tablet = geometry()
    assert_actions_inside_the_card(tablet, "1024x800")
    assert tablet["columns"] == 2, tablet["columns"]

    # Mobile: one column, every action a full-width row, no overflow.
    page.set_viewport_size({"width": 390, "height": 844})
    mobile = geometry()
    assert_actions_inside_the_card(mobile, "390x844")
    assert mobile["columns"] == 1, mobile["columns"]
    first, second, third, fourth = mobile["cells"]
    assert first["top"] < second["top"] < third["top"] < fourth["top"]
    assert abs(first["left"] - second["left"]) <= 1
    buttons = mobile["buttons"]
    assert buttons[0]["top"] < buttons[1]["top"] < buttons[2]["top"]
    assert abs(buttons[0]["width"] - buttons[2]["width"]) <= 1
    assert buttons[0]["width"] >= mobile["panel"]["width"] - 44


def test_forgot_password_view_always_shows_the_generic_result(page, fortios_server):
    page.goto(f"{fortios_server.base_url}/admin/")
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

    page.goto(f"{fortios_server.base_url}/admin/verify-email?token={token}")
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

    reset_page.goto(f"{fortios_server.base_url}/admin/reset-password?token={reset_token}")
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
    page.goto(f"{fortios_server.base_url}/")

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
    page.goto(f"{fortios_server.base_url}/alerte/")
    page.fill("#titleInput", "E2E test advisory")
    page.fill("#descriptionInput", "Created by the E2E suite.")
    page.locator("#versionList").get_by_label("6.2.4").check()
    page.click("#submitButton")

    expect(page.locator("#advisoryList")).to_contain_text("E2E test advisory")


# 8. Edit an advisory ---------------------------------------------------------------------

def test_edit_advisory(page, fortios_server):
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{fortios_server.base_url}/alerte/")
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
    page.goto(f"{fortios_server.base_url}/alerte/")
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
    page.goto(f"{fortios_server.base_url}/alerte/")
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
    page.goto(f"{fortios_server.base_url}/alerte/")
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
    page.goto(f"{fortios_server.base_url}/forticlient/")
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
    page.goto(f"{fortios_server.base_url}/admin/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()


def test_notifications_admin_exposes_grouped_smtp_and_email_appearance(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    for heading in (
        "Alertes CVE",
        "Produits surveillés pour les CVE",
        "Alertes nouvelles versions",
        "Destinataires CVE",
        "Configuration SMTP",
        "Apparence des emails",
        "Test d’envoi",
    ):
        expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()

    # Two independent category switches, plus the opt-in dedicated release list.
    expect(page.locator("#notifications-enabled")).to_have_count(1)
    expect(page.locator("#release-notifications-enabled")).to_have_count(1)
    expect(page.locator("#release-recipients-shared")).to_be_checked()
    expect(page.locator("#release-recipients-block")).to_be_hidden()
    expect(
        page.get_by_text(
            "Releases actuellement prises en charge : FortiGate / FortiOS, FortiManager et "
            "FortiAnalyzer."
        )
    ).to_be_visible()

    expect(page.locator("#smtp-security option")).to_have_count(3)
    assert page.locator("#smtp-security option").evaluate_all(
        "options => options.map(option => option.value)",
    ) == ["starttls", "tls", "none"]
    expect(page.locator("#smtp-advanced-options")).not_to_have_attribute("open", "")
    expect(page.locator("#smtp-host")).not_to_be_disabled()
    expect(page.locator("#smtp-password")).to_have_count(1)
    expect(page.locator("#smtp-password")).not_to_be_disabled()
    expect(page.locator("#replace-smtp-password-button")).to_have_count(0)
    expect(page.locator("#delete-smtp-password-button")).to_have_count(0)


def test_cve_severity_threshold_offers_every_level_and_persists(page, fortios_server):
    """The CVE threshold is a real select: all published levels, persisted across a reload."""
    fortios_notify.save_notification_settings(
        fortios_server.data_dir / "notification-settings.json",
        {
            "enabled": True,
            "minimumSeverity": "high",
            "products": {
                "fortigate-fortios": True,
                "fortimanager": True,
                "fortianalyzer": True,
                "forticlient-ems": True,
                "forticlient": {"windows": True, "macos": True, "linux": True},
            },
            "recipients": ["soc@example.com"],
        },
    )
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    severity = page.locator("#minimum-severity")
    # Every level Fortinet genuinely publishes, most severe first, and nothing invented.
    options = page.locator("#minimum-severity option")
    assert options.evaluate_all("options => options.map(option => option.value)") == [
        "critical",
        "high",
        "medium",
        "low",
    ]
    assert options.evaluate_all("options => options.map(option => option.textContent)") == [
        "Critical",
        "High",
        "Medium",
        "Low",
    ]
    # The historical default is preselected, so an existing configuration cannot drift.
    expect(severity).to_have_value("high")

    severity.select_option("low")
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications")
    ) as saved:
        page.click("#save-notifications-button")
    assert saved.value.json()["settings"]["minimumSeverity"] == "low"
    expect(page.locator("#notifications-message")).to_contain_text("Configuration enregistrée.")

    # Reload: the operator gets back the threshold they saved.
    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#minimum-severity")).to_have_value("low")


def container_state(*findings, scanned_at: str | None = None) -> dict:
    """A notification state holding an ingested Trivy report, as the ingestion would leave it."""
    scanned_at = scanned_at or fortios_notify.utc_now()
    state = fortios_notify._empty_notify_state()
    state["containerSecurityState"] = {
        "findings": {
            f"trivy|cve|{cve}|{package}": {
                "cve": cve,
                "package": package,
                "severity": severity,
                "installedVersion": "1.0-1",
                "fixedVersion": "1.0-2",
                "firstSeenAt": scanned_at,
                "lastSeenAt": scanned_at,
                "resolvedAt": "",
            }
            for (cve, package, severity) in findings
        },
        "lastScanAt": scanned_at,
        "image": "fortios-upgrade-intelligence:ci-scan",
        "commit": "05926bb47750208331d9dda00513fd399234736d",
        "ingestedAt": scanned_at,
        "reportError": "",
    }
    return state


def test_container_security_is_its_own_scope_and_persists(page, fortios_server):
    """Its own switch, its own threshold, its own recipients — nothing shared with the CVE list."""
    fortios_notify.save_notification_settings(
        fortios_server.data_dir / "notification-settings.json",
        {
            "enabled": True,
            "minimumSeverity": "high",
            "products": {
                "fortigate-fortios": True,
                "fortimanager": True,
                "fortianalyzer": True,
                "forticlient-ems": True,
                "forticlient": {"windows": True, "macos": True, "linux": True},
            },
            "recipients": ["soc@example.com"],
        },
    )
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    expect(page.locator("#container-security-form")).to_be_visible()
    severity = page.locator("#container-minimum-severity")
    assert severity.evaluate(
        "select => [...select.options].map(option => option.value)"
    ) == ["critical", "high"]
    expect(severity).to_have_value("high")
    expect(page.locator("#container-security-enabled")).not_to_be_checked()

    page.check("#container-security-enabled")
    page.fill("#container-recipient-list input[type=email]", "image@example.com")
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/container-security")
    ) as saved:
        page.click("#save-container-security-button")
    settings = saved.value.json()["settings"]
    assert settings == {
        "enabled": True,
        "minimumSeverity": "high",
        "recipients": ["image@example.com"],
    }
    expect(page.locator("#container-security-message")).to_contain_text("Configuration enregistrée.")

    # The CVE list is untouched: the two documents are independent.
    expect(page.locator("#recipient-list input[type=email]")).to_have_value("soc@example.com")
    assert len(page.locator("#recipient-list input[type=email]").all()) == 1

    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#container-security-enabled")).to_be_checked()
    expect(page.locator("#container-recipient-list input[type=email]")).to_have_value(
        "image@example.com"
    )


def test_container_security_refuses_to_enable_without_a_recipient(page, fortios_server):
    """A green switch that would send nothing anywhere is refused, and nothing is persisted.

    Two guards, both exercised: the browser's own `required` on the address field, then the panel's
    explicit refusal once the row is gone — the state a configuration would really be in.
    """
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    page.check("#container-security-enabled")

    # An empty address is caught by the browser before any request leaves the page.
    page.fill("#container-recipient-list input[type=email]", "")
    assert page.locator("#container-recipient-list input[type=email]").evaluate(
        "input => input.checkValidity()"
    ) is False
    page.click("#save-container-security-button")
    assert not (fortios_server.data_dir / "container-security-settings.json").exists()

    # With no row at all, the panel refuses explicitly instead of saving a switch that sends nothing.
    page.click("#container-recipient-list .recipient-remove")
    page.click("#save-container-security-button")
    expect(page.locator("#container-security-message")).to_contain_text("au moins un destinataire")
    expect(page.locator("#container-security-enabled")).to_be_checked()
    assert not (fortios_server.data_dir / "container-security-settings.json").exists()


def test_container_security_report_state_never_reads_as_zero(page, fortios_server):
    """"Aucun rapport" and "0 vulnérabilité" must be impossible to confuse."""
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    expect(page.locator("#container-report-state")).to_contain_text("Aucun rapport")
    details = page.locator("#container-report-details")
    expect(details).to_contain_text("—")
    expect(details).not_to_contain_text("Total actives0")

    fortios_notify.write_json(
        fortios_server.data_dir / "fortios-notify-history.json",
        container_state(
            ("CVE-2026-13221", "perl-base", "critical"),
            ("CVE-2026-41992", "gzip", "high"),
            ("CVE-2026-11822", "libsqlite3-0", "high"),
        ),
    )
    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#container-report-state")).to_contain_text("Rapport à jour")
    details = page.locator("#container-report-details")
    expect(details).to_contain_text("Critical")
    expect(details).to_contain_text("Total actives")
    expect(details).to_contain_text("3")
    # The commit is shown shortened, enough to identify the scanned revision without wrapping.
    expect(details).to_contain_text("05926bb47750")

    # An old report is reported as stale rather than silently trusted.
    fortios_notify.write_json(
        fortios_server.data_dir / "fortios-notify-history.json",
        container_state(("CVE-2026-13221", "perl-base", "critical"), scanned_at="2026-01-01T00:00:00Z"),
    )
    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#container-report-state")).to_contain_text("Rapport obsolète")


def test_release_recipients_can_be_detached_from_the_cve_list(page, fortios_server):
    """The dedicated release list is opt-in, validated, persisted and reflected in the preview."""
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    shared = page.locator("#release-recipients-shared")
    block = page.locator("#release-recipients-block")
    cve_rows = page.locator("#recipient-list input[type=email]")
    release_rows = page.locator("#release-recipient-list input[type=email]")

    # Default: shared, so no second list is displayed at all.
    expect(shared).to_be_checked()
    expect(block).to_be_hidden()
    expect(page.get_by_role("heading", name="Destinataires CVE", exact=True)).to_be_visible()
    expect(page.locator("#preview-recipients-hint")).to_contain_text("aucun destinataire")

    cve_rows.first.fill("support@sns-security.fr")

    # Detaching reveals the dedicated list and seeds one empty row.
    shared.uncheck()
    expect(block).to_be_visible()
    expect(
        page.get_by_role("heading", name="Destinataires nouvelles versions", exact=True)
    ).to_be_visible()
    expect(release_rows).to_have_count(1)

    # An empty dedicated list is refused explicitly: removing every row must never save a
    # configuration that would deliver releases nowhere.
    page.locator("#release-recipient-list .recipient-remove").first.click()
    expect(release_rows).to_have_count(0)
    page.click("#save-notifications-button")
    expect(page.locator("#notifications-message")).to_contain_text("au moins un destinataire")
    # The preview hint still describes the CVE scenario currently selected.
    expect(page.locator("#preview-recipients-hint")).to_contain_text("support@sns-security.fr")
    page.click("#add-release-recipient-button")
    expect(release_rows).to_have_count(1)
    release_rows.first.fill("firmware@sns-security.fr")
    # The hint follows the selected scenario: release previews announce the release list,
    # CVE previews the CVE list.
    page.click('[data-preview-scenario="release"]')
    expect(page.locator("#preview-recipients-hint")).to_contain_text("firmware@sns-security.fr")
    page.click('[data-preview-scenario="single"]')
    expect(page.locator("#preview-recipients-hint")).to_contain_text("support@sns-security.fr")

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications")
    ) as saved:
        page.click("#save-notifications-button")
    payload = saved.value.json()["settings"]
    assert payload["releaseRecipientsShared"] is False
    assert payload["releaseRecipients"] == ["firmware@sns-security.fr"]
    assert payload["recipients"] == ["support@sns-security.fr"]

    # Reload: both lists and the detached switch persist.
    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#release-recipients-shared")).not_to_be_checked()
    expect(page.locator("#release-recipients-block")).to_be_visible()
    expect(page.locator("#release-recipient-list input[type=email]").first).to_have_value(
        "firmware@sns-security.fr"
    )
    expect(page.locator("#recipient-list input[type=email]").first).to_have_value(
        "support@sns-security.fr"
    )

    # Re-sharing hides the block again while keeping the dedicated list stored.
    page.locator("#release-recipients-shared").check()
    expect(page.locator("#release-recipients-block")).to_be_hidden()
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications")
    ) as reshared:
        page.click("#save-notifications-button")
    reshared_payload = reshared.value.json()["settings"]
    assert reshared_payload["releaseRecipientsShared"] is True
    assert reshared_payload["releaseRecipients"] == ["firmware@sns-security.fr"]


def test_email_preview_uses_isolated_document_with_real_computed_styles(page, fortios_server):
    csp_violations: list[str] = []

    def record_console(message) -> None:
        if "Content Security Policy directive" in message.text:
            csp_violations.append(message.text)

    page.on("console", record_console)
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    scenario_buttons = page.locator("[data-preview-scenario]")
    expect(scenario_buttons).to_have_count(5)
    assert scenario_buttons.evaluate_all(
        "buttons => buttons.map(button => button.dataset.previewScenario)",
    ) == ["single", "multiple", "multi-product", "release", "release-multi"]
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
    # The SNS renderer is a table-based email: no h1/h2 anchors. The intent of this test is
    # unchanged -- the isolated preview document must really apply the renderer's CSS (font
    # stack, 680px container, hero typography, severity colors, block borders) rather than
    # showing unstyled markup.
    computed = frame.evaluate(
        """() => {
          const container = [...document.querySelectorAll('table')].find(
            table => getComputedStyle(table).maxWidth === '680px'
          );
          const title = [...document.querySelectorAll('div')].find(
            element => element.children.length === 0
              && element.textContent.includes('nouvelles vulnérabilités')
          );
          const counters = [...document.querySelectorAll('div')].filter(
            element => ['CRITICAL', 'HIGH'].includes(element.textContent.trim())
          );
          const criticalLabel = counters.find(element => element.textContent.trim() === 'CRITICAL');
          const highLabel = counters.find(element => element.textContent.trim() === 'HIGH');
          const cveCells = [...document.querySelectorAll('td')].filter(
            cell => cell.textContent.includes('CVE-2026-00001')
          );
          const cveBlock = cveCells[cveCells.length - 1].closest('table');
          return {
            maxWidth: getComputedStyle(container).maxWidth,
            fontFamily: getComputedStyle(container).fontFamily,
            containerBackground: getComputedStyle(container).backgroundColor,
            titleFontSize: getComputedStyle(title).fontSize,
            titleColor: getComputedStyle(title).color,
            criticalColor: getComputedStyle(criticalLabel.parentElement.querySelector('div')).color,
            highColor: getComputedStyle(highLabel.parentElement.querySelector('div')).color,
            separatorStyle: getComputedStyle(cveBlock).borderTopStyle,
            separatorWidth: getComputedStyle(cveBlock).borderTopWidth,
          };
        }"""
    )
    assert computed == {
        "maxWidth": "680px",
        "fontFamily": "Arial, Helvetica, sans-serif",
        "containerBackground": "rgb(255, 255, 255)",
        "titleFontSize": "26px",
        "titleColor": "rgb(255, 255, 255)",
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
    assert frame.locator("h2", has_text="CVE-2026-00001").count() == 0
    # Each CVE keeps its own block, carrying the products it affects (never a merged list).
    block_text = frame.evaluate(
        """(cveId) => {
          const cells = [...document.querySelectorAll('td')].filter(
            cell => cell.textContent.includes(cveId)
          );
          return cells[cells.length - 1].closest('table').textContent;
        }""",
        "CVE-2026-00001",
    )
    assert block_text.count("CVE-2026-00001") == 1
    assert "FortiGate / FortiOS" in block_text
    assert "FortiManager" in block_text
    assert "CVE-2026-00002" not in block_text
    expect(frame.locator("body")).to_contain_text("FortiUpgrade")
    expect(frame.locator("body")).to_contain_text("3 nouvelles vulnérabilités")
    # The products block states that each figure is a number of CVEs per product (not a share of
    # the total): subtitle + explicit unit, "CVE" invariant in French.
    expect(frame.locator("body")).to_contain_text("PRODUITS CONCERNÉS")
    expect(frame.locator("body")).to_contain_text("Nombre de CVE par produit")
    expect(frame.locator("body")).to_contain_text("FortiGate / FortiOS")
    expect(frame.locator("body")).to_contain_text("2 CVE")
    assert frame.evaluate("document.body.innerText.includes('CVEs')") is False
    # The renderer's own assets are inlined as data: URIs (img-src data:), never fetched.
    assert frame.evaluate(
        "[...document.images].every(image => image.src.startsWith('data:image/'))"
    )

    # The release scenario goes through the same production renderer in the same isolated
    # document: SNS identity, one card per release, and none of the CVE business components.
    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/notifications/preview")
    ) as release_response:
        page.click('[data-preview-scenario="release"]')
    release_preview = release_response.value.json()

    expect(page.locator("#email-preview-subject")).to_have_text(release_preview["subject"])
    expect(page.locator("#email-preview-subject")).to_contain_text("Nouvelle version")
    expect(page.locator("#email-preview-text")).to_contain_text("FortiGate / FortiOS")
    expect(page.locator("#email-preview-text")).to_contain_text("8.0.1")
    expect(page.locator("#email-preview-frame")).to_have_attribute(
        "src", release_preview["renderUrl"]
    )
    # frame_locator follows the iframe's current document (auto-waiting) instead of matching a
    # frame URL that is already one navigation behind.
    release_frame = page.frame_locator("#email-preview-frame")
    expect(release_frame.locator("body")).to_contain_text(
        "FortiUpgrade a détecté une nouvelle version Fortinet disponible au téléchargement."
    )
    release_rendered = release_frame.locator("body").evaluate(
        """(body) => {
          const tables = [...body.querySelectorAll('table')];
          const hero = tables.find(
            table => getComputedStyle(table).backgroundColor === 'rgb(11, 11, 13)'
          );
          const card = [...tables].reverse().find(
            table => table.textContent.includes('NOUVELLE VERSION')
          );
          return {
            heroBackground: getComputedStyle(hero).backgroundColor,
            cardBorderWidth: getComputedStyle(card).borderTopWidth,
            imagesInlined: [...body.querySelectorAll('img')].every(
              image => image.src.startsWith('data:image/')
            ),
            text: body.innerText,
          };
        }"""
    )
    assert release_rendered["heroBackground"] == "rgb(11, 11, 13)"
    assert release_rendered["cardBorderWidth"] == "1px"
    assert release_rendered["imagesInlined"] is True
    assert (
        "FortiUpgrade a détecté une nouvelle version Fortinet disponible au téléchargement."
        in release_rendered["text"]
    )
    assert "FortiGate / FortiOS" in release_rendered["text"]
    assert "NOUVELLE VERSION" in release_rendered["text"]
    assert "Détectée le" in release_rendered["text"]
    assert "OUVRIR FORTIUPGRADE" in release_rendered["text"]
    assert "ÉQUIPE SUPPORT" in release_rendered["text"]
    # No CVE component leaked into the release email.
    assert "CVSS" not in release_rendered["text"]
    assert "vulnérabilit" not in release_rendered["text"]
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
    # Appearance text is escaped: it must create no script/svg, no event handler and no
    # attacker-controlled image. The only <img> allowed is the renderer's own inlined asset.
    assert frame.locator("script, svg").count() == 0
    assert frame.evaluate(
        "document.querySelectorAll('[onerror],[onload],[onclick]').length"
    ) == 0
    assert frame.evaluate(
        "[...document.images].every(image => image.src.startsWith('data:image/'))"
    )
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


def test_smtp_admin_edits_configuration_and_appearance(page, fortios_server):
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")
    for field in ("host", "port", "security", "username", "from-address", "app-url", "timeout"):
        expect(page.locator(f"#smtp-{field}")).not_to_be_disabled()
    expect(page.locator("#smtp-password")).to_have_count(1)
    expect(page.locator("#smtp-password")).not_to_be_disabled()
    page.fill("#smtp-host", "smtp.gui.example")
    page.fill("#smtp-port", "2525")
    page.select_option("#smtp-security", "starttls")
    page.fill("#smtp-username", "gui-user")
    page.fill("#smtp-from-address", "gui@example.invalid")
    page.fill("#smtp-app-url", f"{fortios_server.base_url}/")
    page.locator("#smtp-advanced-options summary").click()
    page.fill("#smtp-timeout", "18")
    page.fill("#email-display-name", "FortiUpgrade E2E")
    page.fill("#email-introduction", "Introduction E2E")
    page.fill("#release-email-introduction", "Introduction release E2E")
    page.fill("#email-signature", "Signature E2E")

    with page.expect_response(
        lambda response: response.url.endswith("/api/cert/smtp")
        and response.request.method == "POST"
    ) as saved_response:
        page.click("#save-smtp-button")
    saved_payload = saved_response.value.json()
    assert saved_payload["smtp"]["passwordConfigured"] is False
    assert set(saved_response.value.request.post_data_json) == {
        "transport", "microsoft365", "emailAppearance", "smtp"
    }
    assert "password" not in json.dumps(saved_response.value.request.post_data_json).lower()
    expect(page.locator("#smtp-message")).to_have_text(
        "Configuration email enregistrée."
    )
    assert not (fortios_server.data_dir / "smtp-password").exists()
    page.reload()
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#smtp-host")).to_have_value("smtp.gui.example")
    expect(page.locator("#smtp-port")).to_have_value("2525")
    expect(page.locator("#smtp-username")).to_have_value("gui-user")
    expect(page.locator("#smtp-from-address")).to_have_value("gui@example.invalid")
    expect(page.locator("#smtp-app-url")).to_have_value(f"{fortios_server.base_url}/")
    expect(page.locator("#smtp-timeout")).to_have_value("18")
    expect(page.locator("#email-display-name")).to_have_value("FortiUpgrade E2E")
    expect(page.locator("#email-introduction")).to_have_value("Introduction E2E")
    expect(page.locator("#release-email-introduction")).to_have_value(
        "Introduction release E2E"
    )
    expect(page.locator("#email-signature")).to_have_value("Signature E2E")


def test_release_preview_uses_its_own_introduction_and_plural_sentence(page, fortios_server):
    """The release paragraph is independent from the CVE one, with an automatic fallback."""
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    # Both paragraphs are exposed, separately labelled, in the appearance section.
    expect(page.get_by_text("Introduction alertes CVE", exact=True)).to_be_visible()
    expect(page.get_by_text("Introduction nouvelles versions", exact=True)).to_be_visible()

    cve_intro = "Introduction CVE E2E."
    release_intro = "Introduction release E2E."
    page.fill("#email-introduction", cve_intro)
    page.fill("#release-email-introduction", "")

    # Empty release paragraph: the renderer writes the sentence, agreeing with the count.
    page.click('[data-preview-scenario="release-multi"]')
    expect(page.locator("#email-preview-text")).to_contain_text(
        "FortiUpgrade a détecté 2 nouvelles versions Fortinet disponibles au téléchargement."
    )
    assert cve_intro not in (page.locator("#email-preview-text").text_content() or "")

    page.click('[data-preview-scenario="release"]')
    expect(page.locator("#email-preview-text")).to_contain_text(
        "FortiUpgrade a détecté une nouvelle version Fortinet disponible au téléchargement."
    )

    # A configured release paragraph applies to releases and never leaks into CVE previews.
    page.fill("#release-email-introduction", release_intro)
    page.click('[data-preview-scenario="release"]')
    expect(page.locator("#email-preview-text")).to_contain_text(release_intro)

    page.click('[data-preview-scenario="single"]')
    expect(page.locator("#email-preview-text")).to_contain_text(cve_intro)
    assert release_intro not in (page.locator("#email-preview-text").text_content() or "")

    # Persistence of both paragraphs is covered by the SMTP appearance save/reload test."""


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
    column_widths = page.evaluate(
        """() => [
          document.querySelector('#notifications-form').getBoundingClientRect().width,
          document.querySelector('.notifications-column--email').getBoundingClientRect().width,
          document.querySelector('.notifications-column--preview').getBoundingClientRect().width,
        ]"""
    )
    # 3 columns on wide desktop: the preview column is the widest, the email column is at least
    # comparable to the alerts column.
    assert column_widths[2] >= column_widths[0] * 1.3
    assert column_widths[1] >= column_widths[0] * 0.75

    page.set_viewport_size({"width": 375, "height": 812})
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    expect(page.locator("#smtp-host")).to_be_visible()
    expect(page.locator("#smtp-password-status")).to_be_visible()
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
          source: 'environment', state: 'incomplete', smtpState: 'incomplete',
          passwordConfigured: false,
          microsoft365: {state: 'incomplete', tenantId: '', clientId: '', from: '',
            displayName: 'FortiUpgrade', mailboxIdentity: '',
            clientSecretConfigured: false, canSetClientSecret: true,
            clientSecretStorageState: 'available'}
        }})"""
    )

    expect(page.locator("#smtp-status-label")).to_have_text(
        "Configuration incomplète"
    )
    expect(page.locator("#test-email-button")).to_be_disabled()


def test_transport_indicator_follows_the_selected_transport(page, fortios_server):
    """The status indicator must describe the transport selected in the form.

    A recorded, complete Microsoft 365 configuration is complete even with an empty SMTP block;
    switching the selector back and forth must show each transport's own verdict, and the saved
    Microsoft 365 configuration must stay untouched.
    """
    fortios_notify.save_notification_settings(
        fortios_server.data_dir / "notification-settings.json",
        {
            "enabled": True,
            "minimumSeverity": "high",
            "products": {
                "fortigate-fortios": True,
                "fortimanager": False,
                "fortianalyzer": False,
                "forticlient-ems": False,
                "forticlient": {"windows": True, "macos": False, "linux": False},
            },
            "recipients": ["soc@example.com"],
        },
    )
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    # Microsoft 365 selected, filled and its secret recorded: no SMTP field is touched.
    page.select_option("#email-transport", "microsoft365")
    for field, value in (
        ("m365-tenant-id", "11111111-2222-3333-4444-555555555555"),
        ("m365-client-id", "66666666-7777-8888-9999-000000000000"),
        ("m365-from-address", "fortiupgrade@example.test"),
        ("m365-display-name", "FortiUpgrade — Alertes de sécurité Fortinet"),
        ("m365-mailbox-identity", "fortiupgrade@example.test"),
    ):
        page.fill(f"#{field}", value)
    page.fill("#m365-client-secret", "browser-graph-fixture")
    with page.expect_response(lambda r: r.url.endswith("/api/cert/microsoft365/client-secret")) as secret:
        page.click("#save-m365-secret-button")
    assert secret.value.status == 200
    with page.expect_response(lambda r: r.url.endswith("/api/cert/smtp")) as saved:
        page.click("#save-smtp-button")
    assert saved.value.status == 200

    expect(page.locator("#smtp-status-label")).to_have_text("Configuration complète")
    expect(page.locator("#smtp-status-dot")).to_have_class(re.compile(r"\bsuccess\b"))

    # SMTP is empty: its own verdict is incomplete, without affecting the saved Microsoft 365
    # configuration.
    page.select_option("#email-transport", "smtp")
    expect(page.locator("#smtp-status-label")).to_have_text("Configuration incomplète")
    expect(page.locator("#smtp-status-dot")).to_have_class(re.compile(r"\bfailure\b"))
    expect(page.locator("#test-email-button")).to_be_disabled()

    # Back to Microsoft 365: complete again, and the reloaded page keeps the same verdict.
    page.select_option("#email-transport", "microsoft365")
    expect(page.locator("#smtp-status-label")).to_have_text("Configuration complète")
    page.reload()
    page.click("#notifications-tab")
    expect(page.locator("#email-transport")).to_have_value("microsoft365")
    expect(page.locator("#smtp-status-label")).to_have_text("Configuration complète")
    expect(page.locator("#smtp-status-dot")).to_have_class(re.compile(r"\bsuccess\b"))

    transport_settings = json.loads(
        (fortios_server.data_dir / "email-transport-settings.json").read_text(encoding="utf-8")
    )
    assert transport_settings["transport"] == "microsoft365"
    assert transport_settings["microsoft365"]["tenantId"] == "11111111-2222-3333-4444-555555555555"
    assert "browser-graph-fixture" not in page.content()
    assert not errors


def test_notifications_keeps_the_test_card_in_the_email_column(page, fortios_server):
    """The "Test d’envoi" card sits in the email column, between transport and appearance.

    Same card, same margins and same behaviour: only its position in the layout changes, and the
    empty test recipient must never block saving the email configuration.
    """
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    order = page.evaluate(
        """() => {
             const card = node => {
               if (node.classList.contains('smtp-panel')) return 'transport';
               if (node.classList.contains('test-email-panel')) return 'test';
               if (node.classList.contains('appearance-panel')) return 'appearance';
               if (node.classList.contains('preview-panel')) return 'preview';
               return null;
             };
             const emailColumn = [...document.querySelectorAll('.notifications-column--email .panel')]
               .map(card).filter(Boolean);
             const previewColumn = [...document.querySelectorAll('.notifications-column--preview .panel')]
               .map(card).filter(Boolean);
             return {
               emailColumn,
               previewColumn,
               first: document.querySelector('.notifications-columns').firstElementChild.id,
             };
           }"""
    )
    assert order["emailColumn"] == ["transport", "test"]
    assert order["previewColumn"] == ["appearance", "preview"]
    # Left column untouched: the CVEs alerts card stays the grid's first column.
    assert order["first"] == "notifications-form"

    def boxes() -> dict[str, dict[str, float]]:
        return page.evaluate(
            """() => {
                 const card = selector => document.querySelector(selector).getBoundingClientRect();
                 const transport = card('#smtp-form .smtp-panel');
                 const test = card('#smtp-form .test-email-panel');
                 const appearance = card('#smtp-form .appearance-panel');
                 return {
                   transport: {x: transport.x, y: transport.y, width: transport.width},
                   test: {x: test.x, y: test.y, width: test.width},
                   appearance: {x: appearance.x, y: appearance.y, width: appearance.width},
                 };
               }"""
        )

    desktop = boxes()
    # One logical column: same left edge and same width, stacked in order.
    assert abs(desktop["transport"]["x"] - desktop["test"]["x"]) <= 1
    assert abs(desktop["test"]["x"] - desktop["appearance"]["x"]) <= 1
    assert abs(desktop["transport"]["width"] - desktop["test"]["width"]) <= 1
    assert abs(desktop["test"]["width"] - desktop["appearance"]["width"]) <= 1
    assert desktop["transport"]["y"] < desktop["test"]["y"] < desktop["appearance"]["y"]
    # The right column is narrower than the full page: the card is no longer full-bleed.
    page_width = page.evaluate("document.documentElement.clientWidth")
    assert desktop["test"]["width"] < page_width * 0.75

    # Saving the email configuration still works with an empty test recipient: the test card's
    # own `required` check must not leak into the SMTP form's submission.
    page.fill("#smtp-host", "smtp.layout.example")
    page.fill("#smtp-from-address", "fortiupgrade@example.test")
    page.fill("#smtp-app-url", "https://fortiupgrade.example/app/")
    expect(page.locator("#test-email-recipient")).to_have_value("")
    with page.expect_response(lambda r: r.url.endswith("/api/cert/smtp")) as saved:
        page.click("#save-smtp-button")
    assert saved.value.status == 200

    page.set_viewport_size({"width": 390, "height": 900})
    mobile = boxes()
    assert abs(mobile["transport"]["x"] - mobile["test"]["x"]) <= 1
    assert mobile["transport"]["y"] < mobile["test"]["y"] < mobile["appearance"]["y"]
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )


def test_notifications_responsive_columns_and_sticky_guard(page, fortios_server):
    """The notifications board is a real responsive layout.

    - ≥1400px: three balanced columns, the preview in the third one and the alerts card first;
    - 900–1399px: two columns, the email pipeline stacked on the right;
    - <900px: one column, in the spec order (Alertes, Email, Test, Apparence, Aperçu), without
      horizontal overflow;
    - the sticky preview only engages when the viewport is tall enough (min-height guard); when it
      does, the pinned card leaves a usable window for the appearance fields and the save button
      stays reachable.
    """
    login_cert_admin(page, fortios_server)
    page.click("#notifications-tab")

    def geometry():
        return page.evaluate(
            """() => {
              const box = (selector) => {
                const r = document.querySelector(selector).getBoundingClientRect();
                return {x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width)};
              };
              return {
                alerts: box('#notifications-form'),
                smtp: box('.smtp-panel'),
                test: box('.test-email-panel'),
                appearance: box('.appearance-panel'),
                preview: box('.preview-panel'),
                overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                sticky: getComputedStyle(document.querySelector('.preview-panel')).position,
              };
            }"""
        )

    # Desktop large: three distinct columns, preview in the third one, sticky off at 1080px of
    # height (the pinned card would leave no usable window for the fields).
    page.set_viewport_size({"width": 1920, "height": 1080})
    desktop = geometry()
    assert desktop["overflowX"] <= 0
    assert desktop["sticky"] == "static"
    assert desktop["alerts"]["x"] < desktop["smtp"]["x"] < desktop["preview"]["x"]
    assert abs(desktop["alerts"]["x"] - desktop["smtp"]["x"]) > desktop["alerts"]["width"] * 0.2
    assert desktop["alerts"]["y"] == desktop["smtp"]["y"] == desktop["preview"]["y"]
    assert desktop["preview"]["width"] > desktop["alerts"]["width"]

    # Tablet: two columns, the whole email pipeline stacked in the right one.
    page.set_viewport_size({"width": 1024, "height": 800})
    tablet = geometry()
    assert tablet["overflowX"] <= 0
    assert tablet["alerts"]["x"] < tablet["smtp"]["x"]
    assert abs(tablet["smtp"]["x"] - tablet["preview"]["x"]) <= 1
    assert abs(tablet["appearance"]["x"] - tablet["preview"]["x"]) <= 1
    assert tablet["smtp"]["y"] < tablet["test"]["y"] < tablet["appearance"]["y"] < tablet["preview"]["y"]

    # Mobile: one column, spec order, no horizontal overflow.
    page.set_viewport_size({"width": 390, "height": 844})
    mobile = geometry()
    assert mobile["overflowX"] <= 0
    assert abs(mobile["alerts"]["x"] - mobile["smtp"]["x"]) <= 1
    assert abs(mobile["smtp"]["x"] - mobile["preview"]["x"]) <= 1
    assert (
        mobile["alerts"]["y"]
        < mobile["smtp"]["y"]
        < mobile["test"]["y"]
        < mobile["appearance"]["y"]
        < mobile["preview"]["y"]
    )

    # Tall desktop: the sticky preview engages, pins while scrolling, and still leaves a usable
    # window for the appearance fields (the save button is never covered).
    page.set_viewport_size({"width": 1920, "height": 1300})
    tall = geometry()
    assert tall["sticky"] == "sticky"
    pinned = page.evaluate(
        """() => {
          window.scrollTo(0, Math.floor((document.documentElement.scrollHeight - window.innerHeight) / 2));
          const panel = document.querySelector('.preview-panel');
          const top = Math.round(panel.getBoundingClientRect().top);
          const bottom = Math.round(panel.getBoundingClientRect().bottom);
          window.scrollTo(0, 0);
          return {top, bottom, viewport: window.innerHeight};
        }"""
    )
    assert pinned["top"] <= 17
    assert pinned["viewport"] - pinned["bottom"] >= 240
    reachable = page.evaluate(
        """() => {
          const btn = document.getElementById('save-smtp-button');
          btn.scrollIntoView({block: 'end'});
          const r = btn.getBoundingClientRect();
          const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
          return hit === btn || btn.contains(hit);
        }"""
    )
    assert reachable
