"""Real API persistence and UI checks; no Microsoft credential or network send."""
import json

import pytest
from playwright.sync_api import expect

from scripts import fortios_notify


@pytest.mark.parametrize("width", [1440, 390])
def test_secret_save_preserves_drafts_and_clears_value(page, fortios_server, width):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.set_viewport_size({"width": width, "height": 1000})
    page.goto(f"{fortios_server.base_url}/admin/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    page.select_option("#email-transport", "microsoft365")
    drafts = {
        "m365-tenant-id": "draft-tenant.example",
        "m365-client-id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "m365-from-address": "draft-sender@example.test",
        "m365-display-name": "Draft display name",
        "m365-mailbox-identity": "draft-sender@example.test",
    }
    assert page.locator("#m365-client-secret").bounding_box()["width"] >= 200
    for field, value in drafts.items():
        page.fill(f"#{field}", value)
    for value in ("browser-secret-fixture", "browser-rotated-fixture"):
        page.fill("#m365-client-secret", value)
        with page.expect_response(lambda r: r.url.endswith("/api/cert/microsoft365/client-secret")) as saved:
            page.click("#save-m365-secret-button")
        assert saved.value.status == 200
        assert value not in saved.value.text()
        expect(page.locator("#m365-client-secret")).to_have_value("")
        expect(page.locator("#email-transport")).to_have_value("microsoft365")
        for field, draft in drafts.items():
            expect(page.locator(f"#{field}")).to_have_value(draft)
        assert fortios_server.microsoft365_secret_path.read_text() == value
        assert fortios_server.microsoft365_secret_path.stat().st_mode & 0o777 == 0o600
    expect(page.locator("#m365-secret-status")).to_have_text("Secret configuré")
    assert not (fortios_server.data_dir / "email-transport-settings.json").exists()
    page.reload()
    expect(page.locator("#m365-client-secret")).to_have_value("")
    assert "browser-rotated-fixture" not in page.content()
    assert not errors


@pytest.mark.parametrize("width", [1440, 390])
def test_microsoft365_settings_roundtrip_and_missing_secret(page, fortios_server, width):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    fortios_notify.save_smtp_settings(
        fortios_server.data_dir / "smtp-settings.json",
        {
            "host": "smtp.roundtrip.example",
            "port": 587,
            "security": "starttls",
            "allowInsecure": False,
            "username": "roundtrip-user",
            "from": "roundtrip@example.invalid",
            "appUrl": f"{fortios_server.base_url}/",
            "timeout": 17,
            "emailAppearance": {
                "displayName": "Roundtrip fixture",
                "introduction": "SMTP fixture",
                "signature": "Test suite",
            },
        },
    )
    page.set_viewport_size({"width": width, "height": 1000})
    page.goto(f"{fortios_server.base_url}/admin/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#email-transport")).to_have_value("smtp")
    expect(page.locator("#microsoft365-settings")).to_have_count(1)
    expect(page.locator("#microsoft365-settings")).to_be_hidden()
    expect(page.locator("#smtp-host")).to_have_value("smtp.roundtrip.example")
    expect(page.locator("#smtp-port")).to_have_value("587")
    expect(page.locator("#smtp-username")).to_have_value("roundtrip-user")
    expect(page.locator("#smtp-from-address")).to_have_value("roundtrip@example.invalid")
    smtp_values = {
        "#smtp-host": "smtp.gui.example",
        "#smtp-port": "2525",
        "#smtp-username": "gui-user",
        "#smtp-from-address": "gui@example.invalid",
        "#smtp-app-url": f"{fortios_server.base_url}/gui-app/",
        "#smtp-timeout": "23",
    }
    for field, value in smtp_values.items():
        if field == "#smtp-timeout":
            page.locator("#smtp-advanced-options summary").click()
        page.fill(field, value)
    page.fill("#smtp-password", "smtp-initial-fixture")
    with (
        page.expect_response(
            lambda r: r.url.endswith("/api/cert/smtp") and r.request.method == "POST"
        ) as smtp_settings_response,
        page.expect_response(
            lambda r: r.url.endswith("/api/cert/smtp/password") and r.request.method == "POST"
        ) as smtp_password_response,
    ):
        page.click("#save-smtp-button")
    assert smtp_settings_response.value.status == 200
    assert smtp_password_response.value.status == 200
    assert "smtp-initial-fixture" not in smtp_settings_response.value.text()
    assert "smtp-initial-fixture" not in smtp_password_response.value.text()
    expect(page.locator("#smtp-password")).to_have_value("")
    assert fortios_server.smtp_password_path.read_text() == "smtp-initial-fixture"
    assert fortios_server.smtp_password_path.stat().st_mode & 0o777 == 0o600

    page.fill("#smtp-password", "smtp-rotated-fixture")
    with page.expect_response(
        lambda r: r.url.endswith("/api/cert/smtp/password") and r.request.method == "POST"
    ) as rotated_password_response:
        page.click("#save-smtp-button")
    assert rotated_password_response.value.status == 200
    assert "smtp-rotated-fixture" not in rotated_password_response.value.text()
    expect(page.locator("#smtp-password")).to_have_value("")
    assert fortios_server.smtp_password_path.read_text() == "smtp-rotated-fixture"

    page.fill("#smtp-password", "smtp-failing-fixture")

    def fail_smtp_password(route):
        route.fulfill(
            status=503,
            content_type="application/json",
            body=json.dumps(
                {
                    "error": "Stockage du mot de passe SMTP indisponible.",
                    "errorCode": "storage-unavailable",
                }
            ),
        )

    page.route("**/api/cert/smtp/password", fail_smtp_password)
    with (
        page.expect_response(
            lambda r: r.url.endswith("/api/cert/smtp") and r.request.method == "POST"
        ) as failed_settings_response,
        page.expect_response(
            lambda r: r.url.endswith("/api/cert/smtp/password") and r.request.method == "POST"
        ) as failed_password_response,
    ):
        page.click("#save-smtp-button")
    assert failed_settings_response.value.status == 200
    assert failed_password_response.value.status == 503
    expect(page.locator("#smtp-message")).to_contain_text(
        "Paramètres enregistrés, mais mot de passe non modifié"
    )
    expect(page.locator("#smtp-password")).to_have_value("")
    assert fortios_server.smtp_password_path.read_text() == "smtp-rotated-fixture"
    assert "smtp-failing-fixture" not in page.content()
    page.unroute("**/api/cert/smtp/password", fail_smtp_password)

    # A blank password field is not submitted as a password operation and leaves the rotation intact.
    with page.expect_response(
        lambda r: r.url.endswith("/api/cert/smtp") and r.request.method == "POST"
    ) as blank_settings_response:
        page.click("#save-smtp-button")
    assert blank_settings_response.value.status == 200
    assert fortios_server.smtp_password_path.read_text() == "smtp-rotated-fixture"

    page.select_option("#email-transport", "microsoft365")
    expect(page.locator("#microsoft365-settings")).to_be_visible()
    expect(page.locator("#smtp-transport-fields")).to_be_hidden()
    values = {
        "m365-tenant-id": "11111111-1111-1111-1111-111111111111",
        "m365-client-id": "22222222-2222-2222-2222-222222222222",
        "m365-from-address": "sender@example.invalid",
        "m365-display-name": "Isolated browser fixture",
        "m365-mailbox-identity": "33333333-3333-3333-3333-333333333333",
    }
    for field, value in values.items():
        page.fill(f"#{field}", value)
    with page.expect_response(lambda r: r.url.endswith("/api/cert/smtp") and r.request.method == "POST") as saved:
        page.click("#save-smtp-button")
    assert saved.value.status == 200
    state = json.loads((fortios_server.data_dir / "email-transport-settings.json").read_text())
    assert state["transport"] == "microsoft365"
    assert "clientSecret" not in state["microsoft365"]
    page.reload()
    page.click("#notifications-tab")
    expect(page.locator("#email-transport")).to_have_value("microsoft365")
    for field, value in values.items():
        expect(page.locator(f"#{field}")).to_have_value(value)
    expect(page.locator("#m365-secret-status")).to_have_text("Secret non configuré")
    assert page.locator("#microsoft365-settings input[type=password]").count() == 1
    for path in ("/admin/microsoft365-help", "/admin/microsoft365-guide.md"):
        response = page.request.get(f"{fortios_server.base_url}{path}")
        assert response.status == 200
        assert "Microsoft" in response.text()
    page.fill("#test-email-recipient", "recipient@example.invalid")
    expect(page.locator("#test-email-button")).to_be_disabled()
    # Simulate the public ready status, not a credential: the real backend
    # still has no secret and must safely reject the subsequent test send.
    def ready_status(route):
        response = route.fetch()
        payload = response.json()
        payload["smtp"]["state"] = "operational"
        route.fulfill(response=response, json=payload)

    page.route("**/api/cert/smtp", ready_status)
    page.reload()
    page.click("#notifications-tab")
    expect(page.locator("#test-email-button")).to_be_enabled()
    page.fill("#test-email-recipient", "recipient@example.invalid")
    with page.expect_response(lambda r: r.url.endswith("/api/cert/notifications/test")) as tested:
        page.click("#test-email-button")
    assert tested.value.status == 503
    assert tested.value.json()["sent"] is False
    expect(page.locator("#test-email-message")).not_to_be_empty()
    page.unroute("**/api/cert/smtp", ready_status)
    page.select_option("#email-transport", "smtp")
    expect(page.locator("#microsoft365-settings")).to_be_hidden()
    expect(page.locator("#smtp-transport-fields")).to_be_visible()
    with page.expect_response(lambda r: r.url.endswith("/api/cert/smtp") and r.request.method == "POST") as smtp:
        page.click("#save-smtp-button")
    assert smtp.value.status == 200
    page.reload()
    page.click("#notifications-tab")
    expect(page.locator("#email-transport")).to_have_value("smtp")
    expect(page.locator("#smtp-host")).to_have_value("smtp.gui.example")
    expect(page.locator("#smtp-port")).to_have_value("2525")
    expect(page.locator("#smtp-security")).to_have_value("starttls")
    expect(page.locator("#smtp-username")).to_have_value("gui-user")
    expect(page.locator("#smtp-from-address")).to_have_value("gui@example.invalid")
    expect(page.locator("#smtp-app-url")).to_have_value(f"{fortios_server.base_url}/gui-app/")
    expect(page.locator("#smtp-timeout")).to_have_value("23")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not errors
