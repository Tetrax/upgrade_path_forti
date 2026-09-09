"""Real API persistence and UI checks; no Microsoft credential or network send."""
import json

import pytest
from playwright.sync_api import expect


@pytest.mark.parametrize("width", [1440, 390])
def test_microsoft365_settings_roundtrip_and_missing_secret(page, fortios_server, width):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.set_viewport_size({"width": width, "height": 1000})
    page.goto(f"{fortios_server.base_url}/cert/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()
    page.click("#notifications-tab")
    expect(page.locator("#email-transport")).to_have_value("smtp")
    expect(page.locator("#microsoft365-settings")).to_have_count(1)
    expect(page.locator("#microsoft365-settings")).to_be_hidden()
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
    expect(page.locator("#m365-secret-status")).to_have_text("Secret non configuré ou illisible")
    assert page.locator("#microsoft365-settings input[type=password]").count() == 0
    for path in ("/cert/microsoft365-help", "/cert/microsoft365-guide.md"):
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
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not errors
