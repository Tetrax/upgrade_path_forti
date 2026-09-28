"""Home page relaunch button (`#healthRefreshButton`, in the "État des données" header).

The button must be discreet, keyboard reachable, and must never toggle the collapsed <details> it
sits in. It must also never invent a collection: without an admin session it explains what to do
and starts nothing, and once a real relaunch runs, the state shown comes from the admin API (the
health panel is re-read only when that run really finished).

The collectors themselves are replaced by the isolated fixture's inert FORTIOS_E2E_MOCK_NETWORK
stub: no real scan, no network, no email. FORTIOS_E2E_REFRESH_HOLD_FILE keeps the fake run open
until the test releases it, which is what makes "en cours" and "terminé" deterministic.
"""

from __future__ import annotations

import json
import re

import pytest
from playwright.sync_api import expect

OLD_SUCCESS_AT = "2026-07-15T07:15:00Z"
OLD_SUCCESS_TEXT = "15/07/2026"


@pytest.fixture
def refresh_hold(tmp_path):
    """Path of the file that releases the fake collection (its content is its exit status)."""
    return tmp_path / "refresh-hold"


@pytest.fixture
def fortios_server_env(tmp_path, refresh_hold):
    return {
        "FORTIOS_E2E_REFRESH_HOLD_FILE": str(refresh_hold),
        "FORTIOS_E2E_REFRESH_COMMAND_LOG": str(tmp_path / "refresh-commands.jsonl"),
    }


def write_old_health(fortios_server) -> None:
    """Health data old enough that a refreshed panel is unmistakably different."""
    source = {
        "status": "ok",
        "lastAttemptAt": OLD_SUCCESS_AT,
        "lastSuccessAt": OLD_SUCCESS_AT,
        "consecutiveFailures": 0,
        "durationSeconds": 1.0,
    }
    (fortios_server.data_dir / "fortios-health.json").write_text(
        json.dumps(
            {
                "sources": {"fortios-docs": dict(source), "daily-run": dict(source)},
                "updatedAt": OLD_SUCCESS_AT,
            }
        )
    )


def login_cert_admin(page, fortios_server) -> None:
    page.goto(f"{fortios_server.base_url}/admin/")
    page.fill("#username", fortios_server.admin_username)
    page.fill("#password", fortios_server.admin_password)
    page.click("#login-button")
    expect(page.locator("#admin-view")).to_be_visible()


def open_home(page, fortios_server) -> None:
    page.goto(f"{fortios_server.base_url}/")
    page.wait_for_selector("#productSelect option", state="attached")
    page.wait_for_selector("#healthSummaryText:not(:text('Chargement'))")


def test_button_is_in_the_header_keyboard_reachable_and_never_toggles_the_panel(app_page):
    details = app_page.locator("#healthDetails")
    button = app_page.locator("#healthDetails summary #healthRefreshButton")
    state = app_page.locator("#healthRefreshState")
    expect(button).to_be_visible()
    assert details.evaluate("el => el.open") is False

    # Keyboard: reachable, activated by Enter, and no accidental toggle of the panel.
    # (The button is deliberately disabled while its request is in flight, so focus is taken
    # before activating — not after.)
    button.focus()
    assert (
        app_page.evaluate("() => document.activeElement && document.activeElement.id")
        == "healthRefreshButton"
    )
    app_page.keyboard.press("Enter")
    expect(state).to_contain_text("Session administrateur requise")
    assert details.evaluate("el => el.open") is False

    # Mouse: same guarantee once the first attempt settled.
    expect(button).to_be_enabled()
    button.click()
    expect(state).to_contain_text("Session administrateur requise")
    assert details.evaluate("el => el.open") is False

    # The summary itself keeps behaving like a disclosure control.
    app_page.locator("#healthSummaryText").click()
    assert details.evaluate("el => el.open") is True


def test_anonymous_click_explains_the_session_requirement_and_starts_nothing(
    app_page, fortios_server
):
    app_page.click("#healthRefreshButton")

    state = app_page.locator("#healthRefreshState")
    expect(state).to_contain_text("Session administrateur requise")
    expect(state.locator("a")).to_have_attribute("href", "/admin/")
    # No collector was started, and the button is usable again for the next attempt.
    expect(app_page.locator("#healthRefreshButton")).to_be_enabled()
    assert not (fortios_server.data_dir / "fortios-manual-refresh.json").exists()


def test_relaunch_reports_progress_then_the_real_end_and_refreshes_health(
    page, fortios_server, refresh_hold
):
    write_old_health(fortios_server)
    login_cert_admin(page, fortios_server)
    open_home(page, fortios_server)
    old_text = page.locator("#healthSummaryText").inner_text()
    assert OLD_SUCCESS_TEXT in old_text

    page.click("#healthRefreshButton")
    expect(page.locator("#healthRefreshState")).to_contain_text("Collecte en cours")
    expect(page.locator("#healthRefreshButton")).to_be_disabled()

    # A browser reload during the run reports the real state, never a fabricated one.
    page.reload()
    page.wait_for_selector("#productSelect option", state="attached")
    expect(page.locator("#healthRefreshState")).to_contain_text("Collecte en cours")

    refresh_hold.write_text("0", encoding="utf-8")

    expect(page.locator("#healthRefreshState")).to_contain_text(
        "Dernière relance terminée", timeout=15000
    )
    expect(page.locator("#healthRefreshButton")).to_be_enabled()
    # The panel now shows the freshly collected health data, not the pre-run snapshot.
    new_text = page.locator("#healthSummaryText").inner_text()
    assert OLD_SUCCESS_TEXT not in new_text
    assert new_text != old_text


def test_reported_errors_are_never_dressed_up_as_success(page, fortios_server, refresh_hold):
    login_cert_admin(page, fortios_server)
    open_home(page, fortios_server)
    refresh_hold.write_text("1", encoding="utf-8")

    page.click("#healthRefreshButton")

    state = page.locator("#healthRefreshState")
    expect(state).to_contain_text("erreurs", timeout=15000)
    expect(state).to_have_class(re.compile("health-refresh-state error"))
    expect(page.locator("#healthRefreshButton")).to_be_enabled()


def test_header_layout_keeps_the_button_inside_the_panel_on_a_narrow_screen(app_page):
    app_page.set_viewport_size({"width": 390, "height": 844})
    app_page.reload()
    app_page.wait_for_selector("#productSelect option", state="attached")

    state = app_page.evaluate(
        """() => {
          const rect = (el) => {
            const r = el.getBoundingClientRect();
            return {
              left: Math.round(r.left), right: Math.round(r.right),
              top: Math.round(r.top), bottom: Math.round(r.bottom),
            };
          };
          const button = document.querySelector('#healthRefreshButton');
          return {
            panel: rect(document.querySelector('.health-panel')),
            summary: rect(document.querySelector('#healthDetails summary')),
            button: rect(button),
            clipped: button.scrollWidth > button.clientWidth + 1,
            overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          };
        }"""
    )

    expect(app_page.locator("#healthRefreshButton")).to_be_visible()
    assert state["overflowX"] <= 0, state
    assert state["clipped"] is False, state
    assert state["panel"]["left"] - 1 <= state["button"]["left"], state
    assert state["button"]["right"] <= state["panel"]["right"] + 1, state
    assert state["button"]["top"] >= state["summary"]["top"] - 1, state
