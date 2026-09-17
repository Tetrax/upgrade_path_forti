"""Home briefing bar (`/`): every monitored product gets a summary row, and the CVE badges name
their product — all built from the served catalog (see renderBriefingPanel() in app/index.html).

The fixture catalog (tests/e2e/fixtures/catalog.json) carries FortiManager and FortiAnalyzer
entries, several CVE cases (FortiClient-only, FortiClient+EMS, FortiGate+FortiManager) and the
version/maturity mix the assertions below rely on.
"""

from __future__ import annotations

import datetime
import json

from playwright.sync_api import expect

# Products summarised on the home page, in display order (see BRIEFING_PRODUCT_IDS).
BRIEFING_PRODUCTS = ["fortigate-fortios", "fortimanager", "fortianalyzer", "forticlient-ems"]


def wait_for_catalog(page) -> None:
    expect(page.locator("#dataStatus")).to_contain_text("JSON généré chargé")


def briefing_row(page, product_id: str):
    return page.locator(f'#briefingPanel .briefing-row[data-product="{product_id}"]')


def chip_texts(page, product_id: str) -> list[str]:
    chips = briefing_row(page, product_id).locator(".briefing-chip")
    return [" ".join(chip.inner_text().split()) for chip in chips.all()]


def badge_texts(page) -> list[str]:
    badges = page.locator("#briefingPanel .briefing-row-cves .badge")
    return [" ".join(badge.inner_text().split()) for badge in badges.all()]


def reshape_catalog(fortios_server, mutate) -> None:
    """Rewrite the catalog the isolated server serves, then force a clean reload.

    localStorage is cleared first: the page merges the fetched catalog into its cached state, so a
    stale cache would keep versions the rewritten catalog no longer has (a union, not a replace).
    """
    path = fortios_server.data_dir / "fortios-data.generated.json"
    catalog = json.loads(path.read_text())
    mutate(catalog)
    path.write_text(json.dumps(catalog))


def reload_clean(page) -> None:
    page.evaluate("localStorage.clear()")
    page.reload()
    page.wait_for_selector("#productSelect option", state="attached")
    wait_for_catalog(page)


# --- The four monitored products ----------------------------------------------------------

def test_briefing_summarises_every_monitored_product(app_page):
    rows = app_page.locator("#briefingPanel .briefing-row")
    # Four product rows plus the latest-CVE row, in the documented order.
    expect(rows).to_have_count(5)
    assert [row.locator(".briefing-row-label").text_content() for row in rows.all()] == [
        "FortiGate / FortiOS", "FortiManager", "FortiAnalyzer", "FortiClient EMS", "Dernières CVE",
    ]
    assert [row.get_attribute("data-product") for row in rows.all()][:4] == BRIEFING_PRODUCTS

    # One chip per train of the served catalog, newest train first, four trains at most. The three
    # products the page has no built-in sample for come out exactly as the catalog defines them;
    # FortiGate/FortiOS also inherits the sample models the page starts from (7.4.11 / 7.2.10),
    # which only ever adds a train's older version behind the newest one.
    fortios_chips = chip_texts(app_page, "fortigate-fortios")
    assert len(fortios_chips) == 4, fortios_chips
    assert fortios_chips[0] == "8.0.0 Feature"
    assert "7.0.14 Mature" in fortios_chips
    assert "6.2.4" not in fortios_chips, "only the four most recent trains are summarised"
    assert chip_texts(app_page, "fortimanager") == ["8.0.1", "7.6.3", "7.4.11"]
    assert chip_texts(app_page, "fortianalyzer") == ["8.0.1", "7.6.2", "7.4.10"]
    assert chip_texts(app_page, "forticlient-ems") == ["7.4.2"]

    # Maturity and lifecycle wording exist for FortiOS only: the catalog carries neither for the
    # other products, and the bar must not invent one for them.
    for product_id in ("fortimanager", "fortianalyzer", "forticlient-ems"):
        row_text = briefing_row(app_page, product_id).inner_text()
        for invented in ("Mature", "Feature", "Hors support", "Support →"):
            assert invented not in row_text, f"{product_id} must not show a FortiOS-only status"


def test_briefing_follows_the_catalog_instead_of_hardcoded_trains(app_page, fortios_server):
    """A version the bar has never seen — from a different train — shows up after a catalog change."""
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

    def mutate(catalog):
        manager = next(product for product in catalog["products"] if product["id"] == "fortimanager")
        manager["models"][0]["firmwares"] = [
            {"version": "9.8.1", "build": "9998", "notes": ["release-notes"]},
            {
                "version": "9.9.9",
                "build": "9999",
                "notes": ["release-notes"],
                "discoveredAt": today,
                "links": {"release-notes": "https://docs.fortinet.com/document/fortimanager/9.9.9/release-notes"},
            },
        ]

    reshape_catalog(fortios_server, mutate)
    reload_clean(app_page)

    chips = chip_texts(app_page, "fortimanager")
    # Newest train first, and each train contributes exactly its newest version.
    assert chips == ["9.9.9 NEW", "9.8.1"], chips

    # The chip links to the served release notes and carries the build in its tooltip.
    newest = briefing_row(app_page, "fortimanager").locator(".briefing-chip").first
    assert newest.get_attribute("href") == "https://docs.fortinet.com/document/fortimanager/9.9.9/release-notes"
    title = newest.get_attribute("title")
    assert "build 9999" in title and f"vue le {today}" in title


# --- Latest CVEs ---------------------------------------------------------------------------

def test_briefing_cve_badges_name_their_product(app_page):
    texts = badge_texts(app_page)
    assert len(texts) == 6
    assert len(set(texts)) == len(texts), "the same CVE must not be listed twice"

    # Most recent publication first.
    assert texts == [
        "FMG · CVE-2026-88881",
        "FAZ · CVE-2026-88882",
        "EMS · CVE-2026-88883",
        "EMS · CVE-2026-88885",
        "FGT+FMG · CVE-2026-88886",
        "FGT · CVE-2026-99999",
    ], texts

    # The tooltip keeps the full product list even when the badge only names the briefing product.
    multi = app_page.locator("#briefingPanel .briefing-row-cves .badge", has_text="CVE-2026-88885")
    assert "FortiClient" in multi.get_attribute("title")

    # Severity colouring is the per-path one: critical/high danger, medium warn, low info.
    classes = {
        " ".join(badge.inner_text().split()): badge.get_attribute("class")
        for badge in app_page.locator("#briefingPanel .briefing-row-cves .badge").all()
    }
    assert "danger" in classes["FGT+FMG · CVE-2026-88886"]
    assert "warn" in classes["FMG · CVE-2026-88881"]
    assert "info" in classes["EMS · CVE-2026-88883"]


def test_briefing_keeps_forticlient_only_advisories_on_its_own_page(app_page, fortios_server):
    panel = app_page.locator("#briefingPanel").inner_text()
    assert "CVE-2026-88884" not in panel

    # ...but the FortiClient page still lists it, so nothing was lost from the product's own view.
    app_page.goto(f"{fortios_server.base_url}/forticlient/")
    expect(app_page.locator("#briefingPanel")).to_contain_text("CVE-2026-88884")


# --- Empty states, lifecycle scoping, responsiveness ---------------------------------------

def test_briefing_empty_states_stay_discreet(app_page, fortios_server):
    def mutate(catalog):
        catalog["cves"] = []
        ems = next(product for product in catalog["products"] if product["id"] == "forticlient-ems")
        ems["models"][0]["firmwares"] = []

    reshape_catalog(fortios_server, mutate)
    reload_clean(app_page)

    expect(briefing_row(app_page, "forticlient-ems")).to_contain_text("Aucune donnée")
    expect(app_page.locator("#briefingPanel .briefing-row-cves")).to_contain_text("Aucune CVE récente")
    # The other products still show their versions: one empty product must not blank the bar.
    assert chip_texts(app_page, "fortimanager") == ["8.0.1", "7.6.3", "7.4.11"]

    text = app_page.locator("#briefingPanel").inner_text()
    for placeholder in ("undefined", "null", "None", "NaN"):
        assert placeholder not in text


def test_briefing_support_status_stays_fortios_only(app_page, fortios_server):
    def mutate(catalog):
        catalog["fortiosLifecycle"] = {
            "7.0": {"releaseDate": "2021-01-01", "support": "2021-06-01", "eol": "2022-01-01"},
            "7.4": {"releaseDate": "2023-01-01", "support": "2022-01-01", "eol": "2023-06-01"},
        }

    reshape_catalog(fortios_server, mutate)
    reload_clean(app_page)

    fortios_row = briefing_row(app_page, "fortigate-fortios").inner_text()
    assert "Hors support" in fortios_row

    # FortiManager/FortiAnalyzer/FortiClient EMS also have 7.4 versions, and 7.4 is in the
    # lifecycle table above: only FortiOS may read those dates.
    for product_id in ("fortimanager", "fortianalyzer", "forticlient-ems"):
        row_text = briefing_row(app_page, product_id).inner_text()
        assert "Hors support" not in row_text, product_id
        assert "Support →" not in row_text, product_id


def test_briefing_is_responsive_without_horizontal_overflow(app_page):
    for width, height, max_height in ((1920, 1080, 200), (1440, 900, 200), (1024, 800, 220), (390, 844, 420)):
        app_page.set_viewport_size({"width": width, "height": height})
        overflow = app_page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0, f"{width}px viewport overflows by {overflow}px"

        bar = app_page.locator("#briefingPanel")
        expect(bar).to_be_visible()
        bar_height = app_page.evaluate("document.querySelector('#briefingPanel').getBoundingClientRect().height")
        assert bar_height <= max_height, f"{width}px viewport: briefing bar {bar_height}px tall"

        # Every product stays identifiable, with its versions present, at every width.
        for product_id in BRIEFING_PRODUCTS:
            row = briefing_row(app_page, product_id)
            expect(row).to_be_visible()
            assert row.locator(".briefing-chip").count() >= 1
