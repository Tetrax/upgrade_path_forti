"""Covers three related fixes in scripts/fortios_watch.py:

- merge_state() must never let a fresh collector state's discoveredAt overwrite a firmware's real
  first-seen date, including the ~14k pre-migration entries that have no discoveredAt at all.
- The daily batch script's final commit must apply only the changes it actually computed onto a
  freshly re-read state, not its own stale start-of-run snapshot — otherwise a concurrent live
  create/edit/delete (advisories, paths, compatibilities) can be lost, reverted, or resurrected.
- cross_process_lock() must genuinely serialize separate OS processes, not just threads.
"""

import multiprocessing
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402


def make_firmware_state(firmwares: list[dict]) -> dict:
    return fw.normalize_state({
        "products": [{
            "id": "fortigate-fortios",
            "label": "FortiGate/FortiOS",
            "models": [{"id": "FGT60F", "label": "FortiGate-60F", "firmwares": firmwares}],
        }]
    })


class DiscoveredAtMigrationTests(unittest.TestCase):
    def test_legacy_entry_without_discoveredat_stays_absent(self):
        base = make_firmware_state([{"version": "6.4.7", "build": "1911", "notes": ["release-notes"]}])
        incoming = fw.normalize_state({})
        fw.upsert_firmware(incoming, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="6.4.7", build="1911", notes=("release-notes",),
        ))
        merged = fw.merge_state(base, incoming)
        firmware = merged["products"][0]["models"][0]["firmwares"][0]
        self.assertNotIn("discoveredAt", firmware, "legacy entry must never gain a fabricated discoveredAt")

    def test_legacy_entry_with_existing_discoveredat_is_preserved(self):
        base = make_firmware_state([{
            "version": "7.6.7", "build": "2000", "notes": ["release-notes"], "discoveredAt": "2026-06-01",
        }])
        incoming = fw.normalize_state({})
        fw.upsert_firmware(incoming, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="7.6.7", build="2000", notes=("release-notes",),
        ))
        merged = fw.merge_state(base, incoming)
        firmware = merged["products"][0]["models"][0]["firmwares"][0]
        self.assertEqual(firmware["discoveredAt"], "2026-06-01")

    def test_genuinely_new_entry_gets_todays_date(self):
        base = make_firmware_state([])
        incoming = fw.normalize_state({})
        fw.upsert_firmware(incoming, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="8.0.1", build="3000", notes=("release-notes",),
        ))
        merged = fw.merge_state(base, incoming)
        firmware = merged["products"][0]["models"][0]["firmwares"][0]
        self.assertEqual(firmware.get("discoveredAt"), fw.dt.date.today().isoformat())

    def test_repeated_daily_merges_never_reset_an_already_discovered_version(self):
        """Simulates several consecutive daily runs against the same already-known version: a
        fresh collector state re-discovers it every time (collect_docs_catalog always starts
        blank), but its discoveredAt must only ever be set once, at genuine first sight."""
        state = make_firmware_state([])
        incoming_day1 = fw.normalize_state({})
        fw.upsert_firmware(incoming_day1, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="8.0.1", notes=("release-notes",),
        ))
        state = fw.merge_state(state, incoming_day1)
        first_seen = state["products"][0]["models"][0]["firmwares"][0]["discoveredAt"]

        for _ in range(3):
            incoming_later = fw.normalize_state({})
            fw.upsert_firmware(incoming_later, fw.Firmware(
                product="fortigate-fortios", model="FGT60F", version="8.0.1", notes=("release-notes",),
            ))
            state = fw.merge_state(state, incoming_later)

        still_there = state["products"][0]["models"][0]["firmwares"][0]["discoveredAt"]
        self.assertEqual(still_there, first_seen)


class FirmwareMetadataMergeTests(unittest.TestCase):
    """merge_state()'s firmware merge used to be a shallow dict-spread: {**existing, **incoming}
    replaces the whole notes list / links dict wholesale rather than merging their contents. A
    version enriched by a live official-path fetch (rich notes/links) would lose all of that the
    very next time collect_docs_catalog() re-scraped it with just notes=("release-notes",)."""

    def test_rich_notes_and_links_survive_a_sparse_daily_rescrape(self):
        base = make_firmware_state([{
            "version": "7.2.11", "build": "2000", "maturity": "Mature",
            "notes": ["release-notes", "resolved", "known", "upgrade", "behavior"],
            "links": {
                "release-notes": "https://docs.fortinet.com/document/fortigate/7.2.11/fortios-release-notes",
                "resolved": "https://x/resolved",
                "known": "https://x/known",
                "upgrade": "https://x/upgrade",
                "behavior": "https://x/behavior",
            },
        }])

        # A sparse daily re-scrape, exactly as collect_docs_catalog() always builds it.
        incoming = fw.normalize_state({})
        fw.upsert_firmware(incoming, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="7.2.11", build="2000",
            notes=("release-notes",),
            links={"release-notes": "https://docs.fortinet.com/document/fortigate/7.2.11/fortios-release-notes"},
        ))

        merged = fw.merge_state(base, incoming)
        result = merged["products"][0]["models"][0]["firmwares"][0]

        self.assertEqual(
            set(result["notes"]), {"release-notes", "resolved", "known", "upgrade", "behavior"},
            "rich notes must survive a sparse re-scrape",
        )
        self.assertEqual(
            set(result["links"]), {"release-notes", "resolved", "known", "upgrade", "behavior"},
            "rich links must survive a sparse re-scrape",
        )
        self.assertEqual(result["maturity"], "Mature")
        self.assertEqual(result["build"], "2000")

    def test_new_note_and_link_keys_are_added_not_just_preserved(self):
        base = make_firmware_state([{
            "version": "7.2.11", "build": "2000",
            "notes": ["release-notes"],
            "links": {"release-notes": "https://x/release-notes"},
        }])
        incoming = fw.normalize_state({})
        fw.upsert_firmware(incoming, fw.Firmware(
            product="fortigate-fortios", model="FGT60F", version="7.2.11", build="2000",
            notes=("resolved",),
            links={"resolved": "https://x/resolved"},
        ))
        merged = fw.merge_state(base, incoming)
        result = merged["products"][0]["models"][0]["firmwares"][0]
        self.assertEqual(set(result["notes"]), {"release-notes", "resolved"})
        self.assertEqual(set(result["links"]), {"release-notes", "resolved"})


class ConcurrentWriteTests(unittest.TestCase):
    """Reproduces the exact scenario Codex flagged: a live user creates/edits/deletes advisories,
    paths, and compatibilities while the daily collector script is mid-run (holding a stale
    start-of-run snapshot) — none of those concurrent changes may be lost, reverted, or
    resurrected by the collector's own final commit.
    """

    def test_concurrent_delete_edit_create_and_update_all_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "state.json"

            initial = fw.normalize_state({
                "advisories": [
                    {"id": "adv-A", "title": "A", "product": "fortigate-fortios", "severity": "high"},
                    {"id": "adv-B", "title": "B (deleted live)", "product": "fortigate-fortios", "severity": "critical"},
                    {"id": "adv-C", "title": "C (edited live)", "product": "fortigate-fortios", "severity": "info"},
                ],
                "paths": [{
                    "id": "path-1", "product": "fortigate-fortios", "model": "FGT60F",
                    "from": "7.2.10", "to": "7.4.8", "hops": ["7.2.10", "7.4.8"],
                    "source": "old", "fetchedAt": "2026-01-01T00:00:00Z",
                }],
                "compatibilities": [{
                    "id": "compat-1", "emsVersion": "7.2.4", "clientVersions": ["7.2.4"],
                    "note": "", "source": "x", "createdAt": "2026-01-01T00:00:00Z",
                }],
            })
            fw.write_json(output_path, initial)

            # Script "starts": reads its stale snapshot for the whole run.
            state = fw.normalize_state(fw.read_json(output_path, {}))

            # Meanwhile, a live user (fortios_server.py) deletes, edits, creates, and updates.
            with fw.cross_process_lock(output_path):
                live_state = fw.normalize_state(fw.read_json(output_path, {}))
                live_state["advisories"] = [a for a in live_state["advisories"] if a["id"] != "adv-B"]
                for advisory in live_state["advisories"]:
                    if advisory["id"] == "adv-C":
                        advisory["title"] = "C EDITED LIVE"
                fw.upsert_path(live_state, fw.UpgradePath(
                    product="fortigate-fortios", model="FGT60F", from_version="7.2.10", to_version="7.4.8",
                    hops=("7.2.10", "7.2.13", "7.4.8"), source="live refetch",
                ))
                fw.upsert_compatibility(live_state, {
                    "id": "compat-2-live", "emsVersion": "7.4.1", "clientVersions": ["7.4.1"],
                    "note": "added live during scan", "source": "x", "createdAt": fw.utc_now(),
                })
                fw.write_json(output_path, live_state)

            # Script "finishes": no advisory/path deltas of its own this run (nothing imported).
            with fw.cross_process_lock(output_path):
                latest_from_disk = fw.normalize_state(fw.read_json(output_path, {}))
                state_for_bulk_merge = {**state, "advisories": [], "paths": [], "compatibilities": []}
                final_state = fw.merge_state(latest_from_disk, state_for_bulk_merge)
                fw.write_json(output_path, final_state)

            result = fw.normalize_state(fw.read_json(output_path, {}))

            advisory_ids = sorted(a["id"] for a in result["advisories"])
            self.assertEqual(advisory_ids, ["adv-A", "adv-C"], "concurrent DELETE of adv-B must survive")

            adv_c_title = next(a["title"] for a in result["advisories"] if a["id"] == "adv-C")
            self.assertEqual(adv_c_title, "C EDITED LIVE", "concurrent EDIT must survive")

            # upsert_path() keys by (product, model, from, to), recomputing a canonical id.
            path_hops = next(
                p["hops"] for p in result["paths"]
                if p["model"] == "FGT60F" and p["from"] == "7.2.10" and p["to"] == "7.4.8"
            )
            self.assertEqual(path_hops, ["7.2.10", "7.2.13", "7.4.8"], "concurrent path UPDATE must survive")

            compat_ids = sorted(c["id"] for c in result["compatibilities"])
            self.assertEqual(compat_ids, ["compat-1", "compat-2-live"], "concurrent CREATE must survive")

    def test_delta_advisory_and_path_are_applied_alongside_concurrent_changes(self):
        """The collector's own genuine deltas (e.g. a CSV-imported advisory, an official-path
        fetch) must still land correctly even while unrelated concurrent live edits are also
        in flight."""
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "state.json"
            fw.write_json(output_path, fw.normalize_state({
                "advisories": [{"id": "adv-A", "title": "A", "product": "fortigate-fortios", "severity": "high"}],
            }))

            state = fw.normalize_state(fw.read_json(output_path, {}))
            advisory_deltas = [{"id": "adv-D", "title": "D (imported via CSV this run)", "product": "fortigate-fortios", "severity": "important"}]
            path_deltas = [fw.UpgradePath(
                product="fortigate-fortios", model="FGT60F", from_version="6.4.7", to_version="7.0.14",
                hops=("6.4.7", "7.0.14"), source="official path request",
            )]

            with fw.cross_process_lock(output_path):
                live_state = fw.normalize_state(fw.read_json(output_path, {}))
                fw.upsert_advisory(live_state, {"id": "adv-E", "title": "E (added live)", "product": "fortigate-fortios", "severity": "info"})
                fw.write_json(output_path, live_state)

            with fw.cross_process_lock(output_path):
                latest_from_disk = fw.normalize_state(fw.read_json(output_path, {}))
                state_for_bulk_merge = {**state, "advisories": [], "paths": [], "compatibilities": []}
                final_state = fw.merge_state(latest_from_disk, state_for_bulk_merge)
                for advisory in advisory_deltas:
                    fw.upsert_advisory(final_state, advisory)
                for path in path_deltas:
                    fw.upsert_path(final_state, path)
                fw.write_json(output_path, final_state)

            result = fw.normalize_state(fw.read_json(output_path, {}))
            advisory_ids = sorted(a["id"] for a in result["advisories"])
            self.assertEqual(advisory_ids, ["adv-A", "adv-D", "adv-E"])
            self.assertEqual(len(result["paths"]), 1)
            self.assertEqual(result["paths"][0]["hops"], ["6.4.7", "7.0.14"])


class CrossProcessLockTests(unittest.TestCase):
    @staticmethod
    def _holder(lock_target: Path, hold_seconds: float, start_event, done_event) -> None:
        with fw.cross_process_lock(lock_target):
            start_event.set()
            time.sleep(hold_seconds)
        done_event.set()

    def test_lock_serializes_two_separate_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "state.json"
            target.write_text("{}")

            start_event = multiprocessing.Event()
            done_event = multiprocessing.Event()
            hold_seconds = 1.0
            proc = multiprocessing.Process(
                target=self._holder, args=(target, hold_seconds, start_event, done_event)
            )
            proc.start()
            self.assertTrue(start_event.wait(timeout=5), "child process never acquired the lock")

            started_waiting = time.monotonic()
            with fw.cross_process_lock(target):
                waited = time.monotonic() - started_waiting
            proc.join(timeout=5)

            self.assertGreaterEqual(
                waited, hold_seconds * 0.8,
                "main process should have blocked for roughly as long as the other process held the lock",
            )


if __name__ == "__main__":
    unittest.main()
