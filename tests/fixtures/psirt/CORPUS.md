# PSIRT CSAF fixtures — provenance and observations

Frozen real documents used by `tests/test_csaf_applicability.py` and
`tests/test_cve_reconciliation.py`. All were fetched from Fortinet's public PSIRT endpoints
(`fortiguard.fortinet.com` / `filestore.fortinet.com`) on 2026-10-04; the file-store URLs are
the ones each advisory page advertised at capture time (they embed a slugified title and are
not guessable — that is why the collector discovers them from the page instead of hardcoding).

## The defect case

- `FG-IR-26-174.advisory.html` — the real advisory page (`https://fortiguard.fortinet.com/psirt/FG-IR-26-174`).
- `FG-IR-26-174.csaf.json` — `https://filestore.fortinet.com/fortiguard/psirt/csaf_ztna-portal-improper-certificate-validation_fg-ir-26-174.json`.
  Official matrix: FortiOS `>=7.6.1|<=7.6.6` affected; 7.2/7.4/8.0 all versions and 7.6.7 NOT
  affected; CVE-2026-84393, High, CVSS 7.3.
- `FG-IR-26-174.cvrf.xml` — `https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-26-174`, kept as
  the witness of the old, coarse feed (whole trains "Known Affected", no bounds) that produced
  the false positives. Not used by the collector anymore.

## Corpus (contrasted ranges / branches / products)

| Advisory | CSAF URL (filestore.fortinet.com/fortiguard/psirt/) | Observed tracked applicability |
| --- | --- | --- |
| FG-IR-26-174 | csaf_ztna-portal-improper-certificate-validation_fg-ir-26-174.json | FortiOS 7.6.1–7.6.6 (bounds + not-affected 7.6.7) |
| FG-IR-26-165 | csaf_arbitrary-process-termination-from-exposed-minifilter-communication-port_fg-ir-26-165.json | FortiClientWindows: 7.2 all versions, 7.4.0–7.4.7 |
| FG-IR-26-171 | csaf_workflow-session-email-approval-process-bypass_fg-ir-26-171.json | FortiManager: 7.2 all versions, 7.4.0–7.4.10, 7.6.0–7.6.4 ("FortiManager Cloud" values ignored) |
| FG-IR-26-172 | csaf_uncontrolled-resource-consumption-in-snmp_fg-ir-26-172.json | FortiAnalyzer: 7.6.3–7.6.6 |
| FG-IR-26-154 | csaf_buffer-overread-in-authd-and-wad-daemon_fg-ir-26-154.json | FortiOS: 6.4/7.0/7.2 all versions, 7.4.0–7.4.8, 7.6.0–7.6.3 (2 CVEs) |
| FG-IR-26-162 | csaf_ui-dos-attack_fg-ir-26-162.json | FortiOS: 7.2/7.4 all versions, 7.6.0–7.6.6 |
| FG-IR-26-173 | csaf_null-pointer-dereference-in-log-report_fg-ir-26-173.json | FortiOS: 7.2/7.4 all versions (7.6/8.0 not affected) |

These were also validated over the real network through the collector itself (advisory id →
page → CSAF, no hand-fed URLs): 7/7 resolved; `FG-IR-22-059` (a legacy advisory whose page
still advertises no CSAF link at all) was correctly reported as *skipped — preserved*, never
as a confirmed empty list. This is a bounded corpus, not an exhaustive audit.

## Live catalogue copy

`catalog-live-2026-10-04.json` — minimized copy of the real production catalogue
(`generatedAt: 2026-10-04T20:28:28Z`, captured from the live deployment that day).

Kept real and public:

- all 33 CVE entries as stored at capture time (public Fortinet PSIRT data), including the
  pre-fix coarse entry for CVE-2026-84393 that the reconciliation tests repair;
- the FortiOS EOL lifecycle extract;
- the FortiGate 90G model entry (`FGT90G`) with the exact 7.2.10 / 7.2.13 / 7.4.12 firmwares,
  and the FortiGate 90G cached upgrade paths — this is what keeps the 90G scenario
  reproducible in the browser E2E (`tests/e2e/`);
- one representative model for each of the four other watched products.

Not published; replaced by synthetic placeholders (sections stay non-empty so the
reconciliation tests' section-preservation assertions keep meaning):

- `advisories` — the production entries are internal engineer notes (internal source, internal
  bug ids, operational details); replaced by one clearly marked synthetic placeholder;
- `compatibilities` — the production rows came from the internal EMS compatibility workflow;
  replaced by one synthetic placeholder;
- `searchHistory` — the production file held the team's real search history with real
  timestamps; emptied (no test needs it).

Every fixture in this directory comes from Fortinet's public PSIRT endpoints or from the
public upgrade-path tool, except the three synthetic placeholders above, which are visibly
marked "Fixture advisory"/"Test fixture (synthetic)" and contain no production data.
