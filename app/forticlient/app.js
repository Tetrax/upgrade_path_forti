const GENERATED_DATA_URL = "../../data/fortios-data.generated.json";
const CLIENT_PLATFORM_IDS = ["windows", "macos", "linux"];
const FORTICLIENT_PRODUCT_IDS = ["forticlient", "forticlient-ems"];
const SEVERITY_LABEL = { critical: "Critique", important: "Importante", warning: "Avertissement", info: "Info" };
const CVE_SEVERITY_LABEL = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };

let emsVersions = [];
let clientVersions = [];
let compatibilities = [];
let advisories = [];
let cves = [];
let productLabels = {};
let editingId = null;
// Source of truth for which checkboxes are checked, kept outside the DOM — see the identical
// pattern (and the bug it fixes) in app/alerte/app.js.
let checkedClientVersions = new Set();

const els = {
  briefingPanel: document.getElementById("briefingPanel"),
  emsVersionSelect: document.getElementById("emsVersionSelect"),
  clientVersionSearch: document.getElementById("clientVersionSearch"),
  clientVersionList: document.getElementById("clientVersionList"),
  note: document.getElementById("noteInput"),
  source: document.getElementById("sourceInput"),
  submitButton: document.getElementById("submitButton"),
  submitButtonLabel: document.getElementById("submitButtonLabel"),
  cancelEditButton: document.getElementById("cancelEditButton"),
  formMessage: document.getElementById("formMessage"),
  compatSearch: document.getElementById("compatSearch"),
  compatList: document.getElementById("compatList"),
  advisoryList: document.getElementById("advisoryList"),
  windowsVersionSummary: document.getElementById("windowsVersionSummary"),
  macosVersionSummary: document.getElementById("macosVersionSummary"),
  linuxVersionSummary: document.getElementById("linuxVersionSummary"),
  emsVersionSummary: document.getElementById("emsVersionSummary")
};

els.clientVersionSearch.addEventListener("input", () => renderClientVersionList());
els.submitButton.addEventListener("click", submitCompatibility);
els.cancelEditButton.addEventListener("click", cancelEdit);
els.compatSearch.addEventListener("input", () => renderCompatList());

init();

async function init() {
  setText(els.compatList, "Chargement...", "empty");
  try {
    const response = await fetch(GENERATED_DATA_URL, { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const state = await response.json();
    loadState(state);
  } catch (error) {
    setText(
      els.compatList,
      `Impossible de charger le catalogue (${error.message}). Lancer l'interface avec scripts/fortios_server.py.`,
      "empty"
    );
  }
}

function setText(container, text, className) {
  container.replaceChildren();
  const node = el("div", { className: className || "" });
  node.textContent = text;
  container.appendChild(node);
}

function loadState(state) {
  const products = Array.isArray(state.products) ? state.products : [];
  productLabels = Object.fromEntries(products.map(product => [product.id, product.label || product.id]));
  const fortclient = products.find(p => p.id === "forticlient") || { models: [] };
  const fortclientEms = products.find(p => p.id === "forticlient-ems") || { models: [] };

  const clientSet = new Set();
  for (const model of fortclient.models || []) {
    for (const firmware of model.firmwares || []) {
      if (firmware.version) clientSet.add(firmware.version);
    }
  }
  clientVersions = Array.from(clientSet).sort(compareVersions).reverse();

  const emsModel = (fortclientEms.models || [])[0] || { firmwares: [] };
  emsVersions = (emsModel.firmwares || [])
    .map(firmware => firmware.version)
    .filter(Boolean)
    .sort(compareVersions)
    .reverse();

  compatibilities = Array.isArray(state.compatibilities) ? state.compatibilities : [];
  advisories = (Array.isArray(state.advisories) ? state.advisories : [])
    .filter(item => FORTICLIENT_PRODUCT_IDS.includes(item.product));
  cves = (Array.isArray(state.cves) ? state.cves : [])
    .filter(cve => (cve.affected || []).some(range => FORTICLIENT_PRODUCT_IDS.includes(range.product)));

  populateEmsVersionSelect();
  renderClientVersionList();
  renderCompatList();
  renderAdvisoryList();
  renderVersionSummaries(fortclient, emsModel);
  renderBriefingPanel();
}

// Mirrors the FortiOS/FortiAnalyzer/FortiManager briefing bar on app/index.html, but scoped to
// FortiClient/EMS CVEs — those never show over there (see NO_PATH_PRODUCT_IDS filtering in
// app/index.html's latestCves()) since this page is the one place they belong.
const NEW_BADGE_WINDOW_DAYS = 14;

function isRecent(dateStr) {
  if (!dateStr) return false;
  const ageDays = (Date.now() - new Date(`${dateStr}T00:00:00Z`).getTime()) / 86400000;
  return ageDays >= 0 && ageDays <= NEW_BADGE_WINDOW_DAYS;
}

function latestCves(limit) {
  return [...cves]
    .sort((a, b) => (b.publishedAt || "").localeCompare(a.publishedAt || ""))
    .slice(0, limit);
}

function renderBriefingPanel() {
  if (!els.briefingPanel) return;
  els.briefingPanel.replaceChildren();
  els.briefingPanel.appendChild(el("span", { className: "briefing-label", text: "Dernières CVE" }));

  const latest = latestCves(6);
  if (!latest.length) {
    els.briefingPanel.appendChild(el("span", { className: "muted", text: "Aucune CVE connue pour FortiClient / EMS." }));
    return;
  }
  for (const cve of latest) {
    const scoreLabel = typeof cve.cvssScore === "number" ? ` CVSS ${cve.cvssScore}` : "";
    const badge = document.createElement("a");
    badge.className = `badge ${cveBadgeClass(cve.severity)}`;
    badge.href = cve.url;
    badge.target = "_blank";
    badge.rel = "noopener noreferrer";
    badge.title = `${cve.title} — ${CVE_SEVERITY_LABEL[cve.severity] || "Inconnue"}${scoreLabel}`;
    badge.appendChild(document.createTextNode(`🛡 ${cve.id}`));
    if (isRecent(cve.publishedAt)) {
      badge.appendChild(document.createTextNode(" "));
      badge.appendChild(el("span", { className: "new-badge", text: "New" }));
    }
    els.briefingPanel.appendChild(badge);
  }
}

function renderVersionSummaries(fortclient, emsModel) {
  for (const platform of CLIENT_PLATFORM_IDS) {
    const model = (fortclient.models || []).find(m => m.id === platform);
    const el = document.getElementById(`${platform}VersionSummary`);
    if (!model || !model.firmwares?.length) {
      el.textContent = "Aucune donnée";
      continue;
    }
    const versions = model.firmwares.map(f => f.version).sort(compareVersions);
    el.textContent = `${versions.length} versions (${versions[0]} → ${versions[versions.length - 1]})`;
  }
  if (!emsModel.firmwares?.length) {
    els.emsVersionSummary.textContent = "Aucune donnée";
  } else {
    const versions = emsModel.firmwares.map(f => f.version).sort(compareVersions);
    els.emsVersionSummary.textContent = `${versions.length} versions (${versions[0]} → ${versions[versions.length - 1]})`;
  }
}

function populateEmsVersionSelect() {
  els.emsVersionSelect.replaceChildren();
  for (const version of emsVersions) {
    const option = document.createElement("option");
    option.value = version;
    option.textContent = version;
    els.emsVersionSelect.appendChild(option);
  }
}

function renderClientVersionList() {
  const filter = normalizeSearch(els.clientVersionSearch.value);
  const visible = clientVersions.filter(version => !filter || normalizeSearch(version).includes(filter));

  els.clientVersionList.replaceChildren();
  if (!visible.length) {
    els.clientVersionList.appendChild(el("span", { className: "hint", text: "Aucune version ne correspond au filtre." }));
    return;
  }
  for (const version of visible) {
    els.clientVersionList.appendChild(checkboxRow(version, version, checkedClientVersions));
  }
}

// `checkedSet` is the persistent source of truth (see checkedClientVersions above) — the
// checkbox's own DOM `checked` property is just a view onto it for whatever's currently rendered.
function checkboxRow(value, labelText, checkedSet) {
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.value = value;
  checkbox.checked = checkedSet.has(value);
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) checkedSet.add(value);
    else checkedSet.delete(value);
  });
  const label = document.createElement("label");
  label.appendChild(checkbox);
  label.appendChild(document.createTextNode(" " + labelText));
  return label;
}

function setCheckedValues(checkedSet, values) {
  checkedSet.clear();
  for (const value of values) checkedSet.add(value);
}

async function submitCompatibility() {
  const emsVersion = els.emsVersionSelect.value;
  const clientVersionsChecked = Array.from(checkedClientVersions);

  if (!emsVersion) {
    els.formMessage.textContent = "Choisir une version FortiClient EMS.";
    return;
  }
  if (!clientVersionsChecked.length) {
    els.formMessage.textContent = "Cocher au moins une version FortiClient compatible.";
    return;
  }

  const isEdit = Boolean(editingId);
  els.submitButton.disabled = true;
  els.formMessage.textContent = isEdit ? "Enregistrement en cours..." : "Publication en cours...";
  try {
    const response = await fetch(isEdit ? `/api/compatibilities/${encodeURIComponent(editingId)}` : "/api/compatibilities", {
      method: isEdit ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        emsVersion,
        clientVersions: clientVersionsChecked,
        note: els.note.value.trim(),
        source: els.source.value.trim()
      })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Service local indisponible.");

    compatibilities = payload.state.compatibilities || compatibilities;
    renderCompatList();
    resetForm();
    els.formMessage.textContent = isEdit ? "Combinaison mise à jour." : "Combinaison enregistrée.";
  } catch (error) {
    els.formMessage.textContent = `Enregistrement impossible : ${error.message}. Lancer l'interface avec scripts/fortios_server.py.`;
  } finally {
    els.submitButton.disabled = false;
  }
}

function startEdit(item) {
  editingId = item.id;
  els.emsVersionSelect.value = item.emsVersion || "";
  els.clientVersionSearch.value = "";
  setCheckedValues(checkedClientVersions, item.clientVersions || []);
  renderClientVersionList();
  els.note.value = item.note || "";
  els.source.value = item.source || "";

  els.submitButtonLabel.textContent = "Enregistrer les modifications";
  els.cancelEditButton.classList.remove("hidden");
  els.formMessage.textContent = `Modification de la combinaison EMS ${item.emsVersion}.`;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function cancelEdit() {
  editingId = null;
  resetForm();
  els.formMessage.textContent = "Modification annulée.";
}

async function deleteCompatibility(item) {
  if (!window.confirm(`Supprimer la combinaison EMS ${item.emsVersion} / FortiClient ${item.clientVersions.join(", ")} ?`)) return;
  try {
    const response = await fetch(`/api/compatibilities/${encodeURIComponent(item.id)}`, { method: "DELETE" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Service local indisponible.");

    compatibilities = payload.state.compatibilities || compatibilities.filter(existing => existing.id !== item.id);
    if (editingId === item.id) cancelEdit();
    renderCompatList();
    els.formMessage.textContent = "Combinaison supprimée.";
  } catch (error) {
    els.formMessage.textContent = `Suppression impossible : ${error.message}.`;
  }
}

function resetForm() {
  editingId = null;
  els.clientVersionSearch.value = "";
  checkedClientVersions.clear();
  renderClientVersionList();
  els.note.value = "";
  els.source.value = "";
  els.submitButtonLabel.textContent = "Enregistrer";
  els.cancelEditButton.classList.add("hidden");
}

function filteredCompatibilities() {
  const query = normalizeSearch(els.compatSearch.value);
  if (!query) return compatibilities;
  return compatibilities.filter(item => {
    const haystack = normalizeSearch(
      [item.emsVersion, ...(item.clientVersions || []), item.note, item.source].filter(Boolean).join(" ")
    );
    return haystack.includes(query);
  });
}

function renderCompatList() {
  els.compatList.replaceChildren();
  if (!compatibilities.length) {
    els.compatList.appendChild(el("div", { className: "empty", text: "Aucune combinaison enregistrée pour l'instant." }));
    return;
  }

  const visible = filteredCompatibilities();
  if (!visible.length) {
    els.compatList.appendChild(el("div", { className: "empty", text: "Aucune combinaison ne correspond au filtre." }));
    return;
  }

  const sorted = [...visible].sort((a, b) => compareVersions(b.emsVersion || "", a.emsVersion || ""));
  for (const item of sorted) {
    els.compatList.appendChild(compatCard(item));
  }
}

function compatCard(item) {
  const head = el("div", { className: "callout-head" });
  head.appendChild(el("h4", { className: "callout-title", text: `EMS ${item.emsVersion}` }));
  head.appendChild(el("span", { className: "badge ok", text: `${(item.clientVersions || []).length} version(s) FortiClient` }));

  const relatedAdvisories = advisoriesForCompat(item);
  for (const advisory of relatedAdvisories) {
    const label = advisory.bugId ? `⚠ ${advisory.title} · #${advisory.bugId}` : `⚠ ${advisory.title}`;
    head.appendChild(el("span", { className: `badge ${badgeClass(advisory.severity)}`, text: label }));
  }

  const relatedCves = cvesForCompat(item);
  for (const cve of relatedCves) {
    head.appendChild(el("span", { className: `badge ${cveBadgeClass(cve.severity)}`, text: `🛡 ${cve.id}` }));
  }

  const versionsLine = el("p", { text: `FortiClient : ${(item.clientVersions || []).join(", ") || "-"}` });

  const meta = el("p", { className: "hint", text: `Source : ${item.source || "-"}` });

  const article = el("article", { className: "advisory-row callout" });
  article.appendChild(head);
  article.appendChild(versionsLine);
  if (item.note) article.appendChild(el("p", { className: "hint", text: item.note }));
  article.appendChild(meta);

  for (const advisory of relatedAdvisories) {
    article.appendChild(relatedAdvisoryDetail(advisory));
  }
  for (const cve of relatedCves) {
    article.appendChild(relatedCveDetail(cve));
  }

  const actions = el("div", { className: "code-actions" });
  const editButton = el("button", { className: "mini", text: "Modifier" });
  editButton.type = "button";
  editButton.addEventListener("click", () => startEdit(item));
  const deleteButton = el("button", { className: "mini", text: "Supprimer" });
  deleteButton.type = "button";
  deleteButton.addEventListener("click", () => deleteCompatibility(item));
  actions.appendChild(editButton);
  actions.appendChild(deleteButton);
  article.appendChild(actions);

  return article;
}

function renderAdvisoryList() {
  els.advisoryList.replaceChildren();
  if (!advisories.length) {
    els.advisoryList.appendChild(el("div", { className: "empty", text: "Aucune alerte interne pour FortiClient / FortiClient EMS pour l'instant." }));
    return;
  }

  const sorted = [...advisories].sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
  for (const item of sorted) {
    els.advisoryList.appendChild(advisoryCard(item));
  }
}

function advisoryCard(item) {
  const head = el("div", { className: "callout-head" });
  head.appendChild(el("h4", { className: "callout-title", text: item.title }));
  head.appendChild(el("span", { className: `badge ${badgeClass(item.severity)}`, text: SEVERITY_LABEL[item.severity] || "Info" }));
  if (item.behaviorChange) {
    head.appendChild(el("span", { className: "badge info", text: "⚙ Comportement par défaut" }));
  }

  const description = el("div", { className: "rich-text" });
  renderRichText(description, item.description);

  const minVersions = advisoryMinVersions(item);
  const versionsLabel = minVersions.length
    ? minVersions.map(version => `${version}+`).join(", ")
    : advisoryVersions(item).join(", ") || "-";
  const modelsScope = Array.isArray(item.models) && item.models.length ? item.models.join(", ") : "Tous";
  const meta = el("p", { className: "hint" });
  meta.textContent = `${productLabels[item.product] || item.product} • Versions : ${versionsLabel} • Boîtiers : ${modelsScope} • Source : ${item.source || "-"}`;

  const article = el("article", { className: `advisory-row callout ${calloutClass(item.severity)}` });
  article.appendChild(head);
  article.appendChild(description);
  article.appendChild(meta);

  if (item.bugId) {
    article.appendChild(el("p", { className: "hint", text: `Bug ID : ${item.bugId}${item.bugVersion ? ` (identifié en ${item.bugVersion})` : ""}` }));
  }
  if (item.command) {
    const pre = el("pre", { text: item.command });
    const codebox = el("div", { className: "codebox" });
    codebox.appendChild(pre);
    article.appendChild(codebox);
  }

  const actions = el("div", { className: "code-actions" });
  const manageLink = document.createElement("a");
  manageLink.className = "mini";
  manageLink.href = `../alerte/?product=${encodeURIComponent(item.product)}`;
  manageLink.textContent = "Modifier dans Alertes internes";
  actions.appendChild(manageLink);
  article.appendChild(actions);

  return article;
}

function advisoryVersions(advisory) {
  if (Array.isArray(advisory.versions)) return advisory.versions;
  return advisory.version ? [advisory.version] : [];
}

function advisoryMinVersions(advisory) {
  if (Array.isArray(advisory.minVersions)) return advisory.minVersions;
  return advisory.minVersion ? [advisory.minVersion] : [];
}

function branchOf(version) {
  return version.split(".").slice(0, 2).join(".");
}

function sameTrain(a, b) {
  return branchOf(a) === branchOf(b);
}

// Same threshold semantics as the main app (once a "from version" change ships, it stays in
// effect), but without the path-relative "from" gating — a compatibility combo isn't an upgrade,
// just a version, so there's no "before/after this upgrade" to reason about here.
function advisoryMatchesVersionSimple(advisory, version) {
  const thresholds = advisoryMinVersions(advisory);
  if (thresholds.length) {
    return thresholds.some(threshold =>
      sameTrain(version, threshold) ? compareVersions(version, threshold) >= 0 : compareVersions(branchOf(version), branchOf(threshold)) > 0
    );
  }
  return advisoryVersions(advisory).includes(version);
}

// Same range shape as scripts/fortios_watch.py's CVE collector: a branch with no from/to means
// the whole train is affected (Fortinet's CSAF phrases that as "X.Y all versions").
function cveMatchesVersion(cve, product, model, version) {
  return (cve.affected || []).some(range => {
    if (range.product !== product) return false;
    if (Array.isArray(range.models) && range.models.length && !range.models.includes(model)) return false;
    if (branchOf(version) !== range.branch) return false;
    if (!range.from && !range.to) return true;
    if (range.from && compareVersions(version, range.from) < 0) return false;
    if (range.to && compareVersions(version, range.to) > 0) return false;
    return true;
  });
}

function cvesForCompat(item) {
  const matches = [];
  for (const cve of cves) {
    if (cveMatchesVersion(cve, "forticlient-ems", "ems", item.emsVersion)) {
      matches.push(cve);
      continue;
    }
    // A compat combo just lists FortiClient versions without a platform, so a version is
    // flagged if it's affected on ANY platform (windows/macos/linux) — better to over-warn.
    if ((item.clientVersions || []).some(v => CLIENT_PLATFORM_IDS.some(platform => cveMatchesVersion(cve, "forticlient", platform, v)))) {
      matches.push(cve);
    }
  }
  return matches;
}

function cveBadgeClass(severity) {
  return { critical: "danger", high: "danger", medium: "warn", low: "info" }[severity] || "ok";
}

function cveSeverityToInternal(severity) {
  return { critical: "critical", high: "important", medium: "warning", low: "info" }[severity] || "info";
}

function relatedCveDetail(cve) {
  const wrapper = el("div", { className: `callout ${calloutClass(cveSeverityToInternal(cve.severity))}` });
  const head = el("div", { className: "callout-head" });
  head.appendChild(el("h4", { className: "callout-title", text: cve.title }));
  const scoreLabel = typeof cve.cvssScore === "number" ? ` (CVSS ${cve.cvssScore})` : "";
  head.appendChild(
    el("span", {
      className: `badge ${cveBadgeClass(cve.severity)}`,
      text: `${cve.id} · ${CVE_SEVERITY_LABEL[cve.severity] || "Inconnue"}${scoreLabel}`
    })
  );
  wrapper.appendChild(head);

  const link = document.createElement("a");
  link.className = "hint";
  link.href = cve.url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = `${cve.advisoryId} — fiche PSIRT Fortinet ↗`;
  wrapper.appendChild(link);

  return wrapper;
}

function advisoriesForCompat(item) {
  const matches = [];
  for (const advisory of advisories) {
    if (advisory.product === "forticlient-ems" && advisoryMatchesVersionSimple(advisory, item.emsVersion)) {
      matches.push(advisory);
      continue;
    }
    if (advisory.product === "forticlient" && (item.clientVersions || []).some(v => advisoryMatchesVersionSimple(advisory, v))) {
      matches.push(advisory);
    }
  }
  return matches;
}

function relatedAdvisoryDetail(advisory) {
  const wrapper = el("div", { className: `callout ${calloutClass(advisory.severity)}` });
  const head = el("div", { className: "callout-head" });
  head.appendChild(el("h4", { className: "callout-title", text: advisory.title }));
  head.appendChild(el("span", { className: `badge ${badgeClass(advisory.severity)}`, text: SEVERITY_LABEL[advisory.severity] || "Info" }));
  wrapper.appendChild(head);

  const description = el("div", { className: "rich-text" });
  renderRichText(description, advisory.description);
  wrapper.appendChild(description);

  if (advisory.command) {
    const pre = el("pre", { text: advisory.command });
    const codebox = el("div", { className: "codebox" });
    codebox.appendChild(pre);
    wrapper.appendChild(codebox);
  }

  return wrapper;
}

function badgeClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "ok";
}

function calloutClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "";
}

// Lightweight formatting markup: **bold**, __underline__, "- " bullet lines, blank line = new
// paragraph, ![alt](url) images. Always builds real DOM nodes (never innerHTML).
function renderRichText(container, text) {
  container.replaceChildren();
  if (!text) return;
  const lines = String(text).split("\n");
  let i = 0;
  while (i < lines.length) {
    if (lines[i].trim() === "") {
      i += 1;
      continue;
    }
    if (lines[i].startsWith("- ")) {
      const list = document.createElement("ul");
      while (i < lines.length && lines[i].startsWith("- ")) {
        const item = document.createElement("li");
        appendInlineRich(item, lines[i].slice(2));
        list.appendChild(item);
        i += 1;
      }
      container.appendChild(list);
      continue;
    }
    const paragraph = document.createElement("p");
    let first = true;
    while (i < lines.length && lines[i].trim() !== "" && !lines[i].startsWith("- ")) {
      if (!first) paragraph.appendChild(document.createElement("br"));
      appendInlineRich(paragraph, lines[i]);
      first = false;
      i += 1;
    }
    container.appendChild(paragraph);
  }
}

// Only http(s) and same-origin-relative URLs are ever turned into a real link/image — a
// javascript:/data: URI typed into a description would otherwise run as script the moment
// anyone clicked the resulting "image" link (data: URIs open as a full HTML document).
function isSafeUrl(url) {
  try {
    return ["http:", "https:"].includes(new URL(url, window.location.href).protocol);
  } catch {
    return false;
  }
}

function appendInlineRich(parent, text) {
  const pattern = /\*\*(.+?)\*\*|__(.+?)__|!\[(.*?)\]\((.*?)\)/g;
  let lastIndex = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > lastIndex) parent.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    if (match[4] !== undefined) {
      if (!isSafeUrl(match[4])) {
        parent.appendChild(document.createTextNode(match[0]));
        lastIndex = match.index + match[0].length;
        continue;
      }
      const link = document.createElement("a");
      link.href = match[4];
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      const img = document.createElement("img");
      img.src = match[4];
      img.alt = match[3] || "capture";
      img.loading = "lazy";
      link.appendChild(img);
      parent.appendChild(link);
    } else {
      const node = document.createElement(match[1] !== undefined ? "strong" : "u");
      node.textContent = match[1] !== undefined ? match[1] : match[2];
      parent.appendChild(node);
    }
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) parent.appendChild(document.createTextNode(text.slice(lastIndex)));
}

function el(tag, options) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  return node;
}

function compareVersions(a, b) {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const diff = (left[i] || 0) - (right[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function normalizeSearch(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "");
}
