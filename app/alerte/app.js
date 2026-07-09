const GENERATED_DATA_URL = "../../data/fortios-data.generated.json";
const SEVERITY_ORDER = ["critical", "important", "warning", "info"];
const SEVERITY_LABEL = { critical: "Critique", important: "Importante", warning: "Avertissement", info: "Info" };

let allModels = [];
let allVersions = [];
let advisories = [];
let modelScope = "all";
let versionMode = "exact";
let editingId = null;
let severityFilter = "all";

const els = {
  title: document.getElementById("titleInput"),
  description: document.getElementById("descriptionInput"),
  severity: document.getElementById("severitySelect"),
  timing: document.getElementById("timingSelect"),
  command: document.getElementById("commandInput"),
  source: document.getElementById("sourceInput"),
  versionModeExactButton: document.getElementById("versionModeExactButton"),
  versionModeFromButton: document.getElementById("versionModeFromButton"),
  versionExactField: document.getElementById("versionExactField"),
  versionFromField: document.getElementById("versionFromField"),
  versionSearch: document.getElementById("versionSearch"),
  versionList: document.getElementById("versionList"),
  minVersionSearch: document.getElementById("minVersionSearch"),
  minVersionList: document.getElementById("minVersionList"),
  scopeAllButton: document.getElementById("scopeAllButton"),
  scopeSomeButton: document.getElementById("scopeSomeButton"),
  modelPickerField: document.getElementById("modelPickerField"),
  modelSearch: document.getElementById("modelSearch"),
  modelList: document.getElementById("modelList"),
  submitButton: document.getElementById("submitButton"),
  submitButtonLabel: document.getElementById("submitButtonLabel"),
  cancelEditButton: document.getElementById("cancelEditButton"),
  formMessage: document.getElementById("formMessage"),
  advisorySearch: document.getElementById("advisorySearch"),
  severityFilterGroup: document.getElementById("severityFilterGroup"),
  advisoryList: document.getElementById("advisoryList")
};

els.scopeAllButton.addEventListener("click", () => setScope("all"));
els.scopeSomeButton.addEventListener("click", () => setScope("some"));
els.versionModeExactButton.addEventListener("click", () => setVersionMode("exact"));
els.versionModeFromButton.addEventListener("click", () => setVersionMode("from"));
els.versionSearch.addEventListener("input", () => renderVersionList());
els.minVersionSearch.addEventListener("input", () => renderMinVersionList());
els.modelSearch.addEventListener("input", () => renderModelList());
els.submitButton.addEventListener("click", submitAdvisory);
els.cancelEditButton.addEventListener("click", cancelEdit);
els.advisorySearch.addEventListener("input", () => renderAdvisoryList());
for (const button of els.severityFilterGroup.querySelectorAll("[data-severity-filter]")) {
  button.addEventListener("click", () => setSeverityFilter(button.dataset.severityFilter));
}

init();

async function init() {
  setText(els.advisoryList, "Chargement...", "empty");
  try {
    const response = await fetch(GENERATED_DATA_URL, { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const state = await response.json();
    loadState(state);
  } catch (error) {
    setText(
      els.advisoryList,
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
  const product = (state.products || [])[0] || { models: [] };
  allModels = (product.models || [])
    .map(model => ({ id: model.id, label: model.label || model.id }))
    .sort((a, b) => a.id.localeCompare(b.id));

  const versionSet = new Set();
  for (const model of product.models || []) {
    for (const firmware of model.firmwares || []) {
      if (firmware.version) versionSet.add(firmware.version);
    }
  }
  allVersions = Array.from(versionSet).sort(compareVersions).reverse();

  advisories = Array.isArray(state.advisories) ? state.advisories : [];

  renderVersionList();
  renderModelList();
  renderMinVersionList();
  renderAdvisoryList();
}

function setScope(scope) {
  modelScope = scope;
  els.scopeAllButton.classList.toggle("active", scope === "all");
  els.scopeSomeButton.classList.toggle("active", scope === "some");
  els.modelPickerField.classList.toggle("hidden", scope === "all");
}

function setVersionMode(mode) {
  versionMode = mode;
  els.versionModeExactButton.classList.toggle("active", mode === "exact");
  els.versionModeFromButton.classList.toggle("active", mode === "from");
  els.versionExactField.classList.toggle("hidden", mode !== "exact");
  els.versionFromField.classList.toggle("hidden", mode !== "from");
}

function setSeverityFilter(severity) {
  severityFilter = severity;
  for (const button of els.severityFilterGroup.querySelectorAll("[data-severity-filter]")) {
    button.classList.toggle("active", button.dataset.severityFilter === severity);
  }
  renderAdvisoryList();
}

function renderMinVersionList() {
  const filter = normalizeSearch(els.minVersionSearch.value);
  const checked = new Set(getCheckedValues(els.minVersionList));
  const visible = allVersions.filter(version => !filter || normalizeSearch(version).includes(filter));

  els.minVersionList.replaceChildren();
  if (!visible.length) {
    els.minVersionList.appendChild(el("span", { className: "hint", text: "Aucune version ne correspond au filtre." }));
    return;
  }
  for (const version of visible) {
    els.minVersionList.appendChild(checkboxRow(version, version, checked.has(version)));
  }
}

function renderVersionList() {
  const filter = normalizeSearch(els.versionSearch.value);
  const checked = new Set(getCheckedValues(els.versionList));
  const visible = allVersions.filter(version => !filter || normalizeSearch(version).includes(filter));

  els.versionList.replaceChildren();
  if (!visible.length) {
    els.versionList.appendChild(el("span", { className: "hint", text: "Aucune version ne correspond au filtre." }));
    return;
  }
  for (const version of visible) {
    els.versionList.appendChild(checkboxRow(version, version, checked.has(version)));
  }
}

function renderModelList() {
  const filter = normalizeSearch(els.modelSearch.value);
  const checked = new Set(getCheckedValues(els.modelList));
  const visible = allModels.filter(model => !filter || normalizeSearch(model.id + model.label).includes(filter));

  els.modelList.replaceChildren();
  if (!visible.length) {
    els.modelList.appendChild(el("span", { className: "hint", text: "Aucun modèle ne correspond au filtre." }));
    return;
  }
  for (const model of visible) {
    els.modelList.appendChild(checkboxRow(model.id, model.label, checked.has(model.id)));
  }
}

function checkboxRow(value, labelText, checked) {
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.value = value;
  checkbox.checked = checked;
  const label = document.createElement("label");
  label.appendChild(checkbox);
  label.appendChild(document.createTextNode(" " + labelText));
  return label;
}

function setCheckedValues(container, values) {
  const wanted = new Set(values);
  for (const input of container.querySelectorAll("input[type=checkbox]")) {
    input.checked = wanted.has(input.value);
  }
}

function getCheckedValues(container) {
  return Array.from(container.querySelectorAll("input[type=checkbox]:checked")).map(input => input.value);
}

async function submitAdvisory() {
  const title = els.title.value.trim();
  const description = els.description.value.trim();
  const versions = versionMode === "exact" ? getCheckedValues(els.versionList) : [];
  const minVersions = versionMode === "from" ? getCheckedValues(els.minVersionList) : [];
  const models = modelScope === "some" ? getCheckedValues(els.modelList) : [];

  if (!title || !description) {
    els.formMessage.textContent = "Titre et description sont obligatoires.";
    return;
  }
  if (versionMode === "exact" && !versions.length) {
    els.formMessage.textContent = "Cocher au moins une version FortiOS concernée.";
    return;
  }
  if (versionMode === "from" && !minVersions.length) {
    els.formMessage.textContent = "Cocher au moins un point de départ.";
    return;
  }
  if (modelScope === "some" && !models.length) {
    els.formMessage.textContent = "Cocher au moins un boîtier, ou choisir Tous les boîtiers.";
    return;
  }

  const isEdit = Boolean(editingId);
  els.submitButton.disabled = true;
  els.formMessage.textContent = isEdit ? "Enregistrement en cours..." : "Publication en cours...";
  try {
    const response = await fetch(isEdit ? `/api/advisories/${encodeURIComponent(editingId)}` : "/api/advisories", {
      method: isEdit ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title,
        description,
        severity: els.severity.value,
        timing: els.timing.value,
        versions,
        minVersions,
        models,
        command: els.command.value.trim(),
        source: els.source.value.trim()
      })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Service local indisponible.");

    advisories = payload.state.advisories || advisories;
    renderAdvisoryList();
    resetForm();
    els.formMessage.textContent = isEdit ? "Alerte mise à jour." : "Alerte publiée.";
  } catch (error) {
    els.formMessage.textContent = `Publication impossible : ${error.message}. Lancer l'interface avec scripts/fortios_server.py.`;
  } finally {
    els.submitButton.disabled = false;
  }
}

function startEdit(item) {
  editingId = item.id;
  els.title.value = item.title || "";
  els.description.value = item.description || "";
  els.severity.value = item.severity || "important";
  els.timing.value = item.timing || "post-upgrade";
  els.command.value = item.command || "";
  els.source.value = item.source || "";

  const minVersions = advisoryMinVersions(item);
  if (minVersions.length) {
    setVersionMode("from");
    els.minVersionSearch.value = "";
    renderMinVersionList();
    setCheckedValues(els.minVersionList, minVersions);
  } else {
    setVersionMode("exact");
    els.versionSearch.value = "";
    renderVersionList();
    setCheckedValues(els.versionList, advisoryVersions(item));
  }

  if (Array.isArray(item.models) && item.models.length) {
    setScope("some");
    els.modelSearch.value = "";
    renderModelList();
    setCheckedValues(els.modelList, item.models);
  } else {
    setScope("all");
  }

  els.submitButtonLabel.textContent = "Enregistrer les modifications";
  els.cancelEditButton.classList.remove("hidden");
  els.formMessage.textContent = `Modification de "${item.title}".`;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function cancelEdit() {
  editingId = null;
  resetForm();
  els.formMessage.textContent = "Modification annulée.";
}

async function deleteAdvisory(item) {
  if (!window.confirm(`Supprimer l'alerte "${item.title}" ?`)) return;
  try {
    const response = await fetch(`/api/advisories/${encodeURIComponent(item.id)}`, { method: "DELETE" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Service local indisponible.");

    advisories = payload.state.advisories || advisories.filter(existing => existing.id !== item.id);
    if (editingId === item.id) cancelEdit();
    renderAdvisoryList();
    els.formMessage.textContent = "Alerte supprimée.";
  } catch (error) {
    els.formMessage.textContent = `Suppression impossible : ${error.message}.`;
  }
}

function resetForm() {
  editingId = null;
  els.title.value = "";
  els.description.value = "";
  els.command.value = "";
  els.source.value = "";
  els.severity.value = "important";
  els.timing.value = "post-upgrade";
  els.versionSearch.value = "";
  els.minVersionSearch.value = "";
  els.modelSearch.value = "";
  setScope("all");
  setVersionMode("exact");
  renderVersionList();
  renderMinVersionList();
  renderModelList();
  els.submitButtonLabel.textContent = "Publier l'alerte";
  els.cancelEditButton.classList.add("hidden");
}

function filteredAdvisories() {
  const query = normalizeSearch(els.advisorySearch.value);
  return advisories.filter(item => {
    if (severityFilter !== "all" && item.severity !== severityFilter) return false;
    if (!query) return true;

    const haystack = normalizeSearch(
      [
        item.title,
        item.description,
        ...advisoryVersions(item),
        ...advisoryMinVersions(item),
        ...(Array.isArray(item.models) ? item.models : [])
      ]
        .filter(Boolean)
        .join(" ")
    );
    return haystack.includes(query);
  });
}

function renderAdvisoryList() {
  els.advisoryList.replaceChildren();

  if (!advisories.length) {
    els.advisoryList.appendChild(el("div", { className: "empty", text: "Aucune alerte interne publiée pour l'instant." }));
    return;
  }

  const visible = filteredAdvisories();
  if (!visible.length) {
    els.advisoryList.appendChild(el("div", { className: "empty", text: "Aucune alerte ne correspond au filtre." }));
    return;
  }

  const bySeverity = new Map(SEVERITY_ORDER.map(severity => [severity, []]));
  for (const item of visible) {
    const bucket = bySeverity.has(item.severity) ? item.severity : "info";
    bySeverity.get(bucket).push(item);
  }

  for (const severity of SEVERITY_ORDER) {
    const items = bySeverity.get(severity);
    if (!items.length) continue;

    const sorted = [...items].sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
    const header = el("h3", { className: "section-title", text: `${SEVERITY_LABEL[severity]} (${sorted.length})` });
    els.advisoryList.appendChild(header);
    for (const item of sorted) {
      els.advisoryList.appendChild(advisoryCard(item));
    }
  }
}

function advisoryCard(item) {
  const head = el("div", { className: "callout-head" });
  head.appendChild(el("h4", { className: "callout-title", text: item.title }));
  head.appendChild(el("span", { className: `badge ${badgeClass(item.severity)}`, text: timingLabel(item.timing) }));

  const description = el("p", { text: item.description });

  const minVersions = advisoryMinVersions(item);
  const versionsLabel = minVersions.length
    ? minVersions.map(version => `${version}+`).join(", ")
    : advisoryVersions(item).join(", ") || "-";
  const modelsScope = Array.isArray(item.models) && item.models.length ? item.models.join(", ") : "Tous";
  const meta = el("p", { className: "hint" });
  meta.textContent = `Versions : ${versionsLabel} • Boîtiers : ${modelsScope} • Source : ${item.source || "-"}`;

  const article = el("article", { className: `advisory-row callout ${calloutClass(item.severity)}` });
  article.appendChild(head);
  article.appendChild(description);
  article.appendChild(meta);

  if (item.command) {
    const pre = el("pre", { text: item.command });
    const codebox = el("div", { className: "codebox" });
    codebox.appendChild(pre);
    article.appendChild(codebox);
  }

  const actions = el("div", { className: "code-actions" });
  const editButton = el("button", { className: "mini", text: "Modifier" });
  editButton.type = "button";
  editButton.addEventListener("click", () => startEdit(item));
  const deleteButton = el("button", { className: "mini", text: "Supprimer" });
  deleteButton.type = "button";
  deleteButton.addEventListener("click", () => deleteAdvisory(item));
  actions.appendChild(editButton);
  actions.appendChild(deleteButton);
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

function badgeClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "ok";
}

function calloutClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "";
}

function timingLabel(timing) {
  return {
    "pre-upgrade": "Avant upgrade",
    "during-upgrade": "Pendant",
    "post-upgrade": "Après upgrade"
  }[timing] || "Info";
}
