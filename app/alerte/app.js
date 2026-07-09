const GENERATED_DATA_URL = "../../data/fortios-data.generated.json";
let allModels = [];
let allVersions = [];
let advisories = [];
let modelScope = "all";

const els = {
  title: document.getElementById("titleInput"),
  description: document.getElementById("descriptionInput"),
  severity: document.getElementById("severitySelect"),
  timing: document.getElementById("timingSelect"),
  command: document.getElementById("commandInput"),
  source: document.getElementById("sourceInput"),
  versionSearch: document.getElementById("versionSearch"),
  versionList: document.getElementById("versionList"),
  scopeAllButton: document.getElementById("scopeAllButton"),
  scopeSomeButton: document.getElementById("scopeSomeButton"),
  modelPickerField: document.getElementById("modelPickerField"),
  modelSearch: document.getElementById("modelSearch"),
  modelList: document.getElementById("modelList"),
  submitButton: document.getElementById("submitButton"),
  formMessage: document.getElementById("formMessage"),
  advisoryList: document.getElementById("advisoryList")
};

els.scopeAllButton.addEventListener("click", () => setScope("all"));
els.scopeSomeButton.addEventListener("click", () => setScope("some"));
els.versionSearch.addEventListener("input", () => renderVersionList());
els.modelSearch.addEventListener("input", () => renderModelList());
els.submitButton.addEventListener("click", submitAdvisory);

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
  renderAdvisoryList();
}

function setScope(scope) {
  modelScope = scope;
  els.scopeAllButton.classList.toggle("active", scope === "all");
  els.scopeSomeButton.classList.toggle("active", scope === "some");
  els.modelPickerField.classList.toggle("hidden", scope === "all");
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
  const checkbox = el("input", { type: "checkbox" });
  checkbox.value = value;
  checkbox.checked = checked;
  const label = el("label", {});
  label.appendChild(checkbox);
  label.appendChild(document.createTextNode(" " + labelText));
  return label;
}

function getCheckedValues(container) {
  return Array.from(container.querySelectorAll("input[type=checkbox]:checked")).map(input => input.value);
}

async function submitAdvisory() {
  const title = els.title.value.trim();
  const description = els.description.value.trim();
  const versions = getCheckedValues(els.versionList);
  const models = modelScope === "some" ? getCheckedValues(els.modelList) : [];

  if (!title || !description) {
    els.formMessage.textContent = "Titre et description sont obligatoires.";
    return;
  }
  if (!versions.length) {
    els.formMessage.textContent = "Cocher au moins une version FortiOS concernée.";
    return;
  }
  if (modelScope === "some" && !models.length) {
    els.formMessage.textContent = "Cocher au moins un boîtier, ou choisir Tous les boîtiers.";
    return;
  }

  els.submitButton.disabled = true;
  els.formMessage.textContent = "Publication en cours...";
  try {
    const response = await fetch("/api/advisories", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title,
        description,
        severity: els.severity.value,
        timing: els.timing.value,
        versions,
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
    els.formMessage.textContent = "Alerte publiée.";
  } catch (error) {
    els.formMessage.textContent = `Publication impossible : ${error.message}. Lancer l'interface avec scripts/fortios_server.py.`;
  } finally {
    els.submitButton.disabled = false;
  }
}

function resetForm() {
  els.title.value = "";
  els.description.value = "";
  els.command.value = "";
  els.severity.value = "important";
  els.timing.value = "post-upgrade";
  els.versionSearch.value = "";
  els.modelSearch.value = "";
  setScope("all");
  renderVersionList();
  renderModelList();
}

function renderAdvisoryList() {
  els.advisoryList.replaceChildren();
  if (!advisories.length) {
    els.advisoryList.appendChild(el("div", { className: "empty", text: "Aucune alerte interne publiée pour l'instant." }));
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
  head.appendChild(el("span", { className: `badge ${badgeClass(item.severity)}`, text: timingLabel(item.timing) }));

  const description = el("p", { text: item.description });

  const versions = advisoryVersions(item);
  const modelsScope = Array.isArray(item.models) && item.models.length ? item.models.join(", ") : "Tous";
  const meta = el("p", { className: "hint" });
  meta.textContent = `Versions : ${versions.join(", ") || "-"} • Boîtiers : ${modelsScope} • Source : ${item.source || "-"}`;

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

  return article;
}

function advisoryVersions(advisory) {
  if (Array.isArray(advisory.versions)) return advisory.versions;
  return advisory.version ? [advisory.version] : [];
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
