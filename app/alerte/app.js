const GENERATED_DATA_URL = "../../data/fortios-data.generated.json";
const SEVERITY_ORDER = ["critical", "important", "warning", "info"];
const SEVERITY_LABEL = { critical: "Critique", important: "Importante", warning: "Avertissement", info: "Info" };
const ALL_PRODUCTS_VALUE = "";

let products = [];
let selectedProduct = "";
let advisoryProductFilter = "";
let allModels = [];
let allVersions = [];
let advisories = [];
let modelScope = "all";
let versionMode = "exact";
let editingId = null;
let severityFilter = "all";

const els = {
  productSelect: document.getElementById("productSelect"),
  productFilterSelect: document.getElementById("productFilterSelect"),
  title: document.getElementById("titleInput"),
  description: document.getElementById("descriptionInput"),
  severity: document.getElementById("severitySelect"),
  behaviorChange: document.getElementById("behaviorChangeInput"),
  command: document.getElementById("commandInput"),
  bugId: document.getElementById("bugIdInput"),
  bugVersion: document.getElementById("bugVersionInput"),
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
  advisoryList: document.getElementById("advisoryList"),
  boldButton: document.getElementById("boldButton"),
  underlineButton: document.getElementById("underlineButton"),
  bulletButton: document.getElementById("bulletButton"),
  imageButton: document.getElementById("imageButton"),
  imageFileInput: document.getElementById("imageFileInput"),
  descriptionPreview: document.getElementById("descriptionPreview")
};

const ALLOWED_IMAGE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

els.productSelect.addEventListener("change", () => selectProduct(els.productSelect.value));
els.productFilterSelect.addEventListener("change", () => {
  advisoryProductFilter = els.productFilterSelect.value;
  renderAdvisoryList();
});
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
els.boldButton.addEventListener("click", () => wrapSelection(els.description, "**", "**"));
els.underlineButton.addEventListener("click", () => wrapSelection(els.description, "__", "__"));
els.bulletButton.addEventListener("click", () => toggleBulletLines(els.description));
els.description.addEventListener("input", () => renderRichText(els.descriptionPreview, els.description.value));
els.imageButton.addEventListener("click", () => els.imageFileInput.click());
els.imageFileInput.addEventListener("change", () => {
  const file = els.imageFileInput.files[0];
  if (file) uploadImage(file);
  els.imageFileInput.value = "";
});
els.description.addEventListener("paste", event => {
  const item = Array.from(event.clipboardData?.items || []).find(entry => entry.type.startsWith("image/"));
  if (!item) return;
  event.preventDefault();
  uploadImage(item.getAsFile());
});
els.description.addEventListener("dragover", event => event.preventDefault());
els.description.addEventListener("drop", event => {
  const file = Array.from(event.dataTransfer?.files || []).find(entry => entry.type.startsWith("image/"));
  if (!file) return;
  event.preventDefault();
  uploadImage(file);
});
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
  products = Array.isArray(state.products) ? state.products : [];
  advisories = Array.isArray(state.advisories) ? state.advisories : [];

  populateProductSelects();

  const requestedProduct = new URLSearchParams(window.location.search).get("product");
  const initialProduct = products.some(product => product.id === requestedProduct)
    ? requestedProduct
    : products[0]?.id || "";

  selectProduct(initialProduct);
  advisoryProductFilter = initialProduct || ALL_PRODUCTS_VALUE;
  els.productFilterSelect.value = advisoryProductFilter;
  renderAdvisoryList();
}

function populateProductSelects() {
  els.productSelect.replaceChildren();
  for (const product of products) {
    const option = document.createElement("option");
    option.value = product.id;
    option.textContent = product.label || product.id;
    els.productSelect.appendChild(option);
  }

  els.productFilterSelect.replaceChildren();
  const allOption = document.createElement("option");
  allOption.value = ALL_PRODUCTS_VALUE;
  allOption.textContent = "Tous les produits";
  els.productFilterSelect.appendChild(allOption);
  for (const product of products) {
    const option = document.createElement("option");
    option.value = product.id;
    option.textContent = product.label || product.id;
    els.productFilterSelect.appendChild(option);
  }
}

function productLabel(productId) {
  return products.find(product => product.id === productId)?.label || productId || "-";
}

function selectProduct(productId) {
  selectedProduct = productId;
  els.productSelect.value = productId;

  const product = products.find(item => item.id === productId) || { models: [] };
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

  setScope("all");
  setVersionMode("exact");
  els.versionSearch.value = "";
  els.minVersionSearch.value = "";
  els.modelSearch.value = "";
  renderVersionList();
  renderMinVersionList();
  renderModelList();
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
        product: selectedProduct,
        title,
        description,
        severity: els.severity.value,
        behaviorChange: els.behaviorChange.checked,
        versions,
        minVersions,
        models,
        command: els.command.value.trim(),
        bugId: els.bugId.value.trim(),
        bugVersion: els.bugVersion.value.trim(),
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
  selectProduct(item.product || products[0]?.id || "");
  els.title.value = item.title || "";
  els.description.value = item.description || "";
  renderRichText(els.descriptionPreview, els.description.value);
  els.severity.value = item.severity || "important";
  els.behaviorChange.checked = Boolean(item.behaviorChange);
  els.command.value = item.command || "";
  els.bugId.value = item.bugId || "";
  els.bugVersion.value = item.bugVersion || "";
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
  renderRichText(els.descriptionPreview, "");
  els.command.value = "";
  els.bugId.value = "";
  els.bugVersion.value = "";
  els.source.value = "";
  els.severity.value = "important";
  els.behaviorChange.checked = false;
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
    if (advisoryProductFilter && (item.product || "") !== advisoryProductFilter) return false;
    if (severityFilter !== "all" && item.severity !== severityFilter) return false;
    if (!query) return true;

    const haystack = normalizeSearch(
      [
        item.title,
        item.description,
        item.bugId,
        item.bugVersion,
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
  meta.textContent = `${productLabel(item.product)} • Versions : ${versionsLabel} • Boîtiers : ${modelsScope} • Source : ${item.source || "-"}`;

  const bugMeta = item.bugId
    ? el("p", { className: "hint", text: `Bug ID : ${item.bugId}${item.bugVersion ? ` (identifié en ${item.bugVersion})` : ""}` })
    : null;

  const article = el("article", { className: `advisory-row callout ${calloutClass(item.severity)}` });
  article.appendChild(head);
  article.appendChild(description);
  article.appendChild(meta);
  if (bugMeta) article.appendChild(bugMeta);

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

async function uploadImage(file) {
  if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    els.formMessage.textContent = "Format d'image non supporté (PNG, JPEG, GIF, WEBP).";
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    els.formMessage.textContent = "Image trop volumineuse (8 Mo max).";
    return;
  }

  els.formMessage.textContent = "Envoi de l'image...";
  try {
    const dataBase64 = await fileToBase64(file);
    const response = await fetch("/api/advisory-images", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contentType: file.type, dataBase64 })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || "Service local indisponible.");

    insertAtCursor(els.description, `![capture](${payload.url})\n`);
    renderRichText(els.descriptionPreview, els.description.value);
    els.formMessage.textContent = "Image ajoutée.";
  } catch (error) {
    els.formMessage.textContent = `Envoi de l'image impossible : ${error.message}.`;
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(new Error("Lecture du fichier impossible."));
    reader.readAsDataURL(file);
  });
}

function insertAtCursor(textarea, text) {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const value = textarea.value;
  textarea.value = value.slice(0, start) + text + value.slice(end);
  const cursor = start + text.length;
  textarea.focus();
  textarea.setSelectionRange(cursor, cursor);
}

function wrapSelection(textarea, before, after) {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const value = textarea.value;
  const selected = value.slice(start, end) || "texte";
  textarea.value = value.slice(0, start) + before + selected + after + value.slice(end);
  const cursorStart = start + before.length;
  textarea.focus();
  textarea.setSelectionRange(cursorStart, cursorStart + selected.length);
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
}

function toggleBulletLines(textarea) {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const value = textarea.value;
  const lineStart = value.lastIndexOf("\n", start - 1) + 1;
  const nextBreak = value.indexOf("\n", end);
  const lineEnd = nextBreak === -1 ? value.length : nextBreak;
  const lines = value.slice(lineStart, lineEnd).split("\n");
  const allBulleted = lines.every(line => line.startsWith("- ") || line.trim() === "");
  const transformed = lines
    .map(line => {
      if (line.trim() === "") return line;
      return allBulleted ? line.replace(/^- /, "") : `- ${line}`;
    })
    .join("\n");
  textarea.value = value.slice(0, lineStart) + transformed + value.slice(lineEnd);
  textarea.focus();
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
}

// Lightweight formatting markup: **bold**, __underline__, "- " bullet lines, blank line = new
// paragraph. Always builds real DOM nodes (never innerHTML) so rendering stays safe by construction.
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

function appendInlineRich(parent, text) {
  const pattern = /\*\*(.+?)\*\*|__(.+?)__|!\[(.*?)\]\((.*?)\)/g;
  let lastIndex = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > lastIndex) parent.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    if (match[4] !== undefined) {
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

function badgeClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "ok";
}

function calloutClass(severity) {
  return { critical: "danger", important: "danger", warning: "warn", info: "info" }[severity] || "";
}
