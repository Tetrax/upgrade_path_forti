const GENERATED_DATA_URL = "../../data/fortios-data.generated.json";
const CLIENT_PLATFORM_IDS = ["windows", "macos", "linux"];

let emsVersions = [];
let clientVersions = [];
let compatibilities = [];
let editingId = null;

const els = {
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

  populateEmsVersionSelect();
  renderClientVersionList();
  renderCompatList();
  renderVersionSummaries(fortclient, emsModel);
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
  const checked = new Set(getCheckedValues(els.clientVersionList));
  const visible = clientVersions.filter(version => !filter || normalizeSearch(version).includes(filter));

  els.clientVersionList.replaceChildren();
  if (!visible.length) {
    els.clientVersionList.appendChild(el("span", { className: "hint", text: "Aucune version ne correspond au filtre." }));
    return;
  }
  for (const version of visible) {
    els.clientVersionList.appendChild(checkboxRow(version, version, checked.has(version)));
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

async function submitCompatibility() {
  const emsVersion = els.emsVersionSelect.value;
  const clientVersionsChecked = getCheckedValues(els.clientVersionList);

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
  renderClientVersionList();
  setCheckedValues(els.clientVersionList, item.clientVersions || []);
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

  const versionsLine = el("p", { text: `FortiClient : ${(item.clientVersions || []).join(", ") || "-"}` });

  const meta = el("p", { className: "hint", text: `Source : ${item.source || "-"}` });

  const article = el("article", { className: "advisory-row callout" });
  article.appendChild(head);
  article.appendChild(versionsLine);
  if (item.note) article.appendChild(el("p", { className: "hint", text: item.note }));
  article.appendChild(meta);

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
