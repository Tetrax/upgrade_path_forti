"use strict";

let csrfToken = "";
let canInstall = false;
let validationSucceeded = false;
let validationToken = "";
const MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 8 * 1024 * 1024;
const MAX_CHAIN_BYTES = 16 * 1024 * 1024;
const MAX_PASSWORD_BYTES = 1024;
const MIN_ADMIN_PASSWORD_BYTES = 12;

const byId = (id) => document.getElementById(id);
const loginView = byId("login-view");
const adminView = byId("admin-view");
const logoutButton = byId("logout-button");
const loginForm = byId("login-form");
const certificateForm = byId("certificate-form");
const installButton = byId("install-button");
const activationBox = byId("activation-box");
const validationBadge = byId("validation-badge");
const notificationsForm = byId("notifications-form");
const recipientList = byId("recipient-list");
const PRODUCT_CHECKBOXES = {
  "fortigate-fortios": "product-fortigate-fortios",
  fortimanager: "product-fortimanager",
  fortianalyzer: "product-fortianalyzer",
  "forticlient-ems": "product-forticlient-ems",
};
const FORTICLIENT_CHECKBOXES = {
  windows: "product-forticlient-windows",
  macos: "product-forticlient-macos",
  linux: "product-forticlient-linux",
};

function setMessage(id, message, success = false) {
  const element = byId(id);
  element.textContent = message;
  element.classList.toggle("success", success);
}

async function readResponse(response) {
  let payload = {};
  try {
    payload = await response.json();
  } catch (_error) {
    payload = { error: "Réponse serveur illisible." };
  }
  if (!response.ok) {
    throw new Error(payload.error || `Erreur HTTP ${response.status}`);
  }
  return payload;
}

async function apiRequest(endpoint, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (csrfToken && endpoint !== "login") headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(`/api/cert/${endpoint}`, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  if (response.status === 401 && endpoint !== "login") showLogin();
  return readResponse(response);
}

function showLogin() {
  csrfToken = "";
  validationSucceeded = false;
  validationToken = "";
  canInstall = false;
  certificateForm.reset();
  notificationsForm.reset();
  recipientList.replaceChildren();
  loginView.hidden = false;
  adminView.hidden = true;
  logoutButton.hidden = true;
}

function showAdmin(status) {
  csrfToken = status.csrfToken;
  canInstall = Boolean(status.canInstall);
  loginView.hidden = true;
  adminView.hidden = false;
  logoutButton.hidden = false;
  byId("target-hostname").textContent = status.hostname || "FORTIOS_TLS_HOSTNAME non configuré";
  byId("session-username").textContent = status.username;
  byId("activation-mode").textContent = canInstall ? "Activation locale autorisée" : "Validation uniquement";
  installButton.disabled = !canInstall;
}

function showAdminSection(section) {
  const notificationsActive = section === "notifications";
  byId("certificates-section").hidden = notificationsActive;
  byId("notifications-section").hidden = !notificationsActive;
  byId("certificates-tab").classList.toggle("active", !notificationsActive);
  byId("notifications-tab").classList.toggle("active", notificationsActive);
}

function addRecipient(value = "") {
  const row = document.createElement("div");
  row.className = "recipient-row";
  const input = document.createElement("input");
  input.type = "email";
  input.required = true;
  input.maxLength = 254;
  input.autocomplete = "email";
  input.placeholder = "security@example.com";
  input.value = value;
  input.setAttribute("aria-label", "Adresse email destinataire");
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn recipient-remove";
  remove.textContent = "Supprimer";
  remove.addEventListener("click", () => row.remove());
  row.append(input, remove);
  recipientList.append(row);
}

function renderSmtpStatus(smtp) {
  const operational = smtp.state === "operational";
  byId("smtp-status-label").textContent = operational ? "Opérationnelle" : "Configuration incomplète";
  byId("smtp-status-dot").className = `status-dot ${operational ? "success" : "failure"}`;
  byId("smtp-endpoint").textContent = smtp.host ? `${smtp.host}:${smtp.port}` : "Non configuré";
  byId("smtp-mode").textContent = smtp.starttls ? "STARTTLS" : "Sans STARTTLS";
  byId("smtp-from").textContent = smtp.from || "Non configuré";
  byId("test-email-button").disabled = !operational;
}

function renderNotificationSettings(payload) {
  const settings = payload.settings;
  byId("notifications-enabled").checked = settings.enabled;
  byId("minimum-severity").value = settings.minimumSeverity;
  for (const [product, checkboxId] of Object.entries(PRODUCT_CHECKBOXES)) {
    byId(checkboxId).checked = settings.products[product];
  }
  for (const [platform, checkboxId] of Object.entries(FORTICLIENT_CHECKBOXES)) {
    byId(checkboxId).checked = settings.products.forticlient[platform];
  }
  recipientList.replaceChildren();
  for (const recipient of settings.recipients) addRecipient(recipient);
  if (!settings.recipients.length) addRecipient();
  renderSmtpStatus(payload.smtp);
}

async function loadNotificationSettings() {
  try {
    renderNotificationSettings(await apiRequest("notifications"));
    setMessage("notifications-message", "");
  } catch (error) {
    setMessage("notifications-message", error.message);
  }
}

function buildNotificationSettingsPayload() {
  const recipients = [...recipientList.querySelectorAll("input[type=email]")]
    .map((input) => input.value.trim())
    .filter(Boolean);
  const products = {};
  for (const [product, checkboxId] of Object.entries(PRODUCT_CHECKBOXES)) {
    products[product] = byId(checkboxId).checked;
  }
  products.forticlient = {};
  for (const [platform, checkboxId] of Object.entries(FORTICLIENT_CHECKBOXES)) {
    products.forticlient[platform] = byId(checkboxId).checked;
  }
  return {
    enabled: byId("notifications-enabled").checked,
    minimumSeverity: byId("minimum-severity").value,
    products,
    recipients,
  };
}

async function refreshSession() {
  try {
    const status = await apiRequest("status");
    showAdmin(status);
    await loadNotificationSettings();
  } catch (_error) {
    showLogin();
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("login-button");
  button.disabled = true;
  setMessage("login-message", "Connexion en cours…");
  try {
    const password = byId("password").value;
    const passwordBytes = new TextEncoder().encode(password).length;
    if (passwordBytes < MIN_ADMIN_PASSWORD_BYTES || passwordBytes > MAX_PASSWORD_BYTES) {
      throw new Error("Le mot de passe doit contenir entre 12 et 1 024 octets UTF-8.");
    }
    const payload = await apiRequest("login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: byId("username").value,
        password,
      }),
    });
    csrfToken = payload.csrfToken;
    await refreshSession();
    setMessage("login-message", "");
  } catch (error) {
    setMessage("login-message", error.message);
  } finally {
    byId("password").value = "";
    button.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  try {
    await apiRequest("logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
  } catch (_error) {
    // Local state is cleared even if the already-expired server session cannot be revoked.
  }
  certificateForm.reset();
  showLogin();
});

byId("certificates-tab").addEventListener("click", () => showAdminSection("certificates"));
byId("notifications-tab").addEventListener("click", () => showAdminSection("notifications"));
byId("add-recipient-button").addEventListener("click", () => addRecipient());

notificationsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("save-notifications-button");
  button.disabled = true;
  setMessage("notifications-message", "Enregistrement…");
  try {
    const result = await apiRequest("notifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildNotificationSettingsPayload()),
    });
    renderNotificationSettings(result);
    setMessage("notifications-message", "Configuration enregistrée.", true);
  } catch (error) {
    setMessage("notifications-message", error.message);
  } finally {
    button.disabled = false;
  }
});

byId("test-email-button").addEventListener("click", async () => {
  const button = byId("test-email-button");
  button.disabled = true;
  setMessage("test-email-message", "Envoi en cours…");
  try {
    const result = await apiRequest("notifications/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    setMessage("test-email-message", result.message, true);
  } catch (error) {
    setMessage("test-email-message", error.message);
  } finally {
    button.disabled = false;
  }
});

function fileToBase64(file) {
  if (!file) return Promise.resolve("");
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      resolve(result.includes(",") ? result.split(",", 2)[1] : "");
    };
    reader.onerror = () => reject(new Error(`Impossible de lire ${file.name}.`));
    reader.readAsDataURL(file);
  });
}

async function buildUploadPayload() {
  const certificate = byId("certificate-file").files[0];
  if (!certificate) throw new Error("Sélectionne un certificat ou un bundle.");
  const privateKey = byId("private-key-file").files[0];
  const chain = byId("chain-file").files[0];
  const password = byId("certificate-password").value;
  if (certificate.size > MAX_CERTIFICATE_BYTES) throw new Error("Le certificat dépasse 16 Mio.");
  if (privateKey && privateKey.size > MAX_PRIVATE_KEY_BYTES) throw new Error("La clé privée dépasse 8 Mio.");
  if (chain && chain.size > MAX_CHAIN_BYTES) throw new Error("La chaîne dépasse 16 Mio.");
  if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) {
    throw new Error("Le mot de passe du certificat est trop long.");
  }
  const [certificateBase64, privateKeyBase64, chainBase64] = await Promise.all([
    fileToBase64(certificate),
    fileToBase64(privateKey),
    fileToBase64(chain),
  ]);
  return {
    certificateBase64,
    privateKeyBase64,
    chainBase64,
    password,
  };
}

function resetValidation() {
  validationSucceeded = false;
  validationToken = "";
  activationBox.hidden = true;
  byId("certificate-summary").hidden = true;
  byId("empty-result").hidden = false;
  validationBadge.textContent = "En attente";
  validationBadge.className = "status-badge neutral";
  setMessage("upload-message", "");
  setMessage("install-message", "");
}

function showSummary(summary) {
  byId("summary-subject").textContent = summary.subject || "—";
  byId("summary-issuer").textContent = summary.issuer || "—";
  byId("summary-dns").textContent = (summary.dnsNames || []).join(", ") || "—";
  byId("summary-start").textContent = summary.notBefore || "—";
  byId("summary-end").textContent = summary.notAfter || "—";
  byId("summary-chain").textContent = `${summary.chainLength || 0} certificat(s)`;
  byId("summary-fingerprint").textContent = summary.sha256Fingerprint || "—";
  byId("empty-result").hidden = true;
  byId("certificate-summary").hidden = false;
  activationBox.hidden = false;
  installButton.disabled = !canInstall;
  validationBadge.textContent = "Valide";
  validationBadge.className = "status-badge success";
}

certificateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("validate-button");
  button.disabled = true;
  resetValidation();
  setMessage("upload-message", "Validation cryptographique en cours…");
  try {
    const payload = await buildUploadPayload();
    const summary = await apiRequest("validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    validationSucceeded = true;
    validationToken = summary.validationToken;
    showSummary(summary);
    setMessage("upload-message", "Certificat valide. Vérifie les informations avant activation.", true);
  } catch (error) {
    validationBadge.textContent = "Refusé";
    validationBadge.className = "status-badge failure";
    setMessage("upload-message", error.message);
  } finally {
    button.disabled = false;
  }
});

installButton.addEventListener("click", async () => {
  if (!validationSucceeded || !canInstall) return;
  if (!window.confirm("Activer ce certificat et remplacer la paire TLS actuellement configurée ?")) return;
  installButton.disabled = true;
  setMessage("install-message", "Nouvelle validation puis activation atomique en cours…");
  try {
    const payload = await buildUploadPayload();
    payload.validationToken = validationToken;
    const result = await apiRequest("install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const suffix = result.restartRequired
      ? " Redémarre le serveur web pour charger la nouvelle paire."
      : " La paire active a été remplacée.";
    setMessage("install-message", `Certificat activé.${suffix}`, true);
    certificateForm.reset();
    validationSucceeded = false;
    validationToken = "";
    activationBox.hidden = true;
  } catch (error) {
    setMessage("install-message", error.message);
    installButton.disabled = false;
  }
});

for (const id of ["certificate-file", "private-key-file", "chain-file", "certificate-password"]) {
  byId(id).addEventListener("change", resetValidation);
  byId(id).addEventListener("input", resetValidation);
}

refreshSession();
