"use strict";

let csrfToken = "";
let canInstall = false;
let validationSucceeded = false;
let validationToken = "";
let savedSmtpSettings = null;
let selectedPreviewScenario = "single";
let currentEmailPreview = null;
let emailPreviewRequestGeneration = 0;
const MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 8 * 1024 * 1024;
const MAX_CHAIN_BYTES = 16 * 1024 * 1024;
const MAX_PASSWORD_BYTES = 1024;
const MIN_ADMIN_PASSWORD_BYTES = 12;

const byId = (id) => document.getElementById(id);
const setupView = byId("setup-view");
const loginView = byId("login-view");
const adminView = byId("admin-view");
const logoutButton = byId("logout-button");
const setupForm = byId("setup-form");
const loginForm = byId("login-form");
const certificateForm = byId("certificate-form");
const installButton = byId("install-button");
const activationBox = byId("activation-box");
const validationBadge = byId("validation-badge");
const notificationsForm = byId("notifications-form");
const smtpForm = byId("smtp-form");
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
    const error = new Error(payload.error || `Erreur HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function apiRequest(endpoint, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (csrfToken && !["login", "setup"].includes(endpoint)) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(`/api/cert/${endpoint}`, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  if (response.status === 401 && !["login", "setup"].includes(endpoint)) showLogin();
  return readResponse(response);
}

function resetPrivateState() {
  csrfToken = "";
  validationSucceeded = false;
  validationToken = "";
  canInstall = false;
  certificateForm.reset();
  notificationsForm.reset();
  smtpForm.reset();
  savedSmtpSettings = null;
  currentEmailPreview = null;
  emailPreviewRequestGeneration += 1;
  byId("email-preview-frame").removeAttribute("src");
  recipientList.replaceChildren();
}

function showSetup() {
  resetPrivateState();
  setupView.hidden = false;
  loginView.hidden = true;
  adminView.hidden = true;
  logoutButton.hidden = true;
  setMessage("setup-message", "");
}

function showLogin(message = "") {
  resetPrivateState();
  setupView.hidden = true;
  loginView.hidden = false;
  adminView.hidden = true;
  logoutButton.hidden = true;
  setMessage("login-message", message);
}

function showAdmin(status) {
  csrfToken = status.csrfToken;
  canInstall = Boolean(status.canInstall);
  setupView.hidden = true;
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

function smtpSecurityLabel(security) {
  if (security === "tls") return "TLS implicite";
  if (security === "none") return "Sans chiffrement (autorisé)";
  return "STARTTLS";
}

function updateInsecureConfirmation() {
  const insecure = byId("smtp-security").value === "none";
  byId("smtp-insecure-confirmation").hidden = !insecure;
  byId("smtp-allow-insecure").required = insecure;
  if (!insecure) byId("smtp-allow-insecure").checked = false;
}

function buildEmailAppearancePayload() {
  return {
    displayName: byId("email-display-name").value.trim(),
    introduction: byId("email-introduction").value.trim(),
    signature: byId("email-signature").value.trim(),
  };
}

function updatePreviewSendAvailability() {
  byId("send-preview-email-button").disabled = !(
    savedSmtpSettings?.previewSendReady && currentEmailPreview
  );
}

async function renderEmailPreview() {
  const button = byId("preview-email-button");
  const appearance = buildEmailAppearancePayload();
  const requestGeneration = ++emailPreviewRequestGeneration;
  button.disabled = true;
  currentEmailPreview = null;
  updatePreviewSendAvailability();
  setMessage("email-preview-message", "Génération de l’aperçu…");
  try {
    const preview = await apiRequest("notifications/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: selectedPreviewScenario, appearance }),
    });
    if (requestGeneration !== emailPreviewRequestGeneration) return;
    currentEmailPreview = { ...preview, appearance };
    byId("email-preview-subject").textContent = preview.subject;
    byId("email-preview-text").textContent = preview.text;
    byId("email-preview-frame").src = preview.renderUrl;
    setMessage("email-preview-message", "Aperçu généré par le renderer réel.", true);
  } catch (error) {
    if (requestGeneration !== emailPreviewRequestGeneration) return;
    byId("email-preview-subject").textContent = "Aperçu indisponible";
    byId("email-preview-text").textContent = "";
    byId("email-preview-frame").removeAttribute("src");
    setMessage("email-preview-message", error.message);
  } finally {
    if (requestGeneration === emailPreviewRequestGeneration) {
      button.disabled = false;
      updatePreviewSendAvailability();
    }
  }
}

function renderTestSummary() {
  const smtp = savedSmtpSettings;
  byId("test-smtp-endpoint").textContent = smtp?.host ? `${smtp.host}:${smtp.port}` : "Non configuré";
  byId("test-smtp-security").textContent = smtp ? smtpSecurityLabel(smtp.security) : "—";
  byId("test-smtp-from").textContent = smtp?.from || "Non configuré";
  byId("test-smtp-recipient").textContent = byId("test-email-recipient").value.trim() || "—";
}

function renderSmtpSettings(payload) {
  const smtp = payload.smtp;
  savedSmtpSettings = smtp;
  byId("smtp-host").value = smtp.host || "";
  byId("smtp-port").value = String(smtp.port || 587);
  byId("smtp-security").value = smtp.security || "starttls";
  byId("smtp-allow-insecure").checked = Boolean(smtp.allowInsecure);
  byId("smtp-username").value = smtp.username || "";
  byId("smtp-from-address").value = smtp.from || "";
  byId("smtp-app-url").value = smtp.appUrl || "";
  byId("smtp-timeout").value = String(smtp.timeout || 10);
  byId("email-display-name").value = smtp.emailAppearance?.displayName || "FortiUpgrade";
  byId("email-introduction").value = smtp.emailAppearance?.introduction || "";
  byId("email-signature").value = smtp.emailAppearance?.signature || "";
  byId("smtp-password").value = "";
  byId("smtp-password-field").hidden = true;
  byId("smtp-password-status").textContent = smtp.passwordConfigured
    ? "Mot de passe configuré"
    : "Non configuré";
  byId("replace-smtp-password-button").textContent = smtp.passwordConfigured
    ? "Remplacer le mot de passe"
    : "Définir le mot de passe";
  byId("delete-smtp-password-button").hidden = !smtp.passwordConfigured;
  const operational = smtp.state === "operational";
  byId("smtp-status-label").textContent = operational ? "Opérationnelle" : "Configuration incomplète";
  byId("smtp-status-dot").className = `status-dot ${operational ? "success" : "failure"}`;
  byId("test-email-button").disabled = !operational;
  updatePreviewSendAvailability();
  updateInsecureConfirmation();
  void renderEmailPreview();
  renderTestSummary();
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
}

async function loadNotificationSettings() {
  try {
    renderNotificationSettings(await apiRequest("notifications"));
    setMessage("notifications-message", "");
  } catch (error) {
    setMessage("notifications-message", error.message);
  }
}

async function loadSmtpSettings() {
  try {
    renderSmtpSettings(await apiRequest("smtp"));
    setMessage("smtp-message", "");
  } catch (error) {
    setMessage("smtp-message", error.message);
  }
}

function buildSmtpSettingsPayload() {
  return {
    host: byId("smtp-host").value.trim(),
    port: Number(byId("smtp-port").value),
    security: byId("smtp-security").value,
    allowInsecure: byId("smtp-allow-insecure").checked,
    username: byId("smtp-username").value.trim(),
    password: byId("smtp-password").value,
    from: byId("smtp-from-address").value.trim(),
    appUrl: byId("smtp-app-url").value.trim(),
    timeout: Number(byId("smtp-timeout").value),
    emailAppearance: buildEmailAppearancePayload(),
  };
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
    if (status.setupRequired) {
      showSetup();
      return;
    }
    showAdmin(status);
    await Promise.all([loadNotificationSettings(), loadSmtpSettings()]);
  } catch (error) {
    showLogin(error.status === 401 ? "" : error.message);
  }
}

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("setup-button");
  button.disabled = true;
  setMessage("setup-message", "Création du compte en cours…");
  try {
    const password = byId("setup-password").value;
    const confirmation = byId("setup-password-confirmation").value;
    const passwordBytes = new TextEncoder().encode(password).length;
    if (passwordBytes < MIN_ADMIN_PASSWORD_BYTES || passwordBytes > MAX_PASSWORD_BYTES) {
      throw new Error("Le mot de passe doit contenir entre 12 et 1 024 octets UTF-8.");
    }
    if (password !== confirmation) {
      throw new Error("Les mots de passe ne correspondent pas.");
    }
    const payload = await apiRequest("setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: byId("setup-username").value,
        password,
        passwordConfirmation: confirmation,
      }),
    });
    csrfToken = payload.csrfToken;
    await refreshSession();
  } catch (error) {
    if (error.status === 409) showLogin(error.message);
    else setMessage("setup-message", error.message);
  } finally {
    byId("setup-password").value = "";
    byId("setup-password-confirmation").value = "";
    button.disabled = false;
  }
});

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

byId("smtp-security").addEventListener("change", updateInsecureConfirmation);
byId("preview-email-button").addEventListener("click", () => void renderEmailPreview());
for (const button of document.querySelectorAll("[data-preview-scenario]")) {
  button.addEventListener("click", () => {
    selectedPreviewScenario = button.dataset.previewScenario;
    for (const candidate of document.querySelectorAll("[data-preview-scenario]")) {
      const selected = candidate === button;
      candidate.classList.toggle("active", selected);
      candidate.setAttribute("aria-pressed", String(selected));
    }
    void renderEmailPreview();
  });
}
byId("preview-email-recipient").addEventListener("input", (event) => {
  event.currentTarget.setCustomValidity("");
});
byId("send-preview-email-button").addEventListener("click", async () => {
  const button = byId("send-preview-email-button");
  const recipient = byId("preview-email-recipient");
  recipient.setCustomValidity(recipient.value.trim() ? "" : "Indique un destinataire de test.");
  if (!recipient.reportValidity() || !currentEmailPreview) return;
  button.disabled = true;
  byId("email-preview-send-checks").replaceChildren();
  setMessage("email-preview-message", "Envoi de l’aperçu en cours…");
  try {
    const result = await apiRequest("notifications/send-preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scenario: currentEmailPreview.scenario,
        appearance: currentEmailPreview.appearance,
        runTimestamp: currentEmailPreview.runTimestamp,
        recipient: recipient.value.trim(),
      }),
    });
    for (const check of result.checks || []) {
      const item = document.createElement("li");
      item.textContent = `✓ ${check}`;
      byId("email-preview-send-checks").append(item);
    }
    setMessage("email-preview-message", result.message, true);
  } catch (error) {
    setMessage("email-preview-message", error.message);
  } finally {
    updatePreviewSendAvailability();
  }
});
byId("test-email-recipient").addEventListener("input", renderTestSummary);

byId("replace-smtp-password-button").addEventListener("click", () => {
  const field = byId("smtp-password-field");
  field.hidden = !field.hidden;
  if (field.hidden) {
    byId("smtp-password").value = "";
  } else {
    byId("smtp-password").focus();
  }
});

byId("delete-smtp-password-button").addEventListener("click", async () => {
  if (!window.confirm("Supprimer le mot de passe SMTP enregistré ?")) return;
  const button = byId("delete-smtp-password-button");
  button.disabled = true;
  setMessage("smtp-message", "Suppression du mot de passe…");
  try {
    const result = await apiRequest("smtp/password", { method: "DELETE" });
    renderSmtpSettings(result);
    setMessage("smtp-message", "Mot de passe SMTP supprimé.", true);
  } catch (error) {
    setMessage("smtp-message", error.message);
  } finally {
    button.disabled = false;
  }
});

smtpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("save-smtp-button");
  button.disabled = true;
  setMessage("smtp-message", "Enregistrement…");
  try {
    const result = await apiRequest("smtp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildSmtpSettingsPayload()),
    });
    renderSmtpSettings(result);
    setMessage("smtp-message", "Configuration email enregistrée.", true);
  } catch (error) {
    byId("smtp-password").value = "";
    setMessage("smtp-message", error.message);
  } finally {
    button.disabled = false;
  }
});

byId("test-email-button").addEventListener("click", async () => {
  const button = byId("test-email-button");
  const recipientInput = byId("test-email-recipient");
  if (!recipientInput.reportValidity()) return;
  button.disabled = true;
  byId("smtp-test-checks").replaceChildren();
  setMessage("test-email-message", "Envoi en cours…");
  try {
    const result = await apiRequest("notifications/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recipient: recipientInput.value.trim() }),
    });
    for (const check of result.checks || []) {
      const item = document.createElement("li");
      item.textContent = `✓ ${check}`;
      byId("smtp-test-checks").append(item);
    }
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
