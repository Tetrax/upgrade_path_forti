"use strict";

let csrfToken = "";
let canInstall = false;
let validationSucceeded = false;
let validationToken = "";
let savedSmtpSettings = null;
let selectedPreviewScenario = "single";
let currentEmailPreview = null;
let emailPreviewRequestGeneration = 0;
let publicActionToken = "";
const MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 8 * 1024 * 1024;
const MAX_CHAIN_BYTES = 16 * 1024 * 1024;
const MAX_PASSWORD_BYTES = 1024;
const MIN_ADMIN_PASSWORD_BYTES = 12;
const PUBLIC_CERT_ENDPOINTS = new Set([
  "login",
  "setup",
  "forgot-password",
  "verify-email",
  "reset-password",
]);

const byId = (id) => document.getElementById(id);
const setupView = byId("setup-view");
const loginView = byId("login-view");
const emailVerificationView = byId("email-verification-view");
const passwordResetView = byId("password-reset-view");
const adminView = byId("admin-view");
const logoutButton = byId("logout-button");
const setupForm = byId("setup-form");
const loginForm = byId("login-form");
const forgotPasswordForm = byId("forgot-password-form");
const passwordResetForm = byId("password-reset-form");
const passwordChangeForm = byId("password-change-form");
const recoveryEmailForm = byId("recovery-email-form");
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
  if (csrfToken && !PUBLIC_CERT_ENDPOINTS.has(endpoint)) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(`/api/cert/${endpoint}`, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  if (response.status === 401 && !PUBLIC_CERT_ENDPOINTS.has(endpoint)) showLogin();
  return readResponse(response);
}

function resetPrivateState() {
  csrfToken = "";
  validationSucceeded = false;
  validationToken = "";
  canInstall = false;
  loginForm.hidden = false;
  forgotPasswordForm.reset();
  forgotPasswordForm.hidden = true;
  setMessage("forgot-password-message", "");
  emailVerificationView.hidden = true;
  setMessage("email-verification-message", "");
  passwordResetForm.reset();
  passwordResetView.hidden = true;
  setMessage("password-reset-message", "");
  passwordChangeForm.reset();
  passwordChangeForm.hidden = true;
  setMessage("password-change-message", "");
  recoveryEmailForm.reset();
  recoveryEmailForm.hidden = true;
  setMessage("recovery-email-message", "");
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

function showLogin(message = "", success = false) {
  resetPrivateState();
  setupView.hidden = true;
  loginView.hidden = false;
  adminView.hidden = true;
  logoutButton.hidden = true;
  setMessage("login-message", message, success);
}

function showAdmin(status) {
  csrfToken = status.csrfToken;
  canInstall = Boolean(status.canInstall);
  setupView.hidden = true;
  loginView.hidden = true;
  emailVerificationView.hidden = true;
  passwordResetView.hidden = true;
  adminView.hidden = false;
  logoutButton.hidden = false;
  byId("target-hostname").textContent = status.hostname || "FORTIOS_TLS_HOSTNAME non configuré";
  byId("session-username").textContent = status.username;
  byId("activation-mode").textContent = canInstall ? "Activation locale autorisée" : "Validation uniquement";
  renderAccount(status);
  installButton.disabled = !canInstall;
  showAdminSection("certificates");
}

function showEmailVerification() {
  resetPrivateState();
  setupView.hidden = true;
  loginView.hidden = true;
  adminView.hidden = true;
  emailVerificationView.hidden = false;
  logoutButton.hidden = true;
  const token = new URLSearchParams(window.location.search).get("token") || "";
  publicActionToken = token;
  window.history.replaceState({}, "", window.location.pathname);
  const usable = /^[A-Za-z0-9_-]{43,128}$/.test(token);
  byId("verify-recovery-email-button").disabled = !usable;
  if (!usable) setMessage("email-verification-message", "Lien de vérification invalide ou expiré.");
}

function showPasswordReset() {
  resetPrivateState();
  setupView.hidden = true;
  loginView.hidden = true;
  adminView.hidden = true;
  passwordResetView.hidden = false;
  logoutButton.hidden = true;
  const token = new URLSearchParams(window.location.search).get("token") || "";
  publicActionToken = token;
  window.history.replaceState({}, "", window.location.pathname);
  const usable = /^[A-Za-z0-9_-]{43,128}$/.test(token);
  byId("reset-password-button").disabled = !usable;
  if (!usable) setMessage("password-reset-message", "Lien de récupération invalide ou expiré.");
}

function renderAccount(account) {
  byId("account-username").textContent = account.username || "admin";
  byId("account-recovery-email").textContent = account.recoveryEmail
    || account.pendingRecoveryEmail
    || "Non configurée";
  let recoveryStatus = "Récupération indisponible";
  if (account.recoveryStateAvailable === false) recoveryStatus = "État de récupération indisponible";
  else if (account.recoveryEmailVerified) recoveryStatus = "Vérifiée ✓";
  else if (account.pendingRecoveryEmailPresent) recoveryStatus = "En attente de vérification";
  byId("account-recovery-status").textContent = recoveryStatus;
  byId("resend-recovery-email-button").hidden = !account.pendingRecoveryEmailPresent;

  const changedAt = new Date(account.passwordChangedAt || "");
  byId("account-password-changed-at").textContent = Number.isNaN(changedAt.valueOf())
    ? "—"
    : new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(changedAt);
  const count = Number(account.sessionCount || 0);
  byId("account-session-count").textContent = `${count} session${count === 1 ? "" : "s"} active${count === 1 ? "" : "s"}`;
}

function showAdminSection(section) {
  for (const name of ["certificates", "notifications", "account"]) {
    const active = section === name;
    byId(`${name}-section`).hidden = !active;
    byId(`${name}-tab`).classList.toggle("active", active);
  }
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
  for (const id of ["smtp-host", "smtp-port", "smtp-security", "smtp-allow-insecure", "smtp-username", "smtp-from-address", "smtp-app-url", "smtp-timeout"]) {
    byId(id).disabled = true;
  }
  byId("smtp-password-status").textContent = smtp.passwordConfigured
    ? "Mot de passe configuré"
    : "Non configuré";
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
    const recoveryEmail = byId("setup-recovery-email").value.trim();
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
        recoveryEmail: recoveryEmail || null,
      }),
    });
    csrfToken = payload.csrfToken;
    await refreshSession();
    if (recoveryEmail) {
      try {
        const result = await apiRequest("recovery-email/resend", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        renderAccount(result);
        setMessage("recovery-email-message", "Le lien de vérification a été envoyé.", true);
      } catch (_error) {
        setMessage(
          "recovery-email-message",
          "Adresse enregistrée en attente. Configure SMTP pour envoyer sa vérification.",
        );
      }
    }
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

byId("forgot-password-button").addEventListener("click", () => {
  loginForm.hidden = true;
  forgotPasswordForm.hidden = false;
  setMessage("forgot-password-message", "");
  byId("forgot-username").focus();
});
byId("back-to-login-button").addEventListener("click", () => showLogin());
byId("verification-login-button").addEventListener("click", () => {
  window.history.replaceState({}, "", "/cert/");
  showLogin();
});
byId("verify-recovery-email-button").addEventListener("click", async () => {
  const button = byId("verify-recovery-email-button");
  button.disabled = true;
  setMessage("email-verification-message", "Vérification en cours…");
  try {
    await apiRequest("verify-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: publicActionToken }),
    });
    publicActionToken = "";
    setMessage("email-verification-message", "Adresse de récupération vérifiée.", true);
  } catch (_error) {
    setMessage("email-verification-message", "Lien de vérification invalide ou expiré.");
  }
});
byId("reset-login-button").addEventListener("click", () => {
  window.history.replaceState({}, "", "/cert/");
  showLogin();
});
passwordResetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("reset-password-button");
  button.disabled = true;
  setMessage("password-reset-message", "Réinitialisation en cours…");
  try {
    const newPassword = byId("reset-password").value;
    const confirmation = byId("reset-password-confirmation").value;
    const passwordBytes = new TextEncoder().encode(newPassword).length;
    if (passwordBytes < MIN_ADMIN_PASSWORD_BYTES || passwordBytes > MAX_PASSWORD_BYTES) {
      throw new Error("Le mot de passe doit contenir entre 12 et 1 024 octets UTF-8.");
    }
    if (newPassword !== confirmation) throw new Error("Les mots de passe ne correspondent pas.");
    await apiRequest("reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: publicActionToken, newPassword, confirmation }),
    });
    publicActionToken = "";
    window.history.replaceState({}, "", "/cert/");
    showLogin(
      "Mot de passe réinitialisé. Toutes les sessions administrateur ont été fermées.",
      true,
    );
  } catch (error) {
    passwordResetForm.reset();
    setMessage("password-reset-message", error.message);
    button.disabled = !publicActionToken;
  }
});
forgotPasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("send-reset-link-button");
  button.disabled = true;
  setMessage("forgot-password-message", "Demande en cours…");
  try {
    const result = await apiRequest("forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: byId("forgot-username").value }),
    });
    setMessage("forgot-password-message", result.message, true);
  } catch (_error) {
    setMessage(
      "forgot-password-message",
      "Si un compte correspondant existe et qu’une adresse de récupération vérifiée est configurée, un email de récupération a été envoyé.",
      true,
    );
  } finally {
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
byId("account-tab").addEventListener("click", () => showAdminSection("account"));
byId("change-recovery-email-button").addEventListener("click", () => {
  passwordChangeForm.hidden = true;
  recoveryEmailForm.hidden = false;
  setMessage("recovery-email-message", "");
  byId("recovery-email").focus();
});
byId("cancel-recovery-email-button").addEventListener("click", () => {
  recoveryEmailForm.reset();
  recoveryEmailForm.hidden = true;
  setMessage("recovery-email-message", "");
});
recoveryEmailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("save-recovery-email-button");
  button.disabled = true;
  setMessage("recovery-email-message", "Enregistrement…");
  try {
    const result = await apiRequest("recovery-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: byId("recovery-email").value.trim() }),
    });
    renderAccount(result);
    recoveryEmailForm.reset();
    setMessage(
      "recovery-email-message",
      result.verificationQueued
        ? "Adresse enregistrée. Le lien de vérification a été envoyé."
        : "Adresse enregistrée en attente. SMTP indisponible : configure-le puis renvoie la vérification.",
      result.verificationQueued,
    );
  } catch (error) {
    setMessage("recovery-email-message", error.message);
  } finally {
    button.disabled = false;
  }
});
byId("resend-recovery-email-button").addEventListener("click", async () => {
  const button = byId("resend-recovery-email-button");
  button.disabled = true;
  setMessage("recovery-email-message", "Envoi en cours…");
  try {
    const result = await apiRequest("recovery-email/resend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    renderAccount(result);
    setMessage("recovery-email-message", "Le lien de vérification a été renvoyé.", true);
  } catch (error) {
    setMessage("recovery-email-message", error.message);
  } finally {
    button.disabled = false;
  }
});
byId("revoke-all-sessions-button").addEventListener("click", async () => {
  const button = byId("revoke-all-sessions-button");
  button.disabled = true;
  try {
    await apiRequest("sessions/revoke-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    showLogin("Toutes les sessions administrateur ont été fermées.", true);
  } catch (error) {
    setMessage("password-change-message", error.message);
    button.disabled = false;
  }
});
byId("change-password-button").addEventListener("click", () => {
  passwordChangeForm.hidden = false;
  setMessage("password-change-message", "");
  byId("current-admin-password").focus();
});
byId("cancel-password-change-button").addEventListener("click", () => {
  passwordChangeForm.reset();
  passwordChangeForm.hidden = true;
  setMessage("password-change-message", "");
});
passwordChangeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("submit-password-change-button");
  button.disabled = true;
  setMessage("password-change-message", "Modification en cours…");
  try {
    const currentPassword = byId("current-admin-password").value;
    const newPassword = byId("new-admin-password").value;
    const confirmation = byId("confirm-admin-password").value;
    const passwordBytes = new TextEncoder().encode(newPassword).length;
    if (passwordBytes < MIN_ADMIN_PASSWORD_BYTES || passwordBytes > MAX_PASSWORD_BYTES) {
      throw new Error("Le mot de passe doit contenir entre 12 et 1 024 octets UTF-8.");
    }
    if (newPassword !== confirmation) {
      throw new Error("Les mots de passe ne correspondent pas.");
    }
    if (newPassword === currentPassword) {
      throw new Error("Le nouveau mot de passe doit être différent du mot de passe actuel.");
    }
    await apiRequest("password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ currentPassword, newPassword, confirmation }),
    });
    showLogin(
      "Mot de passe modifié. Pour votre sécurité, toutes les sessions administrateur "
        + "ont été fermées. Reconnectez-vous avec votre nouveau mot de passe.",
      true,
    );
  } catch (error) {
    setMessage("password-change-message", error.message);
  } finally {
    passwordChangeForm.reset();
    button.disabled = false;
  }
});
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

if (window.location.pathname === "/cert/verify-email") showEmailVerification();
else if (window.location.pathname === "/cert/reset-password") showPasswordReset();
else refreshSession();
