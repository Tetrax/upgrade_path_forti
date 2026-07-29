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

async function refreshSession() {
  try {
    const status = await apiRequest("status");
    showAdmin(status);
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
