import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import https from "node:https";
import os from "node:os";
import { clearInterval as clearIntervalTimer, setInterval as setIntervalTimer } from "node:timers";

const DEFAULT_API_BASE_URL = "https://auth.authforge.cc";
const RATE_LIMIT_RETRY_DELAYS = [2, 5];
const NETWORK_RETRY_DELAY = 2;
const KNOWN_SERVER_ERRORS = new Set([
  "invalid_app",
  "invalid_key",
  "expired",
  "revoked",
  "hwid_mismatch",
  "no_credits",
  "app_burn_cap_reached",
  "blocked",
  "rate_limited",
  "replay_detected",
  "app_disabled",
  "session_expired",
  "revoke_requires_session",
  "bad_request",
  "malformed_request",
  "system_error",
]);

const SUCCESS_STATUSES = new Set(["ok", "success", "valid", "true", "1"]);

function sleepSeconds(seconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, seconds * 1000);
  });
}

function cloneObject(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return { ...value };
  }
  return null;
}

function toBase64Url(rawBase64) {
  return rawBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function createEd25519PublicKey(rawBase64) {
  return createPublicKey({
    key: {
      crv: "Ed25519",
      kty: "OKP",
      x: toBase64Url(rawBase64),
    },
    format: "jwk",
  });
}

/**
 * Normalize the public-key argument into a non-empty array of base64 strings.
 *
 * Accepts:
 *   - "abc..."                 (single key — historical contract)
 *   - ["abc...", "def..."]     (key set — current first, previous(es) after)
 *   - "abc...,def..."          (legacy comma-separated for env-var convenience)
 *
 * Returns the trimmed list of keys. Throws if no usable key is present so
 * the constructor can surface "publicKey must be a non-empty string" errors
 * unchanged.
 */
function normalizePublicKeyList(input) {
  const out = [];
  const push = (value) => {
    if (typeof value !== "string") return;
    const trimmed = value.trim();
    if (trimmed) out.push(trimmed);
  };
  if (Array.isArray(input)) {
    for (const entry of input) push(entry);
  } else if (typeof input === "string") {
    if (input.includes(",")) {
      for (const entry of input.split(",")) push(entry);
    } else {
      push(input);
    }
  }
  return out;
}

/**
 * Verify a payload signature against one or more trusted Ed25519 public keys.
 *
 * Accepting a list lets a deployment publish a new public key while clients
 * are still pinned to the previous one — the SDK trusts both during the
 * rotation window and falls back automatically when the server-side key
 * changes. Returns `true` on the first match.
 */
export function verifyPayloadSignatureEd25519(payloadBase64, signatureBase64, publicKeyOrKeys) {
  const keys = normalizePublicKeyList(publicKeyOrKeys);
  if (keys.length === 0) return false;
  for (const key of keys) {
    try {
      const isValid = verify(
        null,
        Buffer.from(payloadBase64, "utf8"),
        createEd25519PublicKey(key),
        Buffer.from(signatureBase64, "base64"),
      );
      if (isValid) return true;
    } catch {
      // Malformed key — try the next one rather than failing the whole set.
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Offline license files (`.authforge`)
//
// A cloud-minted, Ed25519-signed document for machines that never phone home.
// This is a SEPARATE mode from the grace period: the grace period continues a
// signed session after one online activation, while an offline file is
// verified locally with only the app public key and the machine HWID. Nothing
// here performs network I/O or starts online check-ins.
// ---------------------------------------------------------------------------

const OFFLINE_LICENSE_FILE_VERSION = 1;
const OFFLINE_BEGIN_LICENSE = "-----BEGIN AUTHFORGE LICENSE-----";
const OFFLINE_END_LICENSE = "-----END AUTHFORGE LICENSE-----";
const OFFLINE_BEGIN_SIGNATURE = "-----BEGIN AUTHFORGE SIGNATURE-----";
const OFFLINE_END_SIGNATURE = "-----END AUTHFORGE SIGNATURE-----";
const OFFLINE_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export const offlineLicenseErrors = [
  "bad_armor",
  "bad_signature",
  "unsupported_version",
  "malformed_payload",
  "wrong_app",
  "expired",
  "hwid_mismatch",
];

/**
 * Parse armored `.authforge` text into `{ headers, payloadBase64, signatureBase64 }`
 * or `null` when the armor is malformed. Tolerates CRLF, a UTF-8 BOM, any
 * re-wrapping of the base64 body and text before/after the armor.
 * `payloadBase64` is exactly the string the signature covers.
 */
export function parseLicenseFile(text) {
  if (typeof text !== "string") return null;
  const lines = text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n");
  const beginIdx = lines.findIndex((l) => l.trim() === OFFLINE_BEGIN_LICENSE);
  if (beginIdx === -1) return null;
  const endIdx = lines.findIndex((l, i) => i > beginIdx && l.trim() === OFFLINE_END_LICENSE);
  if (endIdx === -1) return null;
  const sigBeginIdx = lines.findIndex((l, i) => i > endIdx && l.trim() === OFFLINE_BEGIN_SIGNATURE);
  if (sigBeginIdx === -1) return null;
  const sigEndIdx = lines.findIndex((l, i) => i > sigBeginIdx && l.trim() === OFFLINE_END_SIGNATURE);
  if (sigEndIdx === -1) return null;

  const block = lines.slice(beginIdx + 1, endIdx);
  const blankIdx = block.findIndex((l) => l.trim() === "");
  if (blankIdx === -1) return null;
  const headers = {};
  for (const raw of block.slice(0, blankIdx)) {
    const line = raw.trim();
    const colon = line.indexOf(":");
    if (colon <= 0) return null;
    headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  const payloadBase64 = block.slice(blankIdx + 1).join("").replace(/\s+/g, "");
  const signatureBase64 = lines.slice(sigBeginIdx + 1, sigEndIdx).join("").replace(/\s+/g, "");
  if (!payloadBase64 || !OFFLINE_BASE64_RE.test(payloadBase64)) return null;
  if (!signatureBase64 || !OFFLINE_BASE64_RE.test(signatureBase64)) return null;
  return { headers, payloadBase64, signatureBase64 };
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === "string" && v.length > 0);
}

function validateOfflinePayloadShape(payload) {
  if (payload.typ !== "authforge-license") return false;
  for (const field of ["appId", "licenseKey", "jti", "kid", "issuedAt"]) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) return false;
  }
  if (payload.expiresAt !== null && (typeof payload.expiresAt !== "string" || payload.expiresAt.length === 0)) {
    return false;
  }
  if (!isPlainObject(payload.hwid)) return false;
  if (payload.hwid.mode === "bound") {
    if (!isStringArray(payload.hwid.hwids)) return false;
  } else if (payload.hwid.mode !== "any") {
    return false;
  }
  return true;
}

/**
 * Verify an offline `.authforge` license file with NO network access.
 *
 * Check order (fixed across every SDK): bad_armor -> bad_signature ->
 * unsupported_version -> malformed_payload -> wrong_app -> expired ->
 * hwid_mismatch. The signature is checked before the payload JSON is
 * decoded so a forged file never reaches the parser.
 *
 * @param {object} params
 * @param {string} params.file      Armored file text.
 * @param {string} params.appId     Your app id; must match the payload.
 * @param {string|readonly string[]} params.publicKey  Trusted public key(s).
 * @param {string|null} [params.hwid]  Local HWID (required for bound files).
 * @param {Date|number} [params.now]   Clock override (tests).
 * @returns {{ok: true, license: object, payloadBase64: string, signatureBase64: string} | {ok: false, error: string}}
 */
export function verifyLicenseFile({ file, appId, publicKey, hwid = null, now = undefined }) {
  const parsed = parseLicenseFile(file);
  if (!parsed) return { ok: false, error: "bad_armor" };

  if (!verifyPayloadSignatureEd25519(parsed.payloadBase64, parsed.signatureBase64, publicKey)) {
    return { ok: false, error: "bad_signature" };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(parsed.payloadBase64, "base64").toString("utf8"));
  } catch {
    return { ok: false, error: "malformed_payload" };
  }
  if (!isPlainObject(payload)) return { ok: false, error: "malformed_payload" };
  if (payload.v !== OFFLINE_LICENSE_FILE_VERSION) return { ok: false, error: "unsupported_version" };
  if (!validateOfflinePayloadShape(payload)) return { ok: false, error: "malformed_payload" };

  if (payload.appId !== appId) return { ok: false, error: "wrong_app" };

  const nowMs = now instanceof Date ? now.getTime() : typeof now === "number" ? now : Date.now();
  if (payload.expiresAt !== null) {
    const exp = new Date(payload.expiresAt).getTime();
    if (!Number.isFinite(exp) || exp <= nowMs) return { ok: false, error: "expired" };
  }

  if (payload.hwid.mode === "bound") {
    const local = typeof hwid === "string" ? hwid.trim() : "";
    if (!local || !payload.hwid.hwids.includes(local)) return { ok: false, error: "hwid_mismatch" };
  }

  return {
    ok: true,
    license: {
      appId: payload.appId,
      licenseKey: payload.licenseKey,
      jti: payload.jti,
      keyId: payload.kid,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      hwidPolicy: payload.hwid.mode === "bound" ? { mode: "bound", hwids: [...payload.hwid.hwids] } : { mode: "any" },
      ...(typeof payload.label === "string" ? { label: payload.label } : {}),
      ...(Object.hasOwn(payload, "licenseExpiresAt") ? { licenseExpiresAt: payload.licenseExpiresAt ?? null } : {}),
      licenseVariables: cloneObject(payload.licenseVariables),
      appVariables: cloneObject(payload.appVariables),
      payload: { ...payload },
    },
    payloadBase64: parsed.payloadBase64,
    signatureBase64: parsed.signatureBase64,
  };
}

function postJson(urlText, body, timeoutSeconds) {
  const payload = JSON.stringify(body);
  const url = new URL(urlText);
  const options = {
    method: "POST",
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port || undefined,
    path: `${url.pathname}${url.search}`,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    },
    timeout: timeoutSeconds * 1000,
  };

  return new Promise((resolve, reject) => {
    const request = https.request(options, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({ statusCode: response.statusCode ?? 0, raw });
      });
    });

    request.on("timeout", () => {
      request.destroy(new Error("timeout"));
    });

    request.on("error", (error) => {
      reject(error);
    });

    request.write(payload);
    request.end();
  });
}

export class AuthForgeClient {
  constructor(
    appId,
    appSecret,
    publicKey,
    heartbeatMode,
    heartbeatInterval = 900,
    apiBaseUrl = DEFAULT_API_BASE_URL,
    onFailure = null,
    requestTimeout = 15,
    ttlSeconds = null,
    hwidOverride = null,
  ) {
    let onlineHeartbeat = false;
    if (appId && typeof appId === "object" && !Array.isArray(appId)) {
      const options = appId;
      appId = options.appId;
      appSecret = options.appSecret;
      publicKey = options.publicKey;
      heartbeatMode = options.heartbeatMode;
      onlineHeartbeat = options.onlineHeartbeat ?? false;
      heartbeatInterval = options.heartbeatInterval ?? 900;
      apiBaseUrl = options.apiBaseUrl ?? DEFAULT_API_BASE_URL;
      onFailure = options.onFailure ?? null;
      requestTimeout = options.requestTimeout ?? 15;
      ttlSeconds = options.ttlSeconds ?? null;
      hwidOverride = options.hwidOverride ?? null;
    }

    if (!appId || typeof appId !== "string") {
      throw new Error("appId must be a non-empty string");
    }
    if (!appSecret || typeof appSecret !== "string") {
      throw new Error("appSecret must be a non-empty string");
    }
    const publicKeyList = normalizePublicKeyList(publicKey);
    if (publicKeyList.length === 0) {
      throw new Error("publicKey must be a non-empty string or array of strings");
    }
    // `heartbeatMode` is a deprecated shim. The product policy is:
    // grace period by default (no network after activate/validate until the
    // session TTL expires), or opt-in online check-ins via `onlineHeartbeat`.
    let mode = null;
    if (heartbeatMode !== null && heartbeatMode !== undefined && String(heartbeatMode) !== "") {
      mode = String(heartbeatMode).toUpperCase();
      if (mode !== "LOCAL" && mode !== "SERVER") {
        throw new Error("heartbeatMode must be LOCAL or SERVER");
      }
      process.emitWarning(
        "heartbeatMode is deprecated: use onlineHeartbeat: true for online check-ins; the default is the grace period behavior",
        "DeprecationWarning",
      );
    }
    if (heartbeatInterval < 10) {
      throw new Error("heartbeatInterval must be >= 10");
    }

    this.appId = appId;
    this.appSecret = appSecret;
    // `publicKey` is the historical name; we now hold the full list to
    // support key rotation, but expose `.publicKey` as the first (primary)
    // entry for callers that read it directly.
    this.publicKeys = publicKeyList;
    this.publicKey = publicKeyList[0];
    // Effective policy: online check-ins when opted in explicitly or via the
    // legacy "SERVER" mode; otherwise the grace period behavior.
    this.onlineHeartbeat = Boolean(onlineHeartbeat) || mode === "SERVER";
    // Back-compat alias for callers that still read `heartbeatMode`.
    this.heartbeatMode = this.onlineHeartbeat ? "SERVER" : "LOCAL";
    this.heartbeatInterval = Number.parseInt(String(heartbeatInterval), 10);
    this.apiBaseUrl = String(apiBaseUrl).replace(/\/+$/, "");
    this.onFailure = typeof onFailure === "function" ? onFailure : null;
    this.requestTimeout = requestTimeout;
    // Requested grace period duration in seconds (equals the session TTL).
    // Server default is 24h; the server clamps requests to 1h..7d.
    const parsedTtl = Number.parseInt(String(ttlSeconds ?? ""), 10);
    this.ttlSeconds = Number.isFinite(parsedTtl) && parsedTtl > 0 ? parsedTtl : null;

    this._heartbeatTimer = null;
    this._heartbeatStarted = false;

    this._licenseKey = null;
    this._sessionToken = null;
    // "online" after login()/validate, "offline" after loginFromFile(), null
    // when logged out. Drives isAuthenticated(), selfBan() and the heartbeat
    // guard so the two modes can never be confused for each other.
    this._sessionKind = null;
    this._sessionExpiresIn = null;
    this._lastNonce = null;
    this._rawPayloadB64 = null;
    this._signature = null;
    this._keyId = null;
    this._sessionData = null;
    this._appVariables = null;
    this._licenseVariables = null;
    this._authenticated = false;
    this._offlineLicense = null;
    this._hwid = this._resolveHwid(hwidOverride);
  }

  /** `"online"`, `"offline"` or `null` when not authenticated. */
  getSessionKind() {
    return this._sessionKind;
  }

  /**
   * The HWID this client sends to AuthForge (or `hwidOverride` if set).
   * Customers on air-gapped machines report this value to the operator so an
   * offline `.authforge` file can be bound to it.
   */
  getHwid() {
    return this._hwid;
  }

  /**
   * Authorize from a cloud-minted offline license file (`.authforge`) with NO
   * network access. Accepts a filesystem path or the armored text itself.
   *
   * On success the client is authenticated (`isAuthenticated()`,
   * `getSessionData()`, `getAppVariables()`, `getLicenseVariables()` work) and
   * `getOfflineLicense()` describes the file. No grace-period timer and no
   * online check-ins are started - the file's own `expiresAt` is the only
   * clock. Online `login()` is untouched.
   *
   * Returns `true`/`false`; failures are reported through `onFailure` with
   * reason `offline_login_failed` (never `process.exit`, unlike `login()`
   * without a callback - an unreadable file should not kill an air-gapped
   * process without a chance to show the user why).
   */
  loginFromFile(pathOrText) {
    let text;
    try {
      text = this._readLicenseFileInput(pathOrText);
    } catch (error) {
      this._failSoft("offline_login_failed", error);
      return false;
    }
    const result = verifyLicenseFile({
      file: text,
      appId: this.appId,
      publicKey: this.publicKeys,
      hwid: this._hwid,
    });
    if (!result.ok) {
      this._failSoft("offline_login_failed", new Error(result.error));
      return false;
    }
    this._applyOfflineLicense(result);
    return true;
  }

  /**
   * Verify a `.authforge` file with this client's app id, public key(s) and
   * HWID, without touching session state. Pure; never throws for bad input.
   */
  verifyLicenseFile(pathOrText, options = {}) {
    let text;
    try {
      text = this._readLicenseFileInput(pathOrText);
    } catch (error) {
      return { ok: false, error: `read_error: ${error instanceof Error ? error.message : String(error)}` };
    }
    return verifyLicenseFile({
      file: text,
      appId: this.appId,
      publicKey: this.publicKeys,
      hwid: this._hwid,
      now: options.now,
    });
  }

  /** Details of the offline file the client authenticated with, or `null`. */
  getOfflineLicense() {
    return this._offlineLicense ? { ...this._offlineLicense } : null;
  }

  _readLicenseFileInput(pathOrText) {
    if (typeof pathOrText !== "string" || pathOrText.length === 0) {
      throw new Error("license file must be a path or the armored text");
    }
    if (pathOrText.includes(OFFLINE_BEGIN_LICENSE)) {
      return pathOrText;
    }
    return readFileSync(pathOrText, "utf8");
  }

  _applyOfflineLicense(result) {
    // Stop any online session first so the two modes never overlap.
    this.logout();
    const { license } = result;
    this._licenseKey = license.licenseKey;
    // Offline files carry no server session token. The explicit session kind
    // (not a token sentinel) is what makes isAuthenticated() true and keeps
    // selfBan()/heartbeats from ever contacting the server for this session.
    this._sessionToken = null;
    this._sessionKind = "offline";
    this._sessionExpiresIn = license.expiresAt ? Math.floor(new Date(license.expiresAt).getTime() / 1000) : null;
    this._rawPayloadB64 = result.payloadBase64;
    this._signature = result.signatureBase64;
    this._keyId = license.keyId;
    this._sessionData = { ...license.payload };
    this._appVariables = license.appVariables;
    this._licenseVariables = license.licenseVariables;
    this._offlineLicense = {
      licenseKey: license.licenseKey,
      jti: license.jti,
      keyId: license.keyId,
      issuedAt: license.issuedAt,
      expiresAt: license.expiresAt,
      hwidPolicy: license.hwidPolicy,
      ...(license.label !== undefined ? { label: license.label } : {}),
      ...(license.licenseExpiresAt !== undefined ? { licenseExpiresAt: license.licenseExpiresAt } : {}),
    };
    this._authenticated = true;
  }

  _failSoft(reason, error) {
    if (this.onFailure) {
      try {
        this.onFailure(reason, error);
      } catch {
        // Caller's callback threw; nothing else to do offline.
      }
    }
  }

  async login(licenseKey) {
    if (!licenseKey || typeof licenseKey !== "string") {
      throw new Error("licenseKey must be a non-empty string");
    }
    try {
      await this._validateAndStore(licenseKey);
      this._startHeartbeatOnce();
      return true;
    } catch (error) {
      this._fail("login_failed", error);
      return false;
    }
  }

  async selfBan(options = {}) {
    if (options !== null && typeof options !== "object") {
      throw new Error("options must be an object");
    }
    const opts = options ?? {};
    const blacklistHwid = opts.blacklistHwid !== false;
    const blacklistIp = opts.blacklistIp !== false;
    const requestedRevoke = opts.revokeLicense !== false;
    const sessionTokenOption =
      typeof opts.sessionToken === "string" && opts.sessionToken.trim()
        ? opts.sessionToken.trim()
        : null;
    const licenseKeyOption =
      typeof opts.licenseKey === "string" && opts.licenseKey.trim()
        ? opts.licenseKey.trim()
        : null;

    // An offline session has no server session and must never phone home on
    // its own. Callers who pass an explicit licenseKey/sessionToken are
    // asking about a *different* credential and still get the normal paths.
    if (this._sessionKind === "offline" && !sessionTokenOption && !licenseKeyOption) {
      throw new Error("offline_session");
    }

    const sessionToken = sessionTokenOption || this._sessionToken;

    if (sessionToken) {
      const body = {
        appId: this.appId,
        sessionToken,
        hwid: this._hwid,
        revokeLicense: requestedRevoke,
        blacklistHwid,
        blacklistIp,
      };
      const responseObject = await this._postJson("/auth/selfban", body);
      if (!this._isSuccessStatus(responseObject?.status)) {
        throw new Error(this._extractServerError(responseObject));
      }
      return responseObject;
    }

    const licenseKey = licenseKeyOption || this._licenseKey;
    if (!licenseKey) {
      throw new Error("missing_license_key");
    }
    const body = {
      appId: this.appId,
      appSecret: this.appSecret,
      licenseKey,
      hwid: this._hwid,
      nonce: this._generateNonce(),
      revokeLicense: false,
      blacklistHwid,
      blacklistIp,
    };
    const responseObject = await this._postJson("/auth/selfban", body);
    if (!this._isSuccessStatus(responseObject?.status)) {
      throw new Error(this._extractServerError(responseObject));
    }
    return responseObject;
  }

  logout() {
    if (this._heartbeatTimer !== null) {
      clearIntervalTimer(this._heartbeatTimer);
    }
    this._heartbeatTimer = null;
    this._heartbeatStarted = false;

    this._licenseKey = null;
    this._sessionToken = null;
    this._sessionKind = null;
    this._sessionExpiresIn = null;
    this._lastNonce = null;
    this._rawPayloadB64 = null;
    this._signature = null;
    this._keyId = null;
    this._sessionData = null;
    this._appVariables = null;
    this._licenseVariables = null;
    this._authenticated = false;
    this._offlineLicense = null;
  }

  isAuthenticated() {
    if (!this._authenticated) {
      return false;
    }
    switch (this._sessionKind) {
      case "online":
        return Boolean(this._sessionToken);
      case "offline":
        return true;
      case null:
        return false;
      default:
        return false;
    }
  }

  getSessionData() {
    return this._sessionData ? { ...this._sessionData } : null;
  }

  getAppVariables() {
    return this._appVariables ? { ...this._appVariables } : null;
  }

  getLicenseVariables() {
    return this._licenseVariables ? { ...this._licenseVariables } : null;
  }

  _startHeartbeatOnce() {
    // Offline sessions have no grace period and no online check-ins: the
    // file's own expiresAt is the only clock. Never start a timer for them.
    if (this._heartbeatStarted || this._sessionKind === "offline") {
      return;
    }
    this._heartbeatStarted = true;
    this._heartbeatTimer = setIntervalTimer(() => {
      this._heartbeatTick().catch(() => {
        // _heartbeatTick handles failures and interval clearing.
      });
    }, this.heartbeatInterval * 1000);
  }

  async _heartbeatTick() {
    if (this._sessionKind === "offline") {
      return;
    }
    try {
      if (this.onlineHeartbeat) {
        await this._serverHeartbeat();
      } else {
        this._gracePeriodCheck();
      }
    } catch (error) {
      this._fail("heartbeat_failed", error);
      if (this._heartbeatTimer !== null) {
        clearIntervalTimer(this._heartbeatTimer);
      }
      this._heartbeatTimer = null;
      this._heartbeatStarted = false;
    }
  }

  async _serverHeartbeat() {
    const sessionToken = this._sessionToken;
    if (!sessionToken) {
      throw new Error("missing_session_token");
    }
    const body = {
      appId: this.appId,
      sessionToken,
      nonce: this._generateNonce(),
      hwid: this._hwid,
    };
    const responseObject = await this._postJson("/auth/heartbeat", body);
    const expectedNonce = String(body.nonce ?? "").trim();
    this._applySignedResponse(responseObject, expectedNonce, null, "heartbeat");
  }

  /**
   * Grace period check: without any network call, re-verify the signed
   * session obtained from activate/validate and fail once the session TTL
   * (the grace period) has expired.
   */
  _gracePeriodCheck() {
    const rawPayloadB64 = this._rawPayloadB64;
    const signature = this._signature;
    const expiresIn = this._sessionExpiresIn;

    if (!rawPayloadB64 || !signature) {
      throw new Error("missing_local_verification_state");
    }

    this._verifySignature(rawPayloadB64, signature);
    if (expiresIn === null) {
      throw new Error("missing_session_expiry");
    }

    const now = Math.floor(Date.now() / 1000);
    if (now >= Number.parseInt(String(expiresIn), 10)) {
      throw new Error("session_expired");
    }
  }

  async _validateAndStore(licenseKey) {
    const body = {
      appId: this.appId,
      appSecret: this.appSecret,
      licenseKey,
      hwid: this._hwid,
      nonce: this._generateNonce(),
    };
    if (this.ttlSeconds !== null) {
      body.ttlSeconds = this.ttlSeconds;
    }
    const responseObject = await this._postJson("/auth/validate", body);
    const expectedNonce = String(body.nonce ?? "").trim();
    this._applySignedResponse(responseObject, expectedNonce, licenseKey, "validate");
  }

  /**
   * Validates a license with the same request and Ed25519 verification as login,
   * without mutating session state or starting heartbeats.
   */
  async validateLicense(licenseKey) {
    if (!licenseKey || typeof licenseKey !== "string") {
      throw new Error("licenseKey must be a non-empty string");
    }
    try {
      const body = {
        appId: this.appId,
        appSecret: this.appSecret,
        licenseKey,
        hwid: this._hwid,
        nonce: this._generateNonce(),
      };
      if (this.ttlSeconds !== null) {
        body.ttlSeconds = this.ttlSeconds;
      }
      const responseObject = await this._postJson("/auth/validate", body, { skipFailureHook: true });
      const expectedNonce = String(body.nonce ?? "").trim();
      const parsed = this._parseValidateSuccess(responseObject, expectedNonce);
      return {
        valid: true,
        sessionToken: parsed.sessionToken,
        expiresIn: parsed.expiresIn,
        sessionData: parsed.sessionData,
        appVariables: parsed.appVariables,
        licenseVariables: parsed.licenseVariables,
        keyId: parsed.keyId,
        ...(parsed.sessionExpiresAt !== undefined ? { sessionExpiresAt: parsed.sessionExpiresAt } : {}),
        ...(parsed.licenseExpiresAt !== undefined ? { licenseExpiresAt: parsed.licenseExpiresAt } : {}),
        ...(parsed.maxHwidSlots !== undefined ? { maxHwidSlots: parsed.maxHwidSlots } : {}),
        ...(parsed.hwidCount !== undefined ? { hwidCount: parsed.hwidCount } : {}),
        ...(parsed.licenseLabel !== undefined ? { licenseLabel: parsed.licenseLabel } : {}),
      };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      return { valid: false, code: err.message, error: err };
    }
  }

  _parseValidateSuccess(responseObject, expectedNonce) {
    if (!this._isSuccessStatus(responseObject?.status)) {
      throw new Error(this._extractServerError(responseObject));
    }

    const rawPayloadB64 = this._requireStr(responseObject, "payload");
    const signature = this._requireStr(responseObject, "signature");
    const payloadObject = this._decodePayloadJson(rawPayloadB64);

    const receivedNonce = String(payloadObject.nonce ?? "").trim();
    if (receivedNonce !== expectedNonce) {
      throw new Error("nonce_mismatch");
    }

    this._verifySignature(rawPayloadB64, signature);

    const sessionToken = String(payloadObject.sessionToken ?? "").trim();
    if (!sessionToken) {
      throw new Error("missing_sessionToken");
    }

    const expiresFromToken = this._extractExpiresInFromSessionToken(sessionToken);
    const expiresFromPayload = payloadObject.expiresIn;
    let expiresIn = expiresFromToken;

    if (expiresIn === null && expiresFromPayload !== undefined && expiresFromPayload !== null) {
      expiresIn = Number.parseInt(String(expiresFromPayload), 10);
    }
    if (expiresIn === null || Number.isNaN(expiresIn)) {
      throw new Error("missing_expiresIn");
    }

    const keyId = typeof responseObject?.keyId === "string" ? responseObject.keyId : null;
    /** @type {Record<string, unknown>} */
    const extra = {};
    if (typeof payloadObject.sessionExpiresAt === "string" && payloadObject.sessionExpiresAt !== "") {
      extra.sessionExpiresAt = payloadObject.sessionExpiresAt;
    }
    if (Object.hasOwn(payloadObject, "licenseExpiresAt")) {
      const le = payloadObject.licenseExpiresAt;
      extra.licenseExpiresAt = typeof le === "string" ? le : null;
    }
    if (payloadObject.maxHwidSlots !== undefined && payloadObject.maxHwidSlots !== null) {
      const n = Number.parseInt(String(payloadObject.maxHwidSlots), 10);
      if (!Number.isNaN(n)) {
        extra.maxHwidSlots = n;
      }
    }
    if (payloadObject.hwidCount !== undefined && payloadObject.hwidCount !== null) {
      const n = Number.parseInt(String(payloadObject.hwidCount), 10);
      if (!Number.isNaN(n)) {
        extra.hwidCount = n;
      }
    }
    if (typeof payloadObject.licenseLabel === "string" && payloadObject.licenseLabel !== "") {
      extra.licenseLabel = payloadObject.licenseLabel;
    }
    return {
      sessionToken,
      expiresIn: Number.parseInt(String(expiresIn), 10),
      sessionData: { ...payloadObject },
      appVariables: this._extractOptionalMap(payloadObject.appVariables),
      licenseVariables: this._extractOptionalMap(payloadObject.licenseVariables),
      keyId,
      rawPayloadB64,
      signature,
      ...extra,
    };
  }

  _applySignedResponse(responseObject, expectedNonce, licenseKey, context = "validate") {
    const parsed = this._parseValidateSuccess(responseObject, expectedNonce);
    void context;

    if (licenseKey !== null) {
      this._licenseKey = licenseKey;
    }
    this._sessionToken = parsed.sessionToken;
    this._sessionKind = "online";
    this._sessionExpiresIn = parsed.expiresIn;
    this._lastNonce = expectedNonce;
    this._rawPayloadB64 = parsed.rawPayloadB64;
    this._signature = parsed.signature;
    this._keyId = parsed.keyId;
    this._sessionData = parsed.sessionData;
    this._appVariables = parsed.appVariables;
    this._licenseVariables = parsed.licenseVariables;
    this._authenticated = true;
  }

  async _postJson(path, data, options = {}) {
    const skipFailureHook = Boolean(options.skipFailureHook);
    const url = `${this.apiBaseUrl}${path}`;
    const body = { ...data };
    let rateAttempt = 0;

    while (true) {
      if (rateAttempt > 0 && Object.hasOwn(body, "nonce")) {
        body.nonce = this._generateNonce();
      }

      let networkAttempt = 0;
      let parsedResponse = null;
      let lastStatusCode = 0;

      while (true) {
        let statusCode = 0;
        let raw = "";
        try {
          ({ statusCode, raw } = await postJson(url, body, this.requestTimeout));
        } catch (error) {
          if (networkAttempt === 0) {
            networkAttempt += 1;
            await sleepSeconds(NETWORK_RETRY_DELAY);
            continue;
          }
          if (!skipFailureHook) {
            this._fail("network_error", error);
          }
          throw new Error(`url_error: ${error}`);
        }

        lastStatusCode = statusCode;
        if (statusCode >= 400) {
          try {
            parsedResponse = this._parseResponseObject(raw);
          } catch {
            throw new Error(`http_error_${statusCode}`);
          }
        } else {
          parsedResponse = this._parseResponseObject(raw);
        }

        for (const key of Object.keys(data)) {
          delete data[key];
        }
        Object.assign(data, body);
        break;
      }

      const isRateLimited =
        lastStatusCode === 429 ||
        this._extractServerError(parsedResponse) === "rate_limited";
      if (isRateLimited && rateAttempt < RATE_LIMIT_RETRY_DELAYS.length) {
        await sleepSeconds(RATE_LIMIT_RETRY_DELAYS[rateAttempt]);
        rateAttempt += 1;
        continue;
      }
      return parsedResponse;
    }
  }

  _parseResponseObject(rawResponse) {
    let parsed;
    try {
      parsed = JSON.parse(rawResponse);
    } catch (error) {
      throw new Error("invalid_json_response", { cause: error });
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("response_not_json_object");
    }
    return parsed;
  }

  _getHwid() {
    const mac = this._safeMacAddress();
    const cpu = this._safeCpuInfo();
    const host = this._safeHostname();
    const material = `mac:${mac}|cpu:${cpu}|host:${host}`;
    return createHash("sha256").update(material, "utf8").digest("hex");
  }

  _resolveHwid(hwidOverride) {
    if (typeof hwidOverride === "string") {
      const trimmed = hwidOverride.trim();
      if (trimmed) {
        return trimmed;
      }
    }
    return this._getHwid();
  }

  _safeMacAddress() {
    try {
      const interfaces = os.networkInterfaces() ?? {};
      for (const entries of Object.values(interfaces)) {
        if (!entries) {
          continue;
        }
        for (const entry of entries) {
          if (!entry || entry.internal) {
            continue;
          }
          const mac = String(entry.mac ?? "").trim();
          if (mac && mac !== "00:00:00:00:00:00") {
            return mac.toLowerCase();
          }
        }
      }
      return "unavailable";
    } catch {
      return "unavailable";
    }
  }

  _safeCpuInfo() {
    try {
      const cpuModel = os.cpus()?.[0]?.model;
      return String(cpuModel || "unavailable");
    } catch {
      return "unavailable";
    }
  }

  _safeHostname() {
    try {
      return String(os.hostname() || "unavailable");
    } catch {
      return "unavailable";
    }
  }

  _decodePayloadJson(payloadB64) {
    const payloadBytes = this._decodeBase64Any(payloadB64);
    let payloadObj;
    try {
      payloadObj = JSON.parse(payloadBytes.toString("utf8"));
    } catch (error) {
      throw new Error("invalid_payload_json", { cause: error });
    }
    if (!payloadObj || typeof payloadObj !== "object" || Array.isArray(payloadObj)) {
      throw new Error("payload_not_json_object");
    }
    return payloadObj;
  }

  _decodeBase64Any(value) {
    const padded = this._addBase64Padding(value);
    try {
      return Buffer.from(padded, "base64");
    } catch {
      const urlSafe = padded.replace(/-/g, "+").replace(/_/g, "/");
      return Buffer.from(urlSafe, "base64");
    }
  }

  _decodeSessionTokenBody(sessionToken) {
    const parts = String(sessionToken).split(".");
    if (parts.length < 2) {
      return null;
    }
    const payloadPart = this._addBase64Padding(parts[0]).replace(/-/g, "+").replace(/_/g, "/");
    try {
      const decoded = Buffer.from(payloadPart, "base64").toString("utf8");
      const payload = JSON.parse(decoded);
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        return null;
      }
      return payload;
    } catch {
      return null;
    }
  }

  _extractExpiresInFromSessionToken(sessionToken) {
    const payload = this._decodeSessionTokenBody(sessionToken);
    if (!payload || payload.exp === undefined || payload.exp === null) {
      return null;
    }
    const value = Number.parseInt(String(payload.exp), 10);
    return Number.isNaN(value) ? null : value;
  }

  _addBase64Padding(text) {
    const remainder = text.length % 4;
    if (remainder === 0) {
      return text;
    }
    return `${text}${"=".repeat(4 - remainder)}`;
  }

  _verifySignature(rawPayloadB64, signature) {
    const sigBuf = Buffer.from(String(signature).trim(), "base64");
    const payloadBuf = Buffer.from(rawPayloadB64, "utf8");
    for (const key of this.publicKeys) {
      let isValid = false;
      try {
        isValid = verify(null, payloadBuf, createEd25519PublicKey(key), sigBuf);
      } catch {
        // Malformed entry — skip and try the next.
      }
      if (isValid) return;
    }
    throw new Error("signature_mismatch");
  }

  _generateNonce() {
    return randomBytes(16).toString("hex");
  }

  _isSuccessStatus(status) {
    if (typeof status === "boolean") {
      return status;
    }
    if (status === null || status === undefined) {
      return false;
    }
    return SUCCESS_STATUSES.has(String(status).trim().toLowerCase());
  }

  _requireStr(obj, key) {
    const value = obj?.[key];
    if (value === null || value === undefined) {
      throw new Error(`missing_${key}`);
    }
    const text = String(value);
    if (!text) {
      throw new Error(`empty_${key}`);
    }
    return text;
  }

  _extractServerError(obj) {
    const rawError = String(obj?.error ?? "").trim().toLowerCase();
    if (KNOWN_SERVER_ERRORS.has(rawError)) {
      return rawError;
    }
    const status = String(obj?.status ?? "").trim().toLowerCase();
    if (KNOWN_SERVER_ERRORS.has(status)) {
      return status;
    }
    return "unknown_error";
  }

  _extractOptionalMap(value) {
    return cloneObject(value);
  }

  _fail(reason, error = null) {
    if (this.onFailure) {
      try {
        this.onFailure(reason, error);
        return;
      } catch {
        // Fall through to process exit if callback throws.
      }
    }
    process.exit(1);
  }
}

export const knownServerErrors = [...KNOWN_SERVER_ERRORS];
