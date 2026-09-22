import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
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
  "demo_quota_exceeded",
  "system_error",
]);

// The only codes that are a definitive verdict on the session or license.
// Every other code, including ones this SDK version doesn't know, is transient.
const DEFINITIVE_ERROR_CODES = new Set([
  "revoked",
  "expired",
  "hwid_mismatch",
  "blocked",
  "session_expired",
  "malformed_request",
  "app_disabled",
  "invalid_app",
  "signature_mismatch",
]);

// Documentation only: named codes known to be transient. Classification is
// "not in DEFINITIVE_ERROR_CODES", so http_error_<status> and unknown codes
// are transient too.
const TRANSIENT_ERROR_CODES = new Set([
  "network_error",
  "timeout",
  "rate_limited",
  "system_error",
  "server_error",
  "handler_error",
  "invalid_json_response",
  "response_not_json_object",
  "unexpected_response",
  "no_credits",
  "demo_quota_exceeded",
  "app_burn_cap_reached",
  "bad_request",
  "invalid_key",
  "replay_detected",
  "revoke_requires_session",
  "missing_session_token",
  "nonce_mismatch",
  "unknown_error",
]);
const SERVER_ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

const SUCCESS_STATUSES = new Set(["ok", "success", "valid", "true", "1"]);

/**
 * Classify a failure code (or an `AuthForgeError`). Only the definitive
 * allowlist (`definitiveErrorCodes`) is fatal; every other code is transient,
 * including `http_error_<status>`, `no_credits` and unknown codes. Values that
 * are neither a string nor an `AuthForgeError` carry no verdict and count as
 * transient.
 */
export function isTransientError(errorOrCode) {
  const code = errorOrCode instanceof AuthForgeError ? errorOrCode.code : errorOrCode;
  if (typeof code !== "string") return true;
  return !DEFINITIVE_ERROR_CODES.has(code);
}

/**
 * A failure with a machine-readable `code`: the server's error code
 * (`revoked`, `hwid_mismatch`, ...) or an SDK code (`network_error`,
 * `timeout`, `http_error_502`, `unexpected_response`, ...). `message` equals
 * `code` for server errors.
 */
export class AuthForgeError extends Error {
  constructor(code, message = code, options = undefined) {
    super(message, options);
    this.name = "AuthForgeError";
    this.code = code;
  }

  /** True when retrying later can succeed. */
  get transient() {
    return isTransientError(this.code);
  }

  /** True when AuthForge definitively rejected the session or license. */
  get fatal() {
    return !this.transient;
  }
}

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
const ARMOR_LINE_WIDTH = 64;

// Activation requests (`.authforge-request`): unsigned transport for a HWID so
// the operator can mint a bound `.authforge` file without the customer pasting
// a raw string. Distinct markers from BEGIN AUTHFORGE LICENSE. Not signed;
// the Checksum header is the only integrity check. Keep SDK_TAG in sync with
// package.json version.
const ACTIVATION_REQUEST_VERSION = 1;
const ACTIVATION_REQUEST_TYP = "authforge-activation-request";
const BEGIN_ACTIVATION_REQUEST = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----";
const END_ACTIVATION_REQUEST = "-----END AUTHFORGE ACTIVATION REQUEST-----";
const SDK_TAG = "node/1.4.0";
const MAX_REQUEST_HWID = 256;
const MAX_REQUEST_MACHINE_NAME = 128;
const MAX_REQUEST_OS = 64;
const MAX_REQUEST_SDK = 64;
const MAX_REQUEST_LICENSE_KEY = 64;

function clipRequestField(value, max) {
  if (typeof value !== "string" || value.length === 0) return "";
  return value.length <= max ? value : value.slice(0, max);
}

function jsonEscapeRequest(value) {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const ch = value[i];
    switch (ch) {
      case "\\":
        out += "\\\\";
        break;
      case '"':
        out += '\\"';
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default:
        if (code < 0x20) {
          out += `\\u00${code.toString(16).padStart(2, "0")}`;
        } else {
          out += ch;
        }
    }
  }
  return `"${out}"`;
}

function wrapArmor64(value) {
  const lines = [];
  for (let i = 0; i < value.length; i += ARMOR_LINE_WIDTH) {
    lines.push(value.slice(i, i + ARMOR_LINE_WIDTH));
  }
  return lines.join("\n");
}

function canonicalActivationRequestJson({ appId, hwid, createdAt, machineName, os: osName, sdk, licenseKey }) {
  const parts = [
    `"v":${ACTIVATION_REQUEST_VERSION}`,
    `"typ":${jsonEscapeRequest(ACTIVATION_REQUEST_TYP)}`,
    `"appId":${jsonEscapeRequest(appId)}`,
    `"hwid":${jsonEscapeRequest(clipRequestField(hwid, MAX_REQUEST_HWID))}`,
    `"createdAt":${jsonEscapeRequest(createdAt)}`,
  ];
  if (machineName) parts.push(`"machineName":${jsonEscapeRequest(clipRequestField(machineName, MAX_REQUEST_MACHINE_NAME))}`);
  if (osName) parts.push(`"os":${jsonEscapeRequest(clipRequestField(osName, MAX_REQUEST_OS))}`);
  if (sdk) parts.push(`"sdk":${jsonEscapeRequest(clipRequestField(sdk, MAX_REQUEST_SDK))}`);
  if (licenseKey) parts.push(`"licenseKey":${jsonEscapeRequest(clipRequestField(licenseKey, MAX_REQUEST_LICENSE_KEY))}`);
  return `{${parts.join(",")}}`;
}

function detectOsLabel() {
  switch (process.platform) {
    case "win32":
      return clipRequestField(`Windows ${os.release()}`, MAX_REQUEST_OS);
    case "darwin":
      return clipRequestField(`macOS ${os.release()}`, MAX_REQUEST_OS);
    default:
      return clipRequestField(`${os.type()} ${os.release()}`, MAX_REQUEST_OS);
  }
}

/**
 * Build armored `.authforge-request` text from explicit fields. Exported so
 * the vector generator and tests share one encoder with the client.
 */
export function formatActivationRequest({
  appId,
  hwid,
  createdAt,
  machineName,
  os: osName,
  sdk,
  licenseKey,
}) {
  const json = canonicalActivationRequestJson({
    appId,
    hwid,
    createdAt,
    machineName,
    os: osName,
    sdk,
    licenseKey,
  });
  const payloadBase64 = Buffer.from(json, "utf8").toString("base64");
  const checksum = createHash("sha256").update(payloadBase64, "utf8").digest("hex").slice(0, 16);
  const clean = (value) => String(value).replace(/[\r\n]+/g, " ").trim();
  return [
    BEGIN_ACTIVATION_REQUEST,
    `Version: ${ACTIVATION_REQUEST_VERSION}`,
    `App-Id: ${clean(appId)}`,
    `Checksum: ${checksum}`,
    "",
    wrapArmor64(payloadBase64),
    END_ACTIVATION_REQUEST,
    "",
  ].join("\n");
}

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

  const transport = url.protocol === "http:" ? http : https;
  return new Promise((resolve, reject) => {
    const request = transport.request(options, (response) => {
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
    // Empty/omitted is valid for offline-only clients (loginFromFile).
    // Online APIs (login, validateLicense, selfBan) still require a secret.
    if (appSecret == null || appSecret === undefined) {
      appSecret = "";
    } else if (typeof appSecret !== "string") {
      throw new Error("appSecret must be a string or omitted");
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
    this._heartbeatInFlight = false;
    // Bumped by login() and logout(). A heartbeat captures it when it starts
    // and drops its result if it changed while the request was in flight.
    this._sessionGeneration = 0;

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
   * Build an activation request (`.authforge-request`) for this machine.
   * No network, no session, no app secret. The HWID is the same value
   * `login()` / `loginFromFile()` use. `machineName` is omitted unless
   * `includeMachineName` is true (hostnames are often a person's name).
   *
   * @param {{ includeMachineName?: boolean, machineName?: string, os?: string, omitOs?: boolean, sdk?: string, omitSdk?: boolean, licenseKey?: string, createdAt?: string }} [options]
   */
  createActivationRequest(options = {}) {
    const createdAt = options.createdAt ?? new Date().toISOString();
    const machineName = options.includeMachineName
      ? options.machineName || os.hostname()
      : undefined;
    const osName = options.omitOs ? undefined : (options.os ?? detectOsLabel());
    const sdk = options.omitSdk ? undefined : (options.sdk ?? SDK_TAG);
    const licenseKey =
      options.licenseKey !== undefined ? options.licenseKey : this._licenseKey || undefined;
    return formatActivationRequest({
      appId: this.appId,
      hwid: this._hwid,
      createdAt,
      machineName,
      os: osName,
      sdk,
      licenseKey,
    });
  }

  /**
   * Write an activation request to `path` (UTF-8). Same options as
   * {@link createActivationRequest}.
   */
  writeActivationRequest(filePath, options = {}) {
    writeFileSync(filePath, this.createActivationRequest(options), "utf8");
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

  _requireAppSecret() {
    if (!this.appSecret) {
      throw new Error(
        "appSecret is required for online APIs; omit it only when using loginFromFile",
      );
    }
  }

  async login(licenseKey) {
    if (!licenseKey || typeof licenseKey !== "string") {
      throw new Error("licenseKey must be a non-empty string");
    }
    this._requireAppSecret();
    this._sessionGeneration += 1;
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
    this._requireAppSecret();
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
    this._sessionGeneration += 1;

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

  /**
   * Run one background check. Transient failures are reported and the timer
   * keeps checking in. Definitive failures drop the stored session first, so
   * neither the grace period nor `isAuthenticated()` keeps the app running on
   * it. `onFailure` may call `logout()`, `isAuthenticated()` or `login()`.
   * A check that was in flight when `logout()`/`login()` ran is discarded.
   */
  async _heartbeatTick() {
    if (this._sessionKind === "offline" || this._heartbeatInFlight) {
      return;
    }
    const generation = this._sessionGeneration;
    this._heartbeatInFlight = true;
    let failure = null;
    try {
      if (this.onlineHeartbeat) {
        await this._serverHeartbeat(generation);
      } else {
        this._gracePeriodCheck();
      }
    } catch (error) {
      failure = error;
    } finally {
      this._heartbeatInFlight = false;
    }
    if (failure === null || generation !== this._sessionGeneration) {
      return;
    }
    failure = this._heartbeatError(failure);
    if (failure.fatal) {
      this.logout();
    }
    this._fail("heartbeat_failed", failure);
  }

  _heartbeatError(error) {
    let failure;
    if (error instanceof AuthForgeError) {
      failure = error;
    } else {
      const message = error instanceof Error ? error.message : String(error);
      const code = message.split(":", 1)[0].trim().toLowerCase();
      failure = new AuthForgeError(SERVER_ERROR_CODE_RE.test(code) ? code : "unknown_error", message, {
        cause: error,
      });
    }
    // A transient failure can't extend the session past its signed TTL.
    if (failure.transient && this._localSessionExpired()) {
      return new AuthForgeError("session_expired", "session_expired", { cause: failure });
    }
    return failure;
  }

  _localSessionExpired() {
    if (this._sessionExpiresIn === null) {
      return false;
    }
    return Math.floor(Date.now() / 1000) >= Number.parseInt(String(this._sessionExpiresIn), 10);
  }

  async _serverHeartbeat(generation = this._sessionGeneration) {
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
    // Network failures surface once, as heartbeat_failed / network_error.
    const responseObject = await this._postJson("/auth/heartbeat", body, { skipFailureHook: true });
    if (generation !== this._sessionGeneration) {
      return;
    }
    if (!this._isSuccessStatus(responseObject?.status)) {
      this._requireHeartbeatVerdict(responseObject);
    }
    const expectedNonce = String(body.nonce ?? "").trim();
    this._applySignedResponse(responseObject, expectedNonce, null, "heartbeat");
  }

  /**
   * A failed check-in is an AuthForge verdict only when the body is
   * `{"status": "failed", "error": "<code>"}`. Anything else (a proxy, a
   * captive portal, a half-written reply) is `unexpected_response`.
   */
  _requireHeartbeatVerdict(responseObject) {
    const status = responseObject?.status;
    const error = responseObject?.error;
    const isFailed = typeof status === "string" && status.trim().toLowerCase() === "failed";
    const hasCode = typeof error === "string" && error.trim() !== "";
    if (!isFailed || !hasCode) {
      throw new AuthForgeError(
        "unexpected_response",
        `unexpected_response: status=${JSON.stringify(status ?? null)} error=${JSON.stringify(error ?? null)}`,
      );
    }
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
    this._requireAppSecret();
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
      throw new AuthForgeError(this._extractServerError(responseObject));
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
            await this._sleep(NETWORK_RETRY_DELAY);
            continue;
          }
          if (!skipFailureHook) {
            this._fail("network_error", error);
          }
          const code = error instanceof Error && error.message === "timeout" ? "timeout" : "network_error";
          throw new AuthForgeError(code, `url_error: ${error}`, { cause: error });
        }

        lastStatusCode = statusCode;
        if (statusCode >= 400) {
          try {
            parsedResponse = this._parseResponseObject(raw);
          } catch (error) {
            throw new AuthForgeError(`http_error_${statusCode}`, `http_error_${statusCode}`, { cause: error });
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

      // no_credits / demo_quota_exceeded / app_burn_cap_reached also use
      // HTTP 429 but are not worth retrying; only retry a genuine rate limit.
      const serverError = this._extractServerError(parsedResponse);
      const isRateLimited =
        serverError === "rate_limited" || (lastStatusCode === 429 && serverError === "unknown_error");
      if (isRateLimited && rateAttempt < RATE_LIMIT_RETRY_DELAYS.length) {
        await this._sleep(RATE_LIMIT_RETRY_DELAYS[rateAttempt]);
        rateAttempt += 1;
        continue;
      }
      return parsedResponse;
    }
  }

  _sleep(seconds) {
    return sleepSeconds(seconds);
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
    // Pass through codes this SDK version doesn't know yet instead of
    // collapsing them into unknown_error.
    const rawError = typeof obj?.error === "string" ? obj.error.trim().toLowerCase() : "";
    if (KNOWN_SERVER_ERRORS.has(rawError) || SERVER_ERROR_CODE_RE.test(rawError)) {
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
export const transientErrorCodes = [...TRANSIENT_ERROR_CODES];
export const definitiveErrorCodes = [...DEFINITIVE_ERROR_CODES];
