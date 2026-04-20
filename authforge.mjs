import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
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
  "bad_request",
  "server_error",
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

export function verifyPayloadSignatureEd25519(payloadBase64, signatureBase64, publicKeyBase64) {
  const isValid = verify(
    null,
    Buffer.from(payloadBase64, "utf8"),
    createEd25519PublicKey(publicKeyBase64),
    Buffer.from(signatureBase64, "base64"),
  );
  return isValid;
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
  ) {
    if (appId && typeof appId === "object" && !Array.isArray(appId)) {
      const options = appId;
      appId = options.appId;
      appSecret = options.appSecret;
      publicKey = options.publicKey;
      heartbeatMode = options.heartbeatMode;
      heartbeatInterval = options.heartbeatInterval ?? 900;
      apiBaseUrl = options.apiBaseUrl ?? DEFAULT_API_BASE_URL;
      onFailure = options.onFailure ?? null;
      requestTimeout = options.requestTimeout ?? 15;
    }

    if (!appId || typeof appId !== "string") {
      throw new Error("appId must be a non-empty string");
    }
    if (!appSecret || typeof appSecret !== "string") {
      throw new Error("appSecret must be a non-empty string");
    }
    if (!publicKey || typeof publicKey !== "string") {
      throw new Error("publicKey must be a non-empty string");
    }
    const mode = String(heartbeatMode ?? "").toUpperCase();
    if (mode !== "LOCAL" && mode !== "SERVER") {
      throw new Error("heartbeatMode must be LOCAL or SERVER");
    }
    if (heartbeatInterval <= 0) {
      throw new Error("heartbeatInterval must be > 0");
    }

    this.appId = appId;
    this.appSecret = appSecret;
    this.publicKey = publicKey;
    this.heartbeatMode = mode;
    this.heartbeatInterval = Number.parseInt(String(heartbeatInterval), 10);
    this.apiBaseUrl = String(apiBaseUrl).replace(/\/+$/, "");
    this.onFailure = typeof onFailure === "function" ? onFailure : null;
    this.requestTimeout = requestTimeout;

    this._heartbeatTimer = null;
    this._heartbeatStarted = false;

    this._licenseKey = null;
    this._sessionToken = null;
    this._sessionExpiresIn = null;
    this._lastNonce = null;
    this._rawPayloadB64 = null;
    this._signature = null;
    this._keyId = null;
    this._sessionData = null;
    this._appVariables = null;
    this._licenseVariables = null;
    this._authenticated = false;
    this._hwid = this._getHwid();
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

  logout() {
    if (this._heartbeatTimer !== null) {
      clearIntervalTimer(this._heartbeatTimer);
    }
    this._heartbeatTimer = null;
    this._heartbeatStarted = false;

    this._licenseKey = null;
    this._sessionToken = null;
    this._sessionExpiresIn = null;
    this._lastNonce = null;
    this._rawPayloadB64 = null;
    this._signature = null;
    this._keyId = null;
    this._sessionData = null;
    this._appVariables = null;
    this._licenseVariables = null;
    this._authenticated = false;
  }

  isAuthenticated() {
    return this._authenticated && Boolean(this._sessionToken);
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
    if (this._heartbeatStarted) {
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
    try {
      if (this.heartbeatMode === "SERVER") {
        await this._serverHeartbeat();
      } else {
        this._localHeartbeat();
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

  _localHeartbeat() {
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
    const responseObject = await this._postJson("/auth/validate", body);
    const expectedNonce = String(body.nonce ?? "").trim();
    this._applySignedResponse(responseObject, expectedNonce, licenseKey, "validate");
  }

  _applySignedResponse(responseObject, expectedNonce, licenseKey, context = "validate") {
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

    if (licenseKey !== null) {
      this._licenseKey = licenseKey;
    }
    this._sessionToken = sessionToken;
    this._sessionExpiresIn = Number.parseInt(String(expiresIn), 10);
    this._lastNonce = expectedNonce;
    this._rawPayloadB64 = rawPayloadB64;
    this._signature = signature;
    this._keyId = typeof responseObject?.keyId === "string" ? responseObject.keyId : null;
    this._sessionData = { ...payloadObject };
    this._appVariables = this._extractOptionalMap(payloadObject.appVariables);
    this._licenseVariables = this._extractOptionalMap(payloadObject.licenseVariables);
    this._authenticated = true;
  }

  async _postJson(path, data) {
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
          this._fail("network_error", error);
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
    const isValid = verify(
      null,
      Buffer.from(rawPayloadB64, "utf8"),
      createEd25519PublicKey(this.publicKey),
      Buffer.from(String(signature).trim(), "base64"),
    );
    if (!isValid) {
      throw new Error("signature_mismatch");
    }
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
