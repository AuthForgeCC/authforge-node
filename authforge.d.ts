export type HeartbeatMode = "SERVER" | "LOCAL";

export interface SessionData {
  [key: string]: unknown;
}

export interface VariableMap {
  [key: string]: unknown;
}

export interface AuthForgeClientOptions {
  appId: string;
  /**
   * Required for online APIs (`login`, `validateLicense`, `selfBan`).
   * Omit, or pass `""` / `null`, for offline-only clients (`loginFromFile`).
   * Air-gapped builds should not ship the App Secret.
   */
  appSecret?: string | null;
  /**
   * Trusted Ed25519 public key(s). Pass a single base64 string for the common
   * case, or an array (current key first, previous key(s) after) to remain
   * verifying during a server-side rotation. A comma-separated string is also
   * accepted for environment-variable convenience.
   */
  publicKey: string | readonly string[];
  /**
   * Enable online check-ins: periodic POST /auth/heartbeat calls for fast
   * revocation and concurrent-use detection. Defaults to `false`, which means
   * the client runs through the grace period on the signed session without
   * contacting AuthForge until the session TTL expires.
   */
  onlineHeartbeat?: boolean;
  /**
   * @deprecated Use `onlineHeartbeat: true` for online check-ins; the default
   * is the grace period behavior. "SERVER" maps to `onlineHeartbeat: true`,
   * "LOCAL" maps to the default.
   */
  heartbeatMode?: string;
  heartbeatInterval?: number;
  apiBaseUrl?: string;
  onFailure?: ((reason: string, error: Error | null) => void) | null;
  requestTimeout?: number;
  /**
   * Requested grace period duration in seconds (equals the session token
   * lifetime). Server default is 24h (86400); the server clamps requests to
   * [3600, 604800] (1h to 7d). Omitted/null uses the server default.
   * Online check-ins preserve this TTL.
   */
  ttlSeconds?: number | null;
  /** Custom HWID / identity (e.g. `discord:123`, `tg:456`). */
  hwidOverride?: string | null;
}

export type ValidateLicenseSuccess = {
  valid: true;
  sessionToken: string;
  expiresIn: number;
  sessionData: SessionData;
  appVariables: VariableMap | null;
  licenseVariables: VariableMap | null;
  keyId: string | null;
  /** ISO 8601 session expiry (newer servers). */
  sessionExpiresAt?: string;
  /** ISO 8601 license expiry; `null` when key is lifetime (explicit JSON null). */
  licenseExpiresAt?: string | null;
  maxHwidSlots?: number;
  hwidCount?: number;
  licenseLabel?: string;
};

export type ValidateLicenseFailure = {
  valid: false;
  /** Machine-readable code (e.g. invalid_key, signature_mismatch, url_error: …). */
  code: string;
  error: Error;
};

export type ValidateLicenseResult = ValidateLicenseSuccess | ValidateLicenseFailure;

export declare function verifyPayloadSignatureEd25519(
  payloadBase64: string,
  signatureBase64: string,
  publicKey: string | readonly string[],
): boolean;

// ---------------------------------------------------------------------------
// Offline license files (`.authforge`) - separate mode from the grace period.
// ---------------------------------------------------------------------------

export type OfflineHwidPolicy = { mode: "bound"; hwids: string[] } | { mode: "any" };

export type OfflineLicenseError =
  | "bad_armor"
  | "bad_signature"
  | "unsupported_version"
  | "malformed_payload"
  | "wrong_app"
  | "expired"
  | "hwid_mismatch";

export interface OfflineLicense {
  appId: string;
  licenseKey: string;
  /** Unique id of this minted file. */
  jti: string;
  /** App signing key id that signed the file. */
  keyId: string;
  issuedAt: string;
  /** ISO 8601 file expiry, or `null` for a lifetime file. */
  expiresAt: string | null;
  hwidPolicy: OfflineHwidPolicy;
  label?: string;
  licenseExpiresAt?: string | null;
  licenseVariables: VariableMap | null;
  appVariables: VariableMap | null;
  /** Full decoded payload (forward-compatible: unknown fields preserved). */
  payload: SessionData;
}

export type VerifyLicenseFileResult =
  | { ok: true; license: OfflineLicense; payloadBase64: string; signatureBase64: string }
  | { ok: false; error: OfflineLicenseError | string };

export interface ParsedLicenseFile {
  headers: Record<string, string>;
  payloadBase64: string;
  signatureBase64: string;
}

/** Parse armored `.authforge` text; `null` when the armor is malformed. */
export declare function parseLicenseFile(text: string): ParsedLicenseFile | null;

export interface ActivationRequestFields {
  appId: string;
  hwid: string;
  createdAt: string;
  machineName?: string;
  os?: string;
  sdk?: string;
  licenseKey?: string;
}

export interface CreateActivationRequestOptions {
  /** Include hostname. Off by default — hostnames are often a person's name. */
  includeMachineName?: boolean;
  machineName?: string;
  os?: string;
  omitOs?: boolean;
  sdk?: string;
  omitSdk?: boolean;
  licenseKey?: string;
  /** Test override. Default is now (UTC, millisecond `Z`). */
  createdAt?: string;
}

/** Armored `.authforge-request` text from explicit fields. */
export declare function formatActivationRequest(fields: ActivationRequestFields): string;

/**
 * Verify a `.authforge` file locally (no network). Check order:
 * bad_armor -> bad_signature -> unsupported_version -> malformed_payload ->
 * wrong_app -> expired -> hwid_mismatch.
 */
export declare function verifyLicenseFile(params: {
  file: string;
  appId: string;
  publicKey: string | readonly string[];
  hwid?: string | null;
  now?: Date | number;
}): VerifyLicenseFileResult;

export declare const offlineLicenseErrors: readonly OfflineLicenseError[];

/** How the client authenticated: server session (`login`) or local file (`loginFromFile`). */
export type SessionKind = "online" | "offline";

export interface OfflineLicenseSummary {
  licenseKey: string;
  jti: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string | null;
  hwidPolicy: OfflineHwidPolicy;
  label?: string;
  licenseExpiresAt?: string | null;
}

export declare class AuthForgeClient {
  constructor(options: AuthForgeClientOptions);
  constructor(
    appId: string,
    appSecret: string | null | undefined,
    publicKey: string | readonly string[],
    heartbeatMode?: string,
    heartbeatInterval?: number,
    apiBaseUrl?: string,
    onFailure?: ((reason: string, error: Error | null) => void) | null,
    requestTimeout?: number,
    ttlSeconds?: number | null,
  );

  readonly appId: string;
  readonly appSecret: string;
  /** Primary (first) trusted public key. See `publicKeys` for the full list. */
  readonly publicKey: string;
  readonly publicKeys: readonly string[];
  /**
   * Effective policy: `true` when online check-ins are enabled, `false` when
   * the client relies on the grace period.
   */
  readonly onlineHeartbeat: boolean;
  /**
   * @deprecated Read `onlineHeartbeat` instead. "SERVER" when online
   * check-ins are enabled, "LOCAL" otherwise.
   */
  readonly heartbeatMode: HeartbeatMode;
  readonly heartbeatInterval: number;
  readonly apiBaseUrl: string;
  readonly onFailure: ((reason: string, error: Error | null) => void) | null;
  readonly requestTimeout: number;
  readonly ttlSeconds: number | null;

  login(licenseKey: string): Promise<boolean>;
  /**
   * Same cryptographic validation as login, without session mutation or heartbeats.
   */
  validateLicense(licenseKey: string): Promise<ValidateLicenseResult>;
  /**
   * Authorize from an offline `.authforge` license file (path or armored text)
   * with no network access. Never starts the grace-period timer or online
   * check-ins. Failures call `onFailure("offline_login_failed", error)` and
   * return `false` (never `process.exit`).
   */
  loginFromFile(pathOrText: string): boolean;
  /** Verify a `.authforge` file with this client's app id / keys / HWID; no state change. */
  verifyLicenseFile(pathOrText: string, options?: { now?: Date | number }): VerifyLicenseFileResult;
  /** Offline file the client authenticated with, or `null`. */
  getOfflineLicense(): OfflineLicenseSummary | null;
  /** HWID sent to AuthForge (or `hwidOverride`). Share it with the operator to get a bound file. */
  getHwid(): string;
  /**
   * Activation request (`.authforge-request`) for this machine. No network,
   * no app secret. `machineName` is omitted unless `includeMachineName` is true.
   */
  createActivationRequest(options?: CreateActivationRequestOptions): string;
  /** Write an activation request to `path`. */
  writeActivationRequest(path: string, options?: CreateActivationRequestOptions): void;
  logout(): void;
  /** `true` for an online session (login) or an offline one (loginFromFile). */
  isAuthenticated(): boolean;
  /**
   * Which kind of session the client holds: `"online"` after `login()`,
   * `"offline"` after `loginFromFile()`, `null` when logged out. `selfBan()`
   * without an explicit `licenseKey`/`sessionToken` throws `offline_session`
   * on an offline session and never contacts the server.
   */
  getSessionKind(): SessionKind | null;
  getSessionData(): SessionData | null;
  getAppVariables(): VariableMap | null;
  getLicenseVariables(): VariableMap | null;
}

export declare const knownServerErrors: string[];
