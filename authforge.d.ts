export type HeartbeatMode = "SERVER" | "LOCAL";

export interface SessionData {
  [key: string]: unknown;
}

export interface VariableMap {
  [key: string]: unknown;
}

export interface AuthForgeClientOptions {
  appId: string;
  appSecret: string;
  publicKey: string;
  heartbeatMode: string;
  heartbeatInterval?: number;
  apiBaseUrl?: string;
  onFailure?: ((reason: string, error: Error | null) => void) | null;
  requestTimeout?: number;
  /**
   * Requested session token lifetime in seconds. Server clamps to
   * [3600, 604800]; out-of-range values are silently clamped.
   * Omitted/null → server default (24h). Heartbeats preserve this TTL.
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
  publicKeyBase64: string,
): boolean;

export declare class AuthForgeClient {
  constructor(options: AuthForgeClientOptions);
  constructor(
    appId: string,
    appSecret: string,
    publicKey: string,
    heartbeatMode: string,
    heartbeatInterval?: number,
    apiBaseUrl?: string,
    onFailure?: ((reason: string, error: Error | null) => void) | null,
    requestTimeout?: number,
    ttlSeconds?: number | null,
  );

  readonly appId: string;
  readonly appSecret: string;
  readonly publicKey: string;
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
  logout(): void;
  isAuthenticated(): boolean;
  getSessionData(): SessionData | null;
  getAppVariables(): VariableMap | null;
  getLicenseVariables(): VariableMap | null;
}

export declare const knownServerErrors: string[];
