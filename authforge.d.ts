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
  heartbeatMode: string;
  heartbeatInterval?: number;
  apiBaseUrl?: string;
  onFailure?: ((reason: string, error: Error | null) => void) | null;
  requestTimeout?: number;
}

export declare function deriveSigningKey(appSecret: string, nonce: string): Buffer;
export declare function signPayload(payloadBase64: string, key: Buffer): string;

export declare class AuthForgeClient {
  constructor(options: AuthForgeClientOptions);
  constructor(
    appId: string,
    appSecret: string,
    heartbeatMode: string,
    heartbeatInterval?: number,
    apiBaseUrl?: string,
    onFailure?: ((reason: string, error: Error | null) => void) | null,
    requestTimeout?: number,
  );

  readonly appId: string;
  readonly appSecret: string;
  readonly heartbeatMode: HeartbeatMode;
  readonly heartbeatInterval: number;
  readonly apiBaseUrl: string;
  readonly onFailure: ((reason: string, error: Error | null) => void) | null;
  readonly requestTimeout: number;

  login(licenseKey: string): Promise<boolean>;
  logout(): void;
  isAuthenticated(): boolean;
  getSessionData(): SessionData | null;
  getAppVariables(): VariableMap | null;
  getLicenseVariables(): VariableMap | null;
}

export declare const knownServerErrors: string[];
