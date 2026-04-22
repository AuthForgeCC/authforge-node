# AuthForge Node.js SDK

Official Node.js SDK for [AuthForge](https://authforge.cc) - credit-based license key authentication with Ed25519-verified responses.

**Zero dependencies.** Node.js built-ins only. Works on Node.js 18+.

## Quick Start

Install from npm:

```bash
npm install @authforgecc/sdk
```

Then:

```js
import { AuthForgeClient } from "@authforgecc/sdk";

const client = new AuthForgeClient(
  "YOUR_APP_ID", // from your AuthForge dashboard
  "YOUR_APP_SECRET", // from your AuthForge dashboard
  "YOUR_PUBLIC_KEY", // from your AuthForge dashboard
  "SERVER", // "SERVER" or "LOCAL"
);

const licenseKey = process.argv[2];

if (await client.login(licenseKey)) {
  console.log("Authenticated!");
  // Your app logic here - heartbeats run automatically in the background
} else {
  console.error("Invalid license key.");
  process.exit(1);
}
```

You can also copy `authforge.mjs` directly into your project if you prefer a single-file integration.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `appId` | `string` | required | Your application ID from the AuthForge dashboard |
| `appSecret` | `string` | required | Your application secret from the AuthForge dashboard |
| `publicKey` | `string` | required | App Ed25519 public key (base64) from dashboard |
| `heartbeatMode` | `string` | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeatInterval` | `number` | `900` | Seconds between heartbeat checks (any value ≥ 1; default 15 min) |
| `apiBaseUrl` | `string` | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | `function` | `null` | Callback `(reason: string, error: Error \| null)` on auth failure |
| `requestTimeout` | `number` | `15` | HTTP request timeout in seconds |
| `ttlSeconds` | `number \| null` | `null` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |

## Billing

- **1 `login()` call = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats on the same license = 1 credit** (billed every 10th successful heartbeat).

A desktop app running 6h/day at a 15-minute interval burns ~3–4 credits/day. A server app running 24/7 at a 1-minute interval burns ~145 credits/day — pick the interval based on how fast you need revocations to propagate (they always take effect on the **next** heartbeat).

## Methods

| Method | Returns | Description |
| --- | --- | --- |
| `login(licenseKey)` | `Promise<boolean>` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `logout()` | `void` | Stops heartbeat and clears all session/auth state |
| `isAuthenticated()` | `boolean` | `true` when an active authenticated session exists |
| `getSessionData()` | `Record<string, unknown> \| null` | Full decoded payload map |
| `getAppVariables()` | `Record<string, unknown> \| null` | App-scoped variables map |
| `getLicenseVariables()` | `Record<string, unknown> \| null` | License-scoped variables map |

## Heartbeat Modes

**SERVER** - The SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state.

**LOCAL** - No network calls. The SDK re-verifies stored signature state and checks expiry timestamp locally. If expired, it triggers failure with `session_expired`.

## Failure Handling

If authentication fails (login rejected, heartbeat fails, signature mismatch, etc.), the SDK calls your `onFailure` callback if one is provided. If no callback is set, **the SDK calls `process.exit(1)` to terminate the process.** This prevents your app from running without a valid license.

Recognized server errors:
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `bad_request`

Request retries are automatic inside the internal HTTP layer:

- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

```js
const handleAuthFailure = (reason, error) => {
  console.error(`Auth failed: ${reason}`);
  if (error) {
    console.error(`Details: ${error.message}`);
  }
  // Clean up and exit gracefully
  process.exit(1);
};

const client = new AuthForgeClient(
  "YOUR_APP_ID",
  "YOUR_APP_SECRET",
  "YOUR_PUBLIC_KEY",
  "SERVER",
  900,
  "https://auth.authforge.cc",
  handleAuthFailure,
);
```

## How It Works

1. **Login** - Collects a hardware fingerprint (MAC, CPU, hostname), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Heartbeat** - A background interval checks in at the configured cadence. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** - Both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Hardware ID

The SDK generates a deterministic hardware fingerprint by hashing:

- First non-internal MAC address
- CPU model
- Hostname

Material format:
`SHA256("mac:<mac>|cpu:<cpu>|host:<hostname>")`

Each component falls back to `unavailable` if it cannot be read.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior.

## Requirements

- Node.js 18+
- No external packages

## License

MIT
