# AuthForge SDK - AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates online: it sends a license key + hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL.

After activation the client follows one of two policies:

- **Grace period (default)**: the app keeps running on the signed session without contacting AuthForge. The SDK re-verifies the signature and expiry locally in the background and fails once the session TTL expires. The grace period equals the session TTL: default 24h, server clamps requests to 1h to 7d (`ttlSeconds`).
- **Online check-ins (opt-in, `onlineHeartbeat: true`)**: the SDK periodically calls `POST /auth/heartbeat` for fast revocation and concurrent-use detection.

If the license is revoked or expired, the background check fails and you handle it (typically exit the app).

## Billing model (so you can pick sensible intervals)

- **1 `login()` or `validateLicense()` = 1 credit** (one `/auth/validate` debit).
- **10 online check-ins = 1 credit** (billed on every 10th successful check-in per license). The grace period costs nothing after the initial activate.
- Keep `heartbeatInterval` at `>= 10` seconds (`900` / 15 min is the common desktop default). `/auth/heartbeat` is limited to 6 requests/minute per license key, and revocations still take effect on the **next** check-in.

## Installation

Install from npm as **`@authforgecc/sdk`**:

```bash
npm install @authforgecc/sdk
```

Or copy `authforge.mjs` into your project (single file, Node.js built-ins only). Requires Node.js 18+.

## Minimal working integration

```js
import process from "node:process";
import { AuthForgeClient } from "@authforgecc/sdk";

const onFailure = (reason, error) => {
  console.error(`AuthForge: ${reason}`);
  if (error) {
    console.error(error);
  }
  process.exit(1);
};

const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  appSecret: "YOUR_APP_SECRET",
  publicKey: "YOUR_PUBLIC_KEY",
  onFailure,
});

const licenseKey = process.argv[2]?.trim();
if (!licenseKey) {
  console.error("Provide a license key.");
  process.exit(1);
}

const ok = await client.login(licenseKey);
if (!ok) {
  console.error("Login failed.");
  process.exit(1);
}

// --- Your application code starts here ---
console.log("Running with a valid license.");
// --- Your application code ends here ---

client.logout();
```

This default configuration activates online once and then runs through the grace period (no further network calls until the session TTL expires). To enable online check-ins, add `onlineHeartbeat: true` (and optionally tune `heartbeatInterval`).

## Constructor parameters

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| `appId` | `string` | yes | - | Application ID |
| `appSecret` | `string` | yes | - | Application secret |
| `publicKey` | `string \| readonly string[]` | yes | - | Base64 Ed25519 public key from the dashboard (3rd positional arg, or `publicKey` in the options object). Accepts one key, an array, or a comma-separated string; the SDK trusts a signature matching **any** entry (key rotation) |
| `onlineHeartbeat` | `boolean` | no | `false` | Enable online check-ins (periodic `/auth/heartbeat`). When `false`, the app runs through the grace period without contacting AuthForge |
| `heartbeatMode` | `string` | no | - | **Deprecated.** `"SERVER"` or `"LOCAL"` (case-insensitive); still the 4th positional arg for compatibility. See [Migrating from heartbeatMode](#migrating-from-heartbeatmode) |
| `heartbeatInterval` | `number` | no | `900` | Seconds between background checks (minimum `10`) |
| `apiBaseUrl` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `onFailure` | `(reason: string, error: Error \| null) => void \| null` | no | `null` | Called on login/check-in/network failure; if omitted, process exits via `process.exit(1)` |
| `requestTimeout` | `number` | no | `15` | HTTP timeout (seconds) |
| `ttlSeconds` | `number \| null` | no | `null` (server default: 86400) | Requested grace period duration (session TTL) in seconds. Server clamps to `[3600, 604800]` (1h to 7d) and preserves the lifetime across check-in refreshes. |
| `hwidOverride` | `string \| null` | no | `null` | Optional custom HWID/subject string. When set to a non-empty value (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from heartbeatMode

`heartbeatMode` is deprecated but still accepted (options object or 4th positional arg). Passing it emits a `DeprecationWarning`; an invalid value still throws `heartbeatMode must be LOCAL or SERVER`.

- `"LOCAL"` maps to the default grace period behavior: remove the option.
- `"SERVER"` maps to `onlineHeartbeat: true`.

```js
// Before
new AuthForgeClient({ appId, appSecret, publicKey, heartbeatMode: "SERVER" });

// After
new AuthForgeClient({ appId, appSecret, publicKey, onlineHeartbeat: true });
```

The client exposes `onlineHeartbeat` (boolean, the effective policy) and keeps a back-compat `heartbeatMode` property (`"SERVER"` when check-ins are enabled, `"LOCAL"` otherwise). Prefer `onlineHeartbeat`.

## Methods

| Method | Returns | Description |
| ------ | ------- | ----------- |
| `login(licenseKey)` | `Promise<boolean>` | Activates online: validates license, verifies signatures, starts the background check interval |
| `validateLicense(licenseKey)` | `Promise<ValidateLicenseResult>` | Same validate + signatures as login; does not mutate session or start background checks; **never** calls `onFailure` or `process.exit`: use the result object |
| `logout()` | `void` | Stops background checks and clears session state |
| `isAuthenticated()` | `boolean` | Whether a session token is present and marked authenticated |
| `getSessionData()` | `Record<string, unknown> \| null` | Decoded signed payload map |
| `getAppVariables()` | `Record<string, unknown> \| null` | App-scoped variables |
| `getLicenseVariables()` | `Record<string, unknown> \| null` | License-scoped variables |

## Error codes the server can return

Full set (`knownServerErrors`): invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- `app_burn_cap_reached` means the app's configured credit burn cap is hit; `revoke_requires_session` means a pre-session self-ban tried to revoke a license (only session-authenticated self-ban can revoke).
- `session_expired` is also raised locally when the grace period (session TTL) runs out.

## Common patterns

### Reading license variables (feature gating)

```js
const varsMap = client.getLicenseVariables() ?? {};
const tier = varsMap.tier;
```

### Graceful shutdown

```js
client.logout();
```

### Custom error handling

Server error codes appear as `Error` messages in the `error` passed to `onFailure` from failed validation (for example `invalid_key`). Reasons are `login_failed`, `heartbeat_failed`, or `network_error`.

```js
const onFailure = (reason, error) => {
  const code = error?.message;
  if (code && new Set(["invalid_key", "expired", "revoked"]).has(code)) {
    console.error(`License issue: ${code}`);
  }
  process.exit(1);
};
```

## Do NOT

- Do not hardcode the app secret as a plain string literal in source - use environment variables or encrypted config
- Do not skip the `onFailure` callback - without it, background check failures terminate the process via `process.exit(1)` without your cleanup
- Do not call `login()` on every app action - call it once at startup; the background checks handle the rest
- Do not use `heartbeatMode` in new code - it is deprecated; use `onlineHeartbeat: true` when you need online check-ins, or nothing at all for the default grace period
- Do not treat the grace period as persistent offline licensing - it is session continuation after one successful online activation, and revocations are only picked up at the next online validate or check-in
