# AuthForge SDK - AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Installation

Install from npm:

```bash
npm install authforge
```

Or copy `authforge.mjs` into your project (single file, Node.js built-ins only). Requires Node.js 18+.

## Minimal working integration

```js
import process from "node:process";
import { AuthForgeClient } from "authforge";

const onFailure = (reason, error) => {
  console.error(`AuthForge: ${reason}`);
  if (error) {
    console.error(error);
  }
  process.exit(1);
};

const client = new AuthForgeClient(
  "YOUR_APP_ID",
  "YOUR_APP_SECRET",
  "SERVER",
  900,
  "https://auth.authforge.cc",
  onFailure,
  15,
);

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

## Constructor parameters

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| `appId` | `string` | yes | - | Application ID |
| `appSecret` | `string` | yes | - | Application secret |
| `heartbeatMode` | `string` | yes | - | `"SERVER"` or `"LOCAL"` (case-insensitive) |
| `heartbeatInterval` | `number` | no | `900` | Seconds between heartbeats |
| `apiBaseUrl` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `onFailure` | `(reason: string, error: Error \| null) => void \| null` | no | `null` | Called on login/heartbeat/network failure; if omitted, process exits via `process.exit(1)` |
| `requestTimeout` | `number` | no | `15` | HTTP timeout (seconds) |

## Methods

| Method | Returns | Description |
| ------ | ------- | ----------- |
| `login(licenseKey)` | `Promise<boolean>` | Validates license, verifies signatures, starts heartbeat interval |
| `logout()` | `void` | Stops heartbeat and clears session state |
| `isAuthenticated()` | `boolean` | Whether a session token is present and marked authenticated |
| `getSessionData()` | `Record<string, unknown> \| null` | Decoded signed payload map |
| `getAppVariables()` | `Record<string, unknown> \| null` | App-scoped variables |
| `getLicenseVariables()` | `Record<string, unknown> \| null` | License-scoped variables |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, session_expired, app_disabled, bad_request

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
- Do not skip the `onFailure` callback - without it, heartbeat failures terminate the process via `process.exit(1)` without your cleanup
- Do not call `login()` on every app action - call it once at startup; heartbeats handle the rest
- Do not use `heartbeatMode="LOCAL"` unless the app has no internet after initial auth
