# AuthForge Node.js SDK

Official Node.js SDK for [AuthForge](https://authforge.cc): credit-based license key authentication with Ed25519-verified responses.

**Zero dependencies.** Node.js built-ins only. Works on Node.js 18+.

## How licensing works

1. **Activate**: the SDK calls `POST /auth/validate` once. The server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL.
2. **Grace period (default)**: the app keeps running on that signed session without contacting AuthForge. The SDK periodically re-verifies the signature and expiry locally and fails once the TTL expires. The grace period equals the session TTL: default 24h, and the server clamps requests to 1h to 7d (`ttlSeconds`).
3. **Online check-ins (optional)**: set `onlineHeartbeat: true` to have the SDK call `POST /auth/heartbeat` every `heartbeatInterval` seconds for fast revocation and concurrent-use detection.

Separately, for machines that can **never** reach the internet, an operator can mint a signed **offline license file (`.authforge`)** in the AuthForge dashboard or Developer API. The SDK verifies it locally with your app public key: see [Offline license files](#offline-license-files-authforge).

## Features

Everything in this list ships in `authforge.mjs` today:

- **License validation** via `POST /auth/validate`, returning a signed session payload.
- **Ed25519 signature verification** on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected. `verifyPayloadSignatureEd25519()` is also exported for standalone use.
- **Key rotation**: `publicKey` accepts a single key, an array of keys, or a comma-separated string. The SDK trusts a signature that matches **any** key in the list, so you can roll the server-side signing key without breaking deployed clients.
- **Nonce anti-replay**: a fresh 128-bit nonce is sent on every request and the echoed nonce in the signed payload is checked before the response is accepted.
- **HWID fingerprinting**: deterministic device hash from MAC + CPU + hostname, with graceful per-component fallback.
- **`hwidOverride`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `maxHwidSlots`; `hwidCount` / `maxHwidSlots` are surfaced on the result. A shared (unlimited-seat) key skips per-device binding.
- **Grace period by default, optional online check-ins** (see [Grace period and online check-ins](#grace-period-and-online-check-ins)).
- **Offline license files (`.authforge`)**: `loginFromFile()` / `verifyLicenseFile()` verify a cloud-minted, Ed25519-signed file with zero network access for air-gapped machines.
- **Self-ban** (`selfBan()`) for anti-tamper response, both pre-session and post-session.
- **Configurable grace period** (`ttlSeconds`) with server-side clamping to `[3600, 604800]`.
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per retry.

## Quick Start

Install from npm:

```bash
npm install @authforgecc/sdk
```

Then:

```js
import { AuthForgeClient } from "@authforgecc/sdk";

const client = new AuthForgeClient({
  appId: "YOUR_APP_ID", // from your AuthForge dashboard
  appSecret: "YOUR_APP_SECRET", // from your AuthForge dashboard
  publicKey: "YOUR_PUBLIC_KEY", // from your AuthForge dashboard
});

const licenseKey = process.argv[2];

if (await client.login(licenseKey)) {
  console.log("Authenticated!");
  // Your app logic here. The app runs through the grace period by default;
  // no further network calls until the session TTL expires.
} else {
  console.error("Invalid license key.");
  process.exit(1);
}
```

To enable online check-ins:

```js
const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  appSecret: "YOUR_APP_SECRET",
  publicKey: "YOUR_PUBLIC_KEY",
  onlineHeartbeat: true,
  heartbeatInterval: 900, // seconds between check-ins
});
```

You can also copy `authforge.mjs` directly into your project if you prefer a single-file integration.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `appId` | `string` | required | Your application ID from the AuthForge dashboard |
| `appSecret` | `string` | required for online APIs; omit / `""` for `loginFromFile` only | Your application secret from the AuthForge dashboard. Do not ship it in air-gapped binaries. |
| `publicKey` | `string \| readonly string[]` | required | App Ed25519 public key(s) (base64) from dashboard. Pass one key, an array, or a comma-separated string to trust multiple keys during rotation (see [Key rotation](#key-rotation)). |
| `onlineHeartbeat` | `boolean` | `false` | Enable online check-ins: periodic `/auth/heartbeat` calls for fast revocation and concurrent-use detection. When `false` (the default), the app runs through the grace period without contacting AuthForge. |
| `heartbeatMode` | `string` | none | **Deprecated.** `"SERVER"` maps to `onlineHeartbeat: true`; `"LOCAL"` maps to the default. See [Migrating from heartbeatMode](#migrating-from-heartbeatmode). |
| `heartbeatInterval` | `number` | `900` | Seconds between checks (online check-ins or local grace period re-verification; minimum `10`; default 15 min) |
| `apiBaseUrl` | `string` | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | `function` | `null` | Callback `(reason: string, error: Error \| null)` on auth failure; server and heartbeat errors are `AuthForgeError` with `code` / `transient` |
| `requestTimeout` | `number` | `15` | HTTP request timeout in seconds |
| `ttlSeconds` | `number \| null` | `null` (server default: 86400) | Requested grace period duration (session TTL) in seconds. Server clamps to `[3600, 604800]` (1h to 7d); preserved across online check-ins. |
| `hwidOverride` | `string \| null` | `null` | Optional custom hardware/subject identifier. When set to a non-empty value, the SDK uses it instead of machine fingerprinting. |

### Identity-based binding example (Telegram/Discord)

```js
const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  appSecret: "YOUR_APP_SECRET",
  publicKey: "YOUR_PUBLIC_KEY",
  hwidOverride: `tg:${telegramUserId}`, // or `discord:${discordUserId}`
});
```

### Key rotation

`publicKey` is a trust list. To rotate the server-side signing key without a
flag-day, ship the **new** key alongside the **previous** one; the SDK accepts a
signature that matches any entry:

```js
const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  appSecret: "YOUR_APP_SECRET",
  publicKey: ["NEW_PUBLIC_KEY", "PREVIOUS_PUBLIC_KEY"], // or "NEW,PREVIOUS"
});
```

`client.publicKeys` exposes the full trust list; `client.publicKey` is the first
(primary) entry.

## Grace period and online check-ins

**Grace period (default)**: after one successful online activate/validate, the app keeps running on the Ed25519-signed session without contacting AuthForge. The SDK re-verifies the cached signature and checks the expiry timestamp locally at the configured interval; when the session TTL expires it triggers failure with `session_expired`. The grace period equals the session TTL (default 24h, server clamps 1h to 7d via `ttlSeconds`). It is session continuation, not persistent offline licensing: a mid-session revocation is not picked up until the next online validate or check-in.

**Online check-ins (`onlineHeartbeat: true`)**: the SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state. Use this when you need fast revocation or concurrent-use detection. A definitive rejection (`revoked`, `hwid_mismatch`, `blocked`, ...) clears the stored session immediately; every other failure (network, `rate_limited`, `system_error`, `no_credits`, unknown codes, unexpected responses) is transient and keeps it until the session TTL runs out. See [Background check failures](#background-check-failures).

## Offline license files (`.authforge`)

For machines that never connect to the internet, the operator mints a **signed offline license file** in the AuthForge dashboard (License page -> *Mint .authforge file*) or via `POST /v1/licenses/{licenseKey}/offline-files`. The file is a standalone Ed25519-signed document; the SDK verifies it with **only** your app public key and the machine HWID. It never contacts AuthForge and never starts online check-ins. Omit `appSecret` so the air-gapped binary does not contain the App Secret.

| | Grace period (default) | Offline license file |
| --- | --- | --- |
| Needs network | Once, at `login()` | Never on the end machine |
| What is verified | Signed *session* from `/auth/validate` | Signed *document* minted in the cloud |
| Lifetime | Session TTL: 1h to 7d | Operator-chosen expiry or lifetime (perpetual licenses only) |
| Revocation | Picked up at the next online validate / check-in | **Not** reachable: the file stays valid until its own expiry |
| Cost | 1 credit per `login()` | 1 credit per mint; verifying is free |

```js
import { AuthForgeClient } from "@authforgecc/sdk";

const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  publicKey: "YOUR_PUBLIC_KEY",
  onFailure: (reason, error) => console.error(reason, error?.message),
});

# 1. Write an activation request the operator drops into the mint dialog:
client.writeActivationRequest("./machine.authforge-request");

// 2. Later, authorize from the minted file (path or armored text). No network.
if (client.loginFromFile("./license.authforge")) {
  console.log("Offline license OK until", client.getOfflineLicense().expiresAt ?? "forever");
  console.log(client.getLicenseVariables());
}
```

Collect the HWID from the same SDK build that will load the file: fingerprints are not portable across SDKs or languages. After `loginFromFile()`, `getSessionKind()` returns `"offline"` (`"online"` after `login()`, `null` when logged out).

`verifyLicenseFile()` (module export and client method) performs the same checks without touching client state. Failure codes, in check order: `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`. `loginFromFile()` reports them through `onFailure("offline_login_failed", error)` and returns `false`; it never calls `process.exit`.

File format (version 1): PEM-style armor with informational headers, a base64 JSON payload (`v`, `appId`, `licenseKey`, `jti`, `kid`, `issuedAt`, `expiresAt`, `hwid` policy, optional label/variable snapshots) and a detached Ed25519 signature over the UTF-8 bytes of the base64 payload string - the same contract as `/auth/validate`. See `offline_license_vectors.json` for conformance vectors.

## Migrating from heartbeatMode

`heartbeatMode` is deprecated. It still works, but constructing a client with it emits a `DeprecationWarning`.

- `heartbeatMode: "LOCAL"` maps to the default: remove the option entirely.
- `heartbeatMode: "SERVER"` maps to `onlineHeartbeat: true`.
- If both options are set, either one enables online check-ins: `heartbeatMode: "SERVER"` is not overridden by `onlineHeartbeat: false`.

```js
// Before
new AuthForgeClient({ appId, appSecret, publicKey, heartbeatMode: "LOCAL" });
new AuthForgeClient({ appId, appSecret, publicKey, heartbeatMode: "SERVER" });

// After
new AuthForgeClient({ appId, appSecret, publicKey });
new AuthForgeClient({ appId, appSecret, publicKey, onlineHeartbeat: true });
```

The `client.heartbeatMode` property is also kept for compatibility: it reads `"SERVER"` when online check-ins are enabled and `"LOCAL"` otherwise. Prefer reading `client.onlineHeartbeat`.

## Billing

- **1 `login()` or `validateLicense()` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same license = 1 credit** (billed every 10th successful check-in). The grace period costs nothing after the initial activate.

A desktop app running 6h/day with online check-ins at a 15-minute interval burns ~3-4 credits/day. `/auth/heartbeat` is limited to 6 requests/minute per license key, so keep intervals at 10 seconds or higher and pick cadence based on revocation speed needs (revocations always take effect on the **next** check-in).

## Methods

| Method | Returns | Description |
| --- | --- | --- |
| `login(licenseKey)` | `Promise<boolean>` | Activates online: validates the key and stores the signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `validateLicense(licenseKey)` | `Promise<ValidateLicenseResult>` | Same `/auth/validate` + signatures as `login`; does not store session or start background checks; failures return `{ valid: false }` and never call `onFailure` or `process.exit` |
| `selfBan(options?)` | `Promise<Record<string, unknown>>` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `loginFromFile(pathOrText)` | `boolean` | Authorizes from an offline `.authforge` file with no network; never starts background checks; failures go to `onFailure("offline_login_failed", …)` |
| `verifyLicenseFile(pathOrText, options?)` | `VerifyLicenseFileResult` | Verifies a `.authforge` file with this client's app id / keys / HWID without changing state |
| `getOfflineLicense()` | `OfflineLicenseSummary \| null` | Metadata of the offline file in use (`jti`, `expiresAt`, `hwidPolicy`, …) |
| `getSessionKind()` | `"online" \| "offline" \| null` | Which kind of session the client holds (`null` when logged out) |
| `getHwid()` | `string` | The HWID this client sends (or `hwidOverride`); customers share it to receive a bound file |
| `createActivationRequest(options?)` | `string` | Unsigned `.authforge-request` for this machine. No network, no secret. Hostname omitted unless `includeMachineName: true` |
| `writeActivationRequest(path, options?)` | `void` | Writes that file as UTF-8 |
| `logout()` | `void` | Stops background checks and clears all session/auth state |
| `isAuthenticated()` | `boolean` | `true` when an active authenticated session exists |
| `getSessionData()` | `Record<string, unknown> \| null` | Full decoded payload map |
| `getAppVariables()` | `Record<string, unknown> \| null` | App-scoped variables map |
| `getLicenseVariables()` | `Record<string, unknown> \| null` | License-scoped variables map |

## Failure Handling

If authentication fails (login rejected, check-in fails, grace period expired, signature mismatch, etc.), the SDK calls your `onFailure` callback if one is provided. Without a callback, a transient background check failure (network outage, `rate_limited`, `system_error`, ...) writes a one-line warning to stderr and check-ins continue; every other failure (a rejected `login()`, a definitive check-in answer, the grace period running out) **calls `process.exit(1)` to terminate the process**, so your app cannot keep running without a valid license. `process.exit` does not wait for pending writes, so set `onFailure` if your app has anything to save.

**`validateLicense()`** is different: it never starts background checks, does not mutate the client's stored session, and **never** invokes `onFailure` or exits the process. Inspect the returned `valid` / `code` fields instead.

Recognized server errors (`knownServerErrors`):
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `app_burn_cap_reached`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `revoke_requires_session`, `bad_request`, `malformed_request`, `demo_quota_exceeded`, `system_error`. Codes added to the server later are passed through unchanged.

Request retries are automatic inside the internal HTTP layer:

- `rate_limited` (or HTTP 429 with no error code): retry after 2s, then 5s (max 3 attempts total)
- `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached` (also HTTP 429): never retried immediately; a background check tries again on the next interval
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

### Background check failures

Background check failures reach `onFailure("heartbeat_failed", error)`, where `error` is an `AuthForgeError`:

- `error.code`: the server's error code from the response body, whatever the HTTP status (`revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `rate_limited`, `no_credits`, `system_error`, `malformed_request`, ...; codes this SDK version doesn't know are passed through unchanged), or an SDK code: `network_error`, `timeout`, `http_error_<status>` (non-JSON error body), `unexpected_response`, `signature_mismatch`, `nonce_mismatch`. `error.message` is the code for server errors, `url_error: ...` for network failures.
- `error.transient` / `error.fatal`: the classification. `isTransientError(errorOrCode)` is the same check as a function; `definitiveErrorCodes` is the allowlist and `transientErrorCodes` lists the named transient codes for reference.

A failed check-in only counts as an AuthForge verdict when its body is `{"status": "failed", "error": "<code>"}`. Any other failure body (for example `{"error": "revoked"}` with no status, or `{"status": "failed"}` with no error, typically from a proxy or captive portal) is reported as `unexpected_response`, with the raw `status`/`error` in `error.message`.

| Kind | Codes | What the SDK does |
|---|---|---|
| Definitive (`error.fatal`) | `revoked`, `expired`, `hwid_mismatch` (the HWID is no longer bound to the license, for example after an HWID reset), `blocked` (the HWID or IP is blacklisted, or not on the whitelist), `session_expired` (also raised locally when the grace period runs out), `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | Clears the stored session (as `logout()` does) and stops background checks **before** calling `onFailure`, so the grace period cannot keep the app running on it. |
| Transient (`error.transient`) | Everything else: `network_error`, `timeout`, `rate_limited`, `system_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, `unexpected_response`, every `http_error_<status>`, unparseable responses and any unrecognized code | Keeps the session and checks in again on the next `heartbeatInterval`. Once the signed session's TTL has passed, the next transient failure is reported as a definitive `session_expired` instead. |

Transient failures only keep checking in if `onFailure` returns normally. Without a callback, a transient failure prints `AuthForge: background check failed (<code>); retrying next interval` to stderr and check-ins continue; a fatal one, including the `session_expired` a transient failure becomes once the session TTL has passed, still calls `process.exit(1)`. Heartbeat network failures are reported once, as `heartbeat_failed` with code `network_error` or `timeout`, not as a separate `network_error` reason.

`onFailure` may safely call `logout()`, `isAuthenticated()` or `login()`: after a definitive failure `isAuthenticated()` is already `false`. A check-in that is still in flight when you call `logout()` or `login()` is discarded, so a late response never brings the old session back.

To tolerate short outages but shut down on a definitive answer, have the callback signal the rest of your app and let it save and exit:

```js
import process from "node:process";
import { AuthForgeClient, AuthForgeError } from "@authforgecc/sdk";

const licenseLost = new AbortController();

const handleAuthFailure = (reason, error) => {
  if (reason === "heartbeat_failed" && error instanceof AuthForgeError && error.transient) {
    // No verdict on the license (outage, rate limit, credits, proxy): keep
    // running. The SDK retries every heartbeatInterval and reports
    // session_expired (fatal) once the ttlSeconds grace period is used up.
    console.warn(`AuthForge check-in failed (${error.code}), retrying`);
    return;
  }
  // Definitive: the session is already cleared (client.isAuthenticated() === false).
  console.error(`License check failed: ${reason} (${error?.code ?? error?.message})`);
  licenseLost.abort(error); // signal the app instead of exiting here
};

const client = new AuthForgeClient({
  appId: "YOUR_APP_ID",
  appSecret: "YOUR_APP_SECRET",
  publicKey: "YOUR_PUBLIC_KEY",
  onlineHeartbeat: true,
  ttlSeconds: 3600, // retry window for transient check-in failures
  onFailure: handleAuthFailure,
});

licenseLost.signal.addEventListener(
  "abort",
  async () => {
    await saveUserWork();
    server.close(); // close whatever keeps the event loop alive (servers, intervals, sockets)
    client.logout();
    process.exitCode = 1; // Node exits once nothing is left running
  },
  { once: true },
);
```

You can also pass `licenseLost.signal` to APIs that accept an `AbortSignal` (`fetch`, `setTimeout` from `node:timers/promises`, `events.once`, ...) so in-flight work stops with it. Calling `process.exit(1)` inside `onFailure` is a last resort: it ends the process without waiting for pending writes or `finally` blocks, so save the user's work first.

## Self-ban (tamper response)

Use `selfBan()` when your anti-tamper checks trip:

```js
// Post-session (authenticated): defaults to revoke + HWID/IP blacklist.
await client.selfBan();

// Pre-session: provide licenseKey, SDK automatically disables revokeLicense.
await client.selfBan({ licenseKey: "AF-XXXX-XXXX-XXXX" });

// Custom flags:
await client.selfBan({
  blacklistHwid: true,
  blacklistIp: true,
  revokeLicense: false,
});
```

`selfBan()` selects request mode automatically:
- Uses post-session mode when `sessionToken` is available (`options.sessionToken` or current SDK session).
- Falls back to pre-session mode with `licenseKey` + nonce + app secret.
- In pre-session mode, revoke is always disabled client-side to avoid unsafe key revocations.
- Not available after `loginFromFile()`: offline sessions have no server session, so `selfBan()` with no explicit `licenseKey` / `sessionToken` rejects with `offline_session` without contacting the server.

## How It Works

1. **Activate** - Uses `hwidOverride` if provided; otherwise collects a hardware fingerprint (MAC, CPU, hostname). It then generates a random nonce and sends everything to the AuthForge API via `/auth/validate`. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload with a TTL. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Background checks** - A background interval runs at the configured cadence. With online check-ins enabled, it calls `/auth/heartbeat` with a fresh nonce and verifies the response. Otherwise it re-verifies the stored signature and checks the grace period expiry without network calls.

3. **Crypto** - Both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Hardware ID

The SDK generates a deterministic hardware fingerprint by hashing:

- First non-internal MAC address
- CPU model
- Hostname

Material format:
`SHA256("mac:<mac>|cpu:<cpu>|host:<hostname>")`

Each component falls back to `unavailable` if it cannot be read.

For non-device identities (for example Telegram users), pass `hwidOverride` such as `tg:<user_id>`.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior. `offline_license_vectors.json` (generated by `generate_offline_vectors.mjs` from a fixed test seed) is the cross-SDK conformance suite for `.authforge` offline license files: good files plus the `bad_signature`, wrong key, `wrong_app`, `expired`, `hwid_mismatch`, `unsupported_version` and `bad_armor` rejects.

## Requirements

- Node.js 18+
- No external packages

## License

MIT
