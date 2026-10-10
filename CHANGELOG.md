# Changelog

## 1.5.0

### Features

- **Self-serve offline activation.** New `activateOffline(licenseKey, { path })` -> `Promise<boolean>`: one call to `POST /auth/offline/activate` turns a license key into a lifetime `.authforge` file bound to this machine's HWID (the same HWID `login()` sends). The file is verified locally (signature against the configured public key(s), app id, HWID) before anything is written; with `path` it is written atomically (temp file + rename, parent directories created). On success the client holds an offline session exactly as after `loginFromFile()`, with no background checks. Needs the app secret, unlike air-gapped files. 2 credits per new machine, charged to the app owner; re-activating the same machine is free and returns the identical file. A refund or revoke cannot reach files already issued.
- Failures reject with an `AuthForgeError` and never call `onFailure` or `process.exit`; nothing is written to `path` and the client does not become authenticated (an existing session is left as it was, as with `loginFromFile()`). Retries match `login()` (`rate_limited`, one network retry).
- **New codes**, all fatal and in `knownServerErrors` / `definitiveErrorCodes`: `offline_activation_disabled`, `offline_activation_requires_perpetual`, `offline_activation_requires_seats`, `offline_activation_limit_reached` (from the server) and `offline_file_rejected` (SDK: the returned file failed local verification; the verifier's reason is in the message). The server's `hwid_mismatch` keeps meaning "no free seat". New transient SDK code `file_write_failed` when the verified file cannot be saved. A success response without `file` is `unexpected_response` (transient).
- `authforge.d.ts`: `activateOffline`, `ActivateOfflineOptions`, `OfflineActivationErrorCode`.
- Tests run every case in the shared `self_serve_activation_vectors.json`.

## 1.4.1

### Fixes

- **No more exit on transient failures without a callback.** Without `onFailure`, a transient background check failure (network outage, timeout, `rate_limited`, `system_error`, `no_credits`, ...) no longer calls `process.exit(1)`. The SDK writes one line to stderr, `AuthForge: background check failed (<code>); retrying next interval`, keeps the session and checks in again on the next interval. Previously a brief outage killed any app that enabled online check-ins without setting a callback.
- Unchanged: without a callback, definitive failures (including the `session_expired` a transient failure becomes once the session TTL has passed) and failed `login()` calls still call `process.exit(1)`.

### Docs

- The README and `AGENTS.md` examples no longer call `process.exit(1)` from `onFailure`. They abort an `AbortController` that the app listens to, so it can save work, close what it opened and exit; `process.exit` is kept as a last resort after saving.

## 1.4.0

### Behavior changes for callers

- **Typed heartbeat errors.** `onFailure("heartbeat_failed", error)` now always receives an `AuthForgeError` (new export) with `code`, `transient` and `fatal`. For server errors `error.message` equals the code.
- **Classification.** Only a definitive allowlist is fatal: `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch`. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>` and unknown codes.
- **Transient failures keep checking in.** Previously any heartbeat failure stopped the timer. Now the session is kept and the next interval checks in again; once the signed session's TTL has passed, a transient failure is reported as `session_expired`.
- **Definitive failures clear the session first.** The stored session is cleared (as `logout()` does) and check-ins stop before `onFailure` runs, so `isAuthenticated()` is already `false` there. `onFailure` may call `logout()`, `isAuthenticated()` or `login()`, and a check-in still in flight when `logout()`/`login()` runs is discarded.
- **`unexpected_response`.** A failed check-in only counts as a verdict when its body is `{"status":"failed","error":"<code>"}`. Any other failure body (for example from a proxy) is reported as transient `unexpected_response`, with the raw `status`/`error` in the message.
- **Rate-limit retries.** Only `rate_limited`, or HTTP 429 with no error code, is retried (after 2s, then 5s). `no_credits`, `demo_quota_exceeded` and `app_burn_cap_reached` (also HTTP 429) are no longer retried immediately. This also applies to `login()` and `validateLicense()`.
- **One callback per heartbeat network failure.** Heartbeat network failures are reported once, as `heartbeat_failed` with code `network_error` or `timeout`; they no longer also fire `onFailure("network_error")`.
- **Unknown server codes are passed through** instead of being collapsed into `unknown_error`.
- **New exports:** `AuthForgeError`, `isTransientError(errorOrCode)`, `transientErrorCodes`, `definitiveErrorCodes`.
- **`http:` base URLs** are supported for `apiBaseUrl` (for example a local test server).
